//! Host implementation.
use crate::{
    write_event, read_event, Host, HostRequest, Transport, UdpMuxPacket,
    PacketDirection::{GuestToHost, HostToGuest}
};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::Arc,
    path::PathBuf,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, BufWriter},
    net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    select,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tokio::fs::OpenOptions;
use tokio::time::{sleep, Duration};

mod pcap_logger;
use pcap_logger::PcapLogger;

trait IntoSplit {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>);
}

impl IntoSplit for UnixStream {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (a, b) = self.into_split();
        (
            Box::new(a) as Box<dyn AsyncRead + Unpin + Send>,
            Box::new(b) as Box<dyn AsyncWrite + Unpin + Send>,
        )
    }
}

impl IntoSplit for VsockStream {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (a, b) = self.into_split();
        (
            Box::new(a) as Box<dyn AsyncRead + Unpin + Send>,
            Box::new(b) as Box<dyn AsyncWrite + Unpin + Send>,
        )
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + IntoSplit { }
impl<T: AsyncRead + AsyncWrite + Send + IntoSplit> AsyncReadWrite for T {}

#[derive(Debug, Deserialize)]
struct Entry {
    transport:  Transport,
    internal_address: SocketAddr,
    external_address: SocketAddr,
    source_address: SocketAddr,
}

/// Execute the host endpoint.
pub async fn execute(command: &Host) -> Result<()> {
    // Set up the event source
    info!(
        "initializing event source at {}",
        command.event_path.display()
    );
    let input = tokio::fs::File::open(&command.event_path)
        .await
        .context("unable to open event source")?;
    let mut input = tokio::io::BufReader::new(input);

    // pcap_logger logging will be a noop if pcap_path is None
    let pcap_logger  = PcapLogger::new(&command.pcap_path);

    // Process events
    info!("processing events");
    loop {
        let mut line = String::new();
        
        let bytes_read = input
            .read_line(&mut line)
            .await
            .context("unable to read new line")?;

        if bytes_read == 0 {
            sleep(Duration::from_millis(200)).await;
            continue
        }
        
        if line.trim().is_empty() {
            continue;
        }

        let Ok(record) = csv_line::from_str::<Entry>(&line) else {
            error!("Unable to parse line {line}");
            continue;
        };

        // Create a proxy and vsock bridge
        info!(
            transport = record.transport.to_string(),
            internal = record.internal_address.to_string(),
            external = record.external_address.to_string(),
            source = record.source_address.to_string(),
            "creating proxy"
        );

        match record.transport {
            Transport::Tcp => {
                let listener = match TcpListener::bind(&record.external_address).await {
                    Ok(x) => x,
                    Err(e) => {
                        let external_address = record.external_address;
                        error!("unable to bind external address {external_address}/tcp: {e}");
                        continue;
                    }
                };

                let command = command.clone();
                let pcap_logger = pcap_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = execute_tcp_proxy(command, record.internal_address, record.source_address, listener, pcap_logger).await
                    {
                        error!("unable to execute tcp proxy: {e}");
                    }
                });
            }

            Transport::Udp => {
                let socket = match UdpSocket::bind(&record.external_address).await {
                    Ok(x) => x,
                    Err(e) => {
                        let external_address = record.external_address;
                        error!("unable to bind external address {external_address}/udp: {e}");
                        continue;
                    }
                };

                let command = command.clone();
                let pcap_logger = pcap_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = execute_udp_mux_proxy(command, record.internal_address, record.source_address, socket, pcap_logger).await {
                        error!("unable to execute udp mux proxy: {e}");
                    }
                });
            }
        }
    }
}

/// Execute a TCP proxy.
async fn execute_tcp_proxy(
    command: Host,
    internal_address: SocketAddr,
    source_address: SocketAddr,
    listener: TcpListener,
    pcap_logger: PcapLogger,
) -> Result<()> {
    //let mut data_stats: HashMap<SocketAddr> = HashMap::new();
    loop {
        let (stream, peer_address) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!("unable to accept external client: {e}");
                continue;
            }
        };

        let command = command.clone();
        let pcap_logger = pcap_logger.clone();
        let internal_address = internal_address.clone();
        let source_address = source_address.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_tcp_client(command, internal_address, stream, peer_address, source_address, pcap_logger).await
            {
                error!("unable to process external client: {e}");
            }
        });
    }
}

async fn connect_to_socket(
    vhost_user_path: Option<PathBuf>,
    command_port: u32,
    context_id: u32,
) -> Result<Box<dyn AsyncReadWrite + Unpin>> {
    match vhost_user_path {
        Some(path) =>  {
            let mut vsock = UnixStream::connect(path)
                .await
                .context("unable to connect to vhost-user-vsock")?;

            debug!("sending connect string to vhost-user-vsock");
            let connect = format!("CONNECT {}\n", command_port);
            let ok = format!("OK {}\n", command_port);
            let mut msg = vec![0u8; ok.len()];
            vsock
                .write_all(connect.as_bytes())
                .await
                .context("unable to write connect string")?;
            vsock
                .read_exact(&mut msg)
                .await
                .context("unable to receive connect acknowledgment")?;
            if msg != ok.as_bytes() {
                return Err(anyhow!("invalid connect acknowledgment received"));
            };
            Ok(Box::new(vsock) as Box<dyn AsyncReadWrite + Unpin>)
        },
        _ => {
            let vsock = VsockStream::connect(VsockAddr::new(context_id, command_port))
                            .await
                            .context("unable to connect vsock bridge")?;
            Ok(Box::new(vsock) as Box<dyn AsyncReadWrite + Unpin>)
        }
    }
}

/// Process a TCP client.
async fn process_tcp_client(
    command: Host,
    internal_address: SocketAddr,
    mut stream: TcpStream,
    peer_address: SocketAddr,
    source_address: SocketAddr,
    pcap_logger: PcapLogger,
) -> Result<()> {
    info!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "processing client"
    );

    // Create vsock bridge
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        source = source_address.to_string(),
        context = command.context_id,
        port = command.command_port,
        "creating vsock bridge"
    );

    let mut vsock = connect_to_socket(command.vhost_user_path, command.command_port,
                                      command.context_id).await?;

    // Forward data to the guest
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        source = source_address.to_string(),
        "issuing forwarding request"
    );
    let e = HostRequest::ForwardTcp {
        internal_address,
        source_address
    };
    write_event(&mut vsock, &e).await?;

    // Initialize counters for byte tracking
    let mut bytes_to_guest = 0;
    let mut bytes_from_guest = 0;


    // Create file for logging raw data
    let mut log_file_bidirectional = if let Some(outdir) = &command.outdir {
        let log_path = outdir.join(format!("vpn_data_{}", internal_address.to_string().replace(":", "_")));
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_path)
                .await
                .context("unable to open log file")?,
        )
    } else {
        None
    };

    let mut log_file = if let Some(outdir) = &command.outdir {
        let log_path = outdir.join(format!("vpn_response_{}", internal_address.to_string().replace(":", "_")));
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_path)
                .await
                .context("unable to open log file")?,
        )
    } else {
        None
    };

    // Forward data with logging
    let (mut vsock_read, mut vsock_write) = vsock.socksplit();
    let (mut stream_read, mut stream_write) = stream.split();
    let mut buf_to_client = vec![0; 4096];
    let mut buf_to_guest = vec![0; 4096];

    // Create a chimera address for logging in case we are spoofing IP
    let log_client_addr = SocketAddr::new( source_address.ip(), peer_address.port());
    pcap_logger.init_tcp_stream(log_client_addr, internal_address).await;

    loop {
        tokio::select! {
            // Data from vsock to stream (guest to client)
            bytes_read = vsock_read.read(&mut buf_to_client) => {
                let bytes_read = bytes_read.context("failed to read from vsock")?;
                if bytes_read == 0 { break; }

                // Log data being sent to the client
                if let Some(log_file_bidirectional) = &mut log_file_bidirectional {
                    log_file_bidirectional.write_all(b"<<<").await?;
                    log_file_bidirectional.write_all(&buf_to_client[..bytes_read]).await?;
                }

                if let Some(log_file) = &mut log_file {
                    log_file.write_all(&buf_to_client[..bytes_read]).await?;
                }


                // Forward to client
                stream_write.write_all(&buf_to_client[..bytes_read]).await.context("failed to write to stream")?;
                bytes_from_guest += bytes_read; // Update bytes from guest
                pcap_logger.log_packet(&buf_to_client[..bytes_read], Transport::Tcp, internal_address, log_client_addr, None, GuestToHost).await;
            }

            // Data from stream to vsock (client to guest)
            bytes_read = stream_read.read(&mut buf_to_guest) => {
                let bytes_read = bytes_read.context("failed to read from stream")?;
                if bytes_read == 0 { break; }

                // Log data being sent to the guest
                if let Some(log_file_bidirectional) = &mut log_file_bidirectional {
                    log_file_bidirectional.write_all(b">>>").await?;
                    log_file_bidirectional.write_all(&buf_to_guest[..bytes_read]).await?;
                }


                // Forward to guest
                vsock_write.write_all(&buf_to_guest[..bytes_read]).await.context("failed to write to vsock")?;
                bytes_to_guest += bytes_read; // Update bytes to guest
                pcap_logger.log_packet(&buf_to_guest[..bytes_read], Transport::Tcp, log_client_addr, internal_address, None, HostToGuest).await;
            }
        }
    }

    pcap_logger.close_tcp_stream(log_client_addr, internal_address).await;

    // Connection statistics logging
    if let Some(outdir) = &command.outdir {
        let outfile_path = outdir.join(format!("vpn_{}", internal_address.to_string().replace(":", "_")));
        let mut outfile = OpenOptions::new()
            .append(true)
            .create(true)
            .open(outfile_path)
            .await
            .context("unable to open output file")?;
        outfile.write_all(format!("{},{}\n", bytes_to_guest, bytes_from_guest).as_bytes()).await?;
    }
    Ok(())
}

/// Execute a multiplexed UDP proxy.
/// This function is spawned ONCE per UDP service.
/// It handles all external clients over a single vsock stream.
async fn execute_udp_mux_proxy(
    command: Host,
    internal_address: SocketAddr,
    source_address: SocketAddr,
    socket: UdpSocket,
    pcap_logger: PcapLogger,
) -> Result<()> {
    let external_address = socket.local_addr()?;
    info!(
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        source = source_address.to_string(),
        "executing multiplexed udp proxy"
    );

    let socket = Arc::new(socket);
    let pcap_logger = Arc::new(pcap_logger);

    // Create ONE vsock bridge for this entire service
    let vsock = connect_to_socket(
        command.vhost_user_path,
        command.command_port,
        command.context_id,
    )
    .await?;
    let (mut vsock_read, vsock_write) = vsock.socksplit();
    let mut vsock_write = BufWriter::new(vsock_write);

    // Send the init request to the guest
    let e = HostRequest::ForwardUdpMux {
        internal_address,
        source_address,
    };
    write_event(&mut vsock_write, &e).await?;
    vsock_write.flush().await?;

    let mut socket_buf = vec![0u8; 8192];

    loop {
        select! {
            // --- Task 1: Guest -> Host -> External Client ---
            result = read_event::<_, UdpMuxPacket>(&mut vsock_read) => {
                match result {
                    Ok(Some(packet)) => {
                        let client_addr = packet.client_addr;
                        let data = packet.data;
                        
                        pcap_logger.log_packet(&data, Transport::Udp, internal_address, client_addr, None, GuestToHost).await;

                        if let Err(e) = socket.send_to(&data, client_addr).await {
                            error!(client = %client_addr, "failed to send datagram to external client: {e}");
                        }
                    },
                    Ok(None) => {
                        info!("Vsock stream closed by guest, shutting down UDP proxy.");
                        break;
                    }
                    Err(e) => {
                        error!("Failed to read from vsock: {e}. Shutting down UDP proxy.");
                        break;
                    }
                }
            }

            // --- Task 2: External Client -> Host -> Guest ---
            result = socket.recv_from(&mut socket_buf) => {
                 match result {
                    Ok((n, client_addr)) => {
                        let data = socket_buf[..n].to_vec();

                        let log_client_addr = SocketAddr::new(source_address.ip(), client_addr.port());
                        pcap_logger.log_packet(&data, Transport::Udp, log_client_addr, internal_address, None, HostToGuest).await;

                        let packet = UdpMuxPacket {
                            client_addr,
                            data,
                        };
                        
                        if let Err(e) = write_event(&mut vsock_write, &packet).await {
                            error!("Failed to write to vsock: {e}. Shutting down UDP proxy.");
                            break;
                        }
                        if let Err(e) = vsock_write.flush().await {
                            error!("Failed to flush vsock writer: {e}. Shutting down UDP proxy.");
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Failed to read from external socket: {e}. Shutting down UDP proxy.");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
