//! Host implementation.

use crate::{write_event, Host, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    net::SocketAddr,
    sync::Arc,
    path::PathBuf,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_vsock::VsockStream;
use tokio::fs::OpenOptions;

trait IntoSplit {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>);
}

impl IntoSplit for UnixStream {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (a, b) = self.into_split();
        (
         Box::new(a) as Box<dyn AsyncRead + Unpin + Send>,
         Box::new(b) as Box<dyn AsyncWrite + Unpin + Send>
        )
    }
}

impl IntoSplit for VsockStream {
    fn socksplit(self: Box<Self>) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (a, b) = self.split();
        (
         Box::new(a) as Box<dyn AsyncRead + Unpin + Send>,
         Box::new(b) as Box<dyn AsyncWrite + Unpin + Send>
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


    // Process events
    info!("processing events");
    loop {
        let mut line = String::new();
        input
            .read_line(&mut line)
            .await
            .context("unable to read new line")?;

        /*
            // XXX: Dropped support for unspecified external addr
            let mut x = internal_address.clone();
            x.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            x
        */
        if line.is_empty() {
            continue
        }

        let Ok(record) = csv_line::from_str::<Entry>(&line) else {
            error!("Unable to parse line {line}");
            continue;
        };
        println!("{:?}", record);

        // Create a proxy and vsock bridge
        info!(
            transport = record.transport.to_string(),
            internal = record.internal_address.to_string(),
            external = record.external_address.to_string(),
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
                tokio::spawn(async move {
                    if let Err(e) = execute_tcp_proxy(command, record.internal_address, listener).await
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
                tokio::spawn(async move {
                    if let Err(e) = execute_udp_proxy(command, record.internal_address, socket).await {
                        error!("unable to execute udp proxy: {e}");
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
    listener: TcpListener,
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
        let internal_address = internal_address.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_tcp_client(command, internal_address, stream, peer_address).await
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
            let vsock = VsockStream::connect(context_id, command_port)
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
        "issuing forwarding request"
    );
    let e = HostRequest::Forward {
        internal_address,
        transport: Transport::Tcp,
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
    let mut buf_to_client = vec![0; 4096];
    let mut buf_to_guest = vec![0; 4096];

    loop {
        tokio::select! {
            // Data from vsock to stream (guest to client)
            bytes_read = vsock.read(&mut buf_to_client) => {
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
                stream.write_all(&buf_to_client[..bytes_read]).await.context("failed to write to stream")?;
                bytes_from_guest += bytes_read; // Update bytes from guest
            }

            // Data from stream to vsock (client to guest)
            bytes_read = stream.read(&mut buf_to_guest) => {
                let bytes_read = bytes_read.context("failed to read from stream")?;
                if bytes_read == 0 { break; }

                // Log data being sent to the guest
                if let Some(log_file_bidirectional) = &mut log_file_bidirectional {
                    log_file_bidirectional.write_all(b">>>").await?;
                    log_file_bidirectional.write_all(&buf_to_guest[..bytes_read]).await?;
                }


                // Forward to guest
                vsock.write_all(&buf_to_guest[..bytes_read]).await.context("failed to write to vsock")?;
                bytes_to_guest += bytes_read; // Update bytes to guest
            }
        }
    }

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

/// Execute a UDP proxy.
async fn execute_udp_proxy(
    command: Host,
    internal_address: SocketAddr,
    socket: UdpSocket,
) -> Result<()> {
    let external_address = socket.local_addr()?;
    info!(
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        "executing udp proxy"
    );

    let socket = Arc::new(socket);
    let mut buffer = [0u8; 8192];
    let mut clients: HashMap<SocketAddr, Sender<Vec<u8>>> = HashMap::new();
    loop {
        // Wait for a datagram
        let (n, client_address) = socket
            .recv_from(&mut buffer)
            .await
            .context("unable to receive client datagram")?;
        let q = match clients.entry(client_address) {
            Occupied(e) => e.get().clone(),
            Vacant(e) => {
                let command = command.clone();
                let socket = socket.clone();
                let (q_tx, q_rx) = channel(16);
                tokio::spawn(async move {
                    if let Err(e) =
                        forward_udp_client(command, socket, client_address, internal_address, q_rx)
                            .await
                    {
                        error!(
                            client = client_address.to_string(),
                            "unable to forward udp client: {e}"
                        );
                    }
                });
                e.insert(q_tx).clone()
            }
        };

        // Forward to the dedicated client task
        if let Err(e) = q.send(buffer[..n].to_vec()).await {
            error!("unable to forward client datagram to task: {e}");
        }
    }
}

/// Forward a UDP client.
async fn forward_udp_client(
    command: Host,
    socket: Arc<UdpSocket>,
    client_address: SocketAddr,
    internal_address: SocketAddr,
    mut queue: Receiver<Vec<u8>>,
) -> Result<()> {
    let external_address = socket.local_addr()?;

    // Create vsock bridge and split it
    let vsock = connect_to_socket(command.vhost_user_path, command.command_port,
                                      command.context_id).await?;
    let (vsock_rx, mut vsock_tx) = vsock.socksplit();

    // Forward data to the guest
    debug!(
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        "issuing open connection request"
    );
    let e = HostRequest::Forward {
        internal_address,
        transport: Transport::Udp,
    };
    write_event(&mut vsock_tx, &e).await?;

    debug!(
        client = client_address.to_string(),
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding udp datagrams"
    );

    // Forward data
    tokio::spawn(async move {
        if let Err(e) = forward_udp_to_client(socket, vsock_rx, client_address).await {
            error!("unable to forward udp to client: {e}");
        }
    });
    while let Some(data) = queue.recv().await {
        vsock_tx
            .write_u16(data.len() as _)
            .await
            .context("unable to write datagram size")?;
        vsock_tx
            .write_all(&data)
            .await
            .context("unable to write datagram")?;
    }
    Ok(())
}

/// Forward UDP to client.
async fn forward_udp_to_client(
    socket: Arc<UdpSocket>,
    mut vsock_rx: Box<dyn AsyncRead + Unpin + Send>,
    client_address: SocketAddr,
) -> Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let n = vsock_rx
            .read_u16()
            .await
            .context("unable to read datagram size")? as _;
        vsock_rx
            .read_exact(&mut buffer[..n])
            .await
            .context("unable to read datagram")?;
        socket
            .send_to(&buffer, &client_address)
            .await
            .context("unable to send datagram")?;
    }
}
