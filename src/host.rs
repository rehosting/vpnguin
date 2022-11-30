//! Host implementation.

use crate::{write_event, Host, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_vsock::{ReadHalf, VsockStream};

/// Execute the host endpoint.
pub async fn execute(command: &Host) -> Result<()> {
    // Set up the event source
    info!(
        "initializing event source at {}",
        command.event_path.display()
    );
    let bind_re =
        Regex::new(r"^bind (tcp|udp) (\d+\.\d+\.\d+\.\d+:\d+)( (\d+\.\d+\.\d+\.\d+:\d+))?")
            .context("unable to compile bind regex")?;
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
        if let Some(cs) = bind_re.captures(&line) {
            let transport = match &cs[1] {
                "tcp" => Transport::Tcp,
                "udp" => Transport::Udp,
                x => {
                    error!("unable to parse transport {x}");
                    continue;
                }
            };
            let internal_address: SocketAddr = match cs[2].parse() {
                Ok(x) => x,
                Err(e) => {
                    error!("unable to parse internal address {}: {e}", &cs[2]);
                    continue;
                }
            };
            let external_address = if let Some(x) = cs.get(4) {
                match x.as_str().parse() {
                    Ok(x) => x,
                    Err(e) => {
                        error!("unable to parse external address {}: {e}", &cs[4]);
                        continue;
                    }
                }
            } else {
                let mut x = internal_address.clone();
                x.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                x
            };

            // Create a proxy and vsock bridge
            info!(
                transport = transport.to_string(),
                internal = internal_address.to_string(),
                external = external_address.to_string(),
                "creating proxy"
            );

            match transport {
                Transport::Tcp => {
                    let listener = match TcpListener::bind(&external_address).await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("unable to bind external address {external_address}/tcp: {e}");
                            continue;
                        }
                    };

                    let command = command.clone();
                    tokio::spawn(async move {
                        if let Err(e) = execute_tcp_proxy(command, internal_address, listener).await
                        {
                            error!("unable to execute tcp proxy: {e}");
                        }
                    });
                }

                Transport::Udp => {
                    let socket = match UdpSocket::bind(&external_address).await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("unable to bind external address {external_address}/udp: {e}");
                            continue;
                        }
                    };

                    let command = command.clone();
                    tokio::spawn(async move {
                        if let Err(e) = execute_udp_proxy(command, internal_address, socket).await {
                            error!("unable to execute udp proxy: {e}");
                        }
                    });
                }
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

    let mut vsock = UnixStream::connect(&command.vhost_user_path)
        .await
        .context("unable to connect to vhost-user-vsock")?;

    debug!("sending connect string to vhost-user-vsock");
    let connect = format!("CONNECT {}\n", command.command_port);
    let ok = format!("OK {}\n", command.command_port);
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
    }

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

    // Forward data
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding data to guest"
    );
    tokio::io::copy_bidirectional(&mut vsock, &mut stream)
        .await
        .context("unable to forward data to guest")?;
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "terminated forwarding to guest"
    );

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
    // Create vsock bridge
    let vsock = VsockStream::connect(command.context_id, command.command_port)
        .await
        .context("unable to connect vsock bridge")?;
    let (vsock_rx, mut vsock_tx) = vsock.split();

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
    mut vsock_rx: ReadHalf,
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
