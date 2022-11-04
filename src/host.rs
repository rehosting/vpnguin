//! Host implementation.

use crate::{write_event, Host, HostRequest, Transport};
use anyhow::{Context, Result};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_vsock::VsockStream;

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
            if let Err(e) = process_client(command, internal_address, stream, peer_address).await {
                error!("unable to process external client: {e}");
            }
        });
    }
}

/// Process a client.
async fn process_client(
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
    let mut vsock = VsockStream::connect(command.context_id, command.command_port)
        .await
        .context("unable to connect vsock bridge")?;

    // Open a connection on the guest side
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "issuing open connection request"
    );
    let open_conn = HostRequest::OpenConnection {
        address: internal_address,
        transport: Transport::Tcp,
    };
    write_event(&mut vsock, &open_conn).await?;

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

    // Create vsock bridge
    let mut vsock = VsockStream::connect(command.context_id, command.command_port)
        .await
        .context("unable to connect vsock bridge")?;

    // Open a "connection" on the guest side
    debug!(
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        "issuing open connection request"
    );
    let open_conn = HostRequest::OpenConnection {
        address: internal_address,
        transport: Transport::Udp,
    };
    write_event(&mut vsock, &open_conn).await?;

    // Forward data
    debug!(
        external = external_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding udp datagrams"
    );

    let mut buffer = [0u8; 8192];
    loop {
        debug!("reading client datagram");
        let (n, peer_address) = socket
            .recv_from(&mut buffer)
            .await
            .context("unable to read client datagram")?;
        debug!(
            peer = peer_address.to_string(),
            external = external_address.to_string(),
            internal = internal_address.to_string(),
            size = n,
            "forwarding udp datagram"
        );
        vsock
            .write_all(&buffer[..n])
            .await
            .context("unable to forward client datagram")?;
        debug!("reading server datagram");
        let n = vsock
            .read(&mut buffer)
            .await
            .context("unable to read server datagram")?;
        debug!("forwarding server datagram");
        socket
            .send_to(&buffer[..n], &peer_address)
            .await
            .context("unable to forward server datagram")?;
    }
}
