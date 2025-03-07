//! Guest implementation.

use std::net::{IpAddr, SocketAddr};

use crate::{read_event, Guest, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    select,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use tokio::time::{timeout, Duration};
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Execute the guest endpoint.
pub async fn execute(command: &Guest) -> Result<()> {
    // Set up a vsock listener
    info!(
        context = command.context_id,
        port = command.command_port,
        "listening for events"
    );
    let mut listener = VsockListener::bind(command.context_id, command.command_port)
        .context("unable to bind vsock listener")?;

    loop {
        let (vsock, peer_address) = listener
            .accept()
            .await
            .context("unable to accept vsock client")?;
        tokio::spawn(async move {
            if let Err(e) = process_client(vsock, peer_address).await {
                error!("unable to process client: {e:#?}");
            }
        });
    }
}

/// Process a vsock client.
async fn process_client(mut vsock: VsockStream, peer_address: VsockAddr) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    // Process the init event
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read init event")?;
    match e {
        Some(HostRequest::Forward {
            mut internal_address,
            transport: _transport @ Transport::Tcp,
            source_address,
        }) => {
            // Check for wildcard addresses and replace with localhost
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }
            let socket = match internal_address.ip() {
                IpAddr::V4(_) => TcpSocket::new_v4().context("unable to create IPv4 TCP socket")?,
                IpAddr::V6(_) => TcpSocket::new_v6().context("unable to create IPv6 TCP socket")?,
            };
            socket.bind(source_address)?;
            match timeout(CONNECTION_TIMEOUT, socket.connect(internal_address)).await {
                Ok(Ok(stream)) => {
                    info!("Successfully connected to {}", internal_address);
                    proxy_tcp(vsock, peer_address, stream).await?;
                },
                Ok(Err(e)) => {
                    warn!("Failed to connect to {}: {}", internal_address, e);
                    return Err(e).context(format!("Failed to connect to {}", internal_address));
                },
                Err(_) => {
                    warn!("Connection attempt to {} timed out", internal_address);
                    return Err(anyhow!("Connection attempt timed out"));
                },
            }
        }

        Some(HostRequest::Forward {
            mut internal_address,
            transport: _transport @ Transport::Udp,
            source_address,
        }) => {
            // Check for wildcard addresses and replace with localhost
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }

            proxy_udp(vsock, peer_address, internal_address, source_address).await?;
        }

        None => {
            return Err(anyhow!("unable to read init event (no event received)"));
        }
    };

    Ok(())
}

/// Proxy TCP.
async fn proxy_tcp(
    vsock: VsockStream,
    peer_address: VsockAddr,
    mut stream: TcpStream,
) -> Result<()> {
    let (mut vsock_read, mut vsock_write) = vsock.split();
    let (mut stream_read, mut stream_write) = stream.split();

    let vsock_to_stream = async {
        let mut buffer = [0u8; 8192];
        loop {
            match vsock_read.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stream_write.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        stream_write.shutdown().await
    };

    let stream_to_vsock = async {
        let mut buffer = [0u8; 8192];
        loop {
            match stream_read.read(&mut buffer).await {
                Ok(0) => {
                    debug!("TCP stream closed, shutting down vsock");
                    break; // EOF - TCP stream closed
                }
                Ok(n) => {
                    if vsock_write.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("Error reading from TCP stream: {:?}", e);
                    break;
                }
            }
        }
        vsock_write.shutdown().await
    };

    select! {
        _ = vsock_to_stream => {},
        _ = stream_to_vsock => {},
    }

    debug!(peer = peer_address.to_string(), "Proxy operation completed");
    Ok(())
}

/// Proxy UDP.
async fn proxy_udp(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    internal_address: SocketAddr,
    source_address: SocketAddr,
) -> Result<()> {
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding udp datagrams"
    );

    let mut buffer = [0u8; 8192];
    let socket = UdpSocket::bind(source_address)
        .await
        .context("unable to bind udp socket")?;

    loop {
        debug!("reading client datagram");
        let n = vsock
            .read_u16()
            .await
            .context("unable to read client datagram size")? as _;
        vsock
            .read_exact(&mut buffer[..n])
            .await
            .context("unable to read client datagram")?;
        debug!(
            peer = peer_address.to_string(),
            internal = internal_address.to_string(),
            size = n,
            "forwarding udp datagram"
        );
        socket
            .send_to(&buffer[..n], &internal_address)
            .await
            .context("unable to write client datagram")?;
        debug!("reading server datagram");
        let n = socket
            .recv(&mut buffer)
            .await
            .context("unable to read server datagram")?;
        debug!("forwarding server datagram");
        // TODO: Buffer this and similar to reduce syscalls if perf becomes an issue
        vsock
            .write_u16(n as _)
            .await
            .context("unable to write server datagram size")?;
        vsock
            .write_all(&buffer[..n])
            .await
            .context("unable to write server datagram")?;
    }
}
