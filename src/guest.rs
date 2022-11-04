//! Guest implementation.

use std::net::SocketAddr;

use crate::{read_event, Guest, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_vsock::{SockAddr, VsockListener, VsockStream};

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
                error!("unable to process client: {e}");
            }
        });
    }
}

/// Process a vsock client.
async fn process_client(mut vsock: VsockStream, peer_address: SockAddr) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    // Process the init event
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read init event")?;
    match e {
        Some(HostRequest::OpenConnection {
            address,
            transport: _transport @ Transport::Tcp,
        }) => {
            let stream = TcpStream::connect(address)
                .await
                .context("unable to connect to guest server")?;
            proxy_tcp(vsock, peer_address, stream).await?;
        }

        Some(HostRequest::OpenConnection {
            address,
            transport: _transport @ Transport::Udp,
        }) => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .context("unable to create guest socket")?;
            proxy_udp(vsock, peer_address, socket, address).await?;
        }

        Some(_) => {
            return Err(anyhow!("unexpected init event: {e:?}"));
        }

        None => {
            return Err(anyhow!("unable to read init event"));
        }
    };

    Ok(())
}

/// Proxy TCP.
async fn proxy_tcp(
    mut vsock: VsockStream,
    peer_address: SockAddr,
    mut stream: TcpStream,
) -> Result<()> {
    // Forward data
    debug!(peer = peer_address.to_string(), "forwarding data to host");
    tokio::io::copy_bidirectional(&mut vsock, &mut stream)
        .await
        .context("unable to forward data to host")?;
    debug!(
        peer = peer_address.to_string(),
        "terminated forwarding to host"
    );
    Ok(())
}

/// Proxy UDP.
async fn proxy_udp(
    mut vsock: VsockStream,
    peer_address: SockAddr,
    socket: UdpSocket,
    server_address: SocketAddr,
) -> Result<()> {
    debug!(peer = peer_address.to_string(), "forwarding udp datagrams");
    let mut buffer = [0u8; 8192];
    loop {
        debug!("reading client datagram");
        let n = vsock
            .read(&mut buffer)
            .await
            .context("unable to read client datagram")?;
        debug!(
            peer = peer_address.to_string(),
            internal = server_address.to_string(),
            size = n,
            "forwarding udp datagram"
        );
        socket
            .send_to(&buffer[..n], &server_address)
            .await
            .context("unable to write client datagram")?;
        debug!("reading server datagram");
        let n = socket
            .recv(&mut buffer)
            .await
            .context("unable to read server datagram")?;
        debug!("forwarding server datagram");
        vsock
            .write_all(&buffer[..n])
            .await
            .context("unable to write server datagram")?;
    }
}
