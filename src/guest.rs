//! Guest implementation.

use std::net::{IpAddr, SocketAddr};

use crate::{read_event, Guest, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

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
        }) => {
            // Check for wildcard addresses and replace with localhost
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }

            let stream = TcpStream::connect(internal_address)
                .await
                .context("unable to connect to guest server")?;
            proxy_tcp(vsock, peer_address, stream).await?;
        }

        Some(HostRequest::Forward {
            mut internal_address,
            transport: _transport @ Transport::Udp,
        }) => {
            // Check for wildcard addresses and replace with localhost
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }

            proxy_udp(vsock, peer_address, internal_address).await?;
        }

        None => {
            return Err(anyhow!("unable to read init event (no event received)"));
        }
    };

    Ok(())
}

/// Proxy TCP.
async fn proxy_tcp(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
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
    peer_address: VsockAddr,
    internal_address: SocketAddr,
) -> Result<()> {
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding udp datagrams"
    );

    let mut buffer = [0u8; 8192];
    let socket = UdpSocket::bind("0.0.0.0:0")
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
