//! Guest implementation.

use crate::{Guest, VSOCK_PORT};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_vsock::VsockStream;

/// Guest event.
enum GuestEvent {
    /// Bind a new server socket.
    Bind { address: SocketAddr },
    /// Destroy a server socket.
    Destroy { address: SocketAddr },
}

/// Execute the guest endpoint.
pub async fn execute(command: &Guest) -> Result<()> {
    // Create a vsock socket
    let host_socket = VsockStream::connect(libc::VMADDR_CID_HOST, VSOCK_PORT)
        .await
        .context("unable to connect to host VPN server")?;

    // Spawn a control socket task
    let (control_tx, control_rx) = channel(16);
    tokio::spawn(async move {
        if let Err(e) = guest_control(control_rx, host_socket).await {
            error!("{e}");
        }
    });

    // TODO: Wait for bind events
    loop {}
}

/// Guest control task.
async fn guest_control(
    mut control_rx: Receiver<GuestEvent>,
    mut host_stream: VsockStream,
) -> Result<()> {
    // TODO: Wait for bind events, forward to host
    loop {
        match control_rx.recv().await {
            Some(GuestEvent::Bind { address }) => unimplemented!(),
            Some(GuestEvent::Destroy { address }) => unimplemented!(),
            None => break,
        }
    }

    Ok(())
}
