//! Guest implementation.

use crate::{read_event, write_event, Guest, GuestRequest, HostRequest};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::AsyncReadExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tokio_vsock::{ReadHalf, SockAddr, VsockListener, VsockStream, WriteHalf};

/// Execute the guest endpoint.
pub async fn execute(command: &Guest) -> Result<()> {
    // Set up a vsock listener
    info!(context = command.context_id, port = command.command_port, "listening for events");
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
    let mut stream = match e {
        Some(HostRequest::OpenConnection { address }) => {
            let stream = TcpStream::connect(address)
                .await
                .context("unable to connect to guest server")?;
            stream
        }

        Some(_) => {
            return Err(anyhow!("unexpected init event: {e:?}"));
        }

        None => {
            return Err(anyhow!("unable to read init event"));
        }
    };

    // Forward data
    debug!(peer = peer_address.to_string(), "forwarding data to host");
    tokio::io::copy_bidirectional(&mut vsock, &mut stream).await.context("unable to forward data to host")?;
    debug!(peer = peer_address.to_string(), "terminated forwarding to host");
    Ok(())
}
