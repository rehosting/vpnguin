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

/// Forward data from server to host.
async fn forward_to_host(mut stream_rx: OwnedReadHalf, mut vsock_tx: WriteHalf) -> Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let n = stream_rx.read(&mut buffer).await?;
        if n == 0 {
            // EOF
            break;
        }
        let e = GuestRequest::SendData {
            data: buffer[..n].to_vec(),
        };
        if let Err(_e) = write_event(&mut vsock_tx, &e).await {
            // Assume that the host terminated
            break;
        }
    }

    debug!("terminating host forwarding");
    Ok(())
}

/// Forward data from host to server.
async fn forward_to_server(mut vsock_rx: ReadHalf, mut stream_tx: OwnedWriteHalf) -> Result<()> {
    loop {
        let e: Option<HostRequest> = read_event(&mut vsock_rx).await?;
        match e {
            Some(HostRequest::SendData { data }) => {
                if let Err(_e) = tokio::io::AsyncWriteExt::write_all(&mut stream_tx, &data).await {
                    // Assume the server connection closed
                    break;
                }
            }

            Some(e) => {
                return Err(anyhow!("unexpected host event: {e:?}"));
            }

            None => break,
        }
    }

    debug!("terminating server forwarding");
    Ok(())
}
