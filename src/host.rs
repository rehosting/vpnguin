//! Host implementation.

use crate::{read_event, write_event, GuestRequest, Host, HostRequest};
use anyhow::{Context, Result};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
};
use tokio_vsock::{ReadHalf, VsockStream, WriteHalf};

/// Execute the host endpoint.
pub async fn execute(command: &Host) -> Result<()> {
    // Set up the event source
    info!(
        "initializing event source at {}",
        command.event_path.display()
    );
    let bind_re = Regex::new(r"^bind (\d+\.\d+\.\d+\.\d+:\d+)( (\d+\.\d+\.\d+\.\d+:\d+))?")
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
            let internal_address: SocketAddr = match cs[1].parse() {
                Ok(x) => x,
                Err(e) => {
                    error!("unable to parse internal address {}: {e}", &cs[1]);
                    continue;
                }
            };

            // Create a server and vsock bridge
            let external_address = if let Some(x) = cs.get(3) {
                match x.as_str().parse() {
                    Ok(x) => x,
                    Err(e) => {
                        error!("unable to parse external address {}: {e}", &cs[3]);
                        continue;
                    }
                }
            } else {
                let mut x = internal_address.clone();
                x.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                x
            };
            info!(
                internal = internal_address.to_string(),
                external = external_address.to_string(),
                "creating server"
            );
            let listener = match TcpListener::bind(&external_address).await {
                Ok(x) => x,
                Err(e) => {
                    error!("unable to bind external address {external_address}: {e}");
                    continue;
                }
            };

            let command = command.clone();
            tokio::spawn(async move {
                if let Err(e) = execute_server(command, internal_address, listener).await {
                    error!("unable to execute server: {e}");
                }
            });
        }
    }
}

/// Execute a server.
async fn execute_server(
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
    };
    write_event(&mut vsock, &open_conn).await?;

    // Forward data
    debug!(peer = peer_address.to_string(), "forwarding data to guest");
    tokio::io::copy_bidirectional(&mut vsock, &mut stream)
        .await
        .context("unable to forward data to guest")?;
    debug!(peer = peer_address.to_string(), "terminated forwarding to guest");
    Ok(())
}
