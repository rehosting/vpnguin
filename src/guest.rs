//! Guest implementation.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::{read_event, write_event, Guest, HostRequest, UdpMuxPacket};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncWriteExt, BufWriter, copy},
    net::{TcpSocket, TcpStream, UdpSocket},
    select,
    sync::mpsc,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use tokio::time::{timeout, Duration};
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// Execute the guest endpoint.
pub async fn execute(command: &Guest) -> Result<()> {
    // Set up a vsock listener
    info!(
        context = command.context_id,
        port = command.command_port,
        "listening for events"
    );
    let mut listener = VsockListener::bind(VsockAddr::new(command.context_id, command.command_port))
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
async fn process_client(vsock: VsockStream, peer_address: VsockAddr) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    let (mut vsock_read, mut vsock_write) = tokio::io::split(vsock);

    let e: Option<HostRequest> = read_event(&mut vsock_read)
        .await
        .context("unable to read init event")?;
    match e {
        Some(HostRequest::ForwardTcp {
            mut internal_address,
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
                Ok(Ok(mut stream)) => {
                    info!("Successfully connected to {}", internal_address);
                    stream.set_nodelay(true)?;

                    // split the TCP stream into read/write halves
                    let (mut stream_read, mut stream_write) = stream.split();

                    // create copy futures for both directions
                    let client_to_server = copy(&mut vsock_read, &mut stream_write);
                    let server_to_client = copy(&mut stream_read, &mut vsock_write);

                    // pin them so select! can poll them
                    tokio::pin!(client_to_server);
                    tokio::pin!(server_to_client);

                    // wait for either direction to finish (or error)
                    tokio::select! {
                        res = &mut client_to_server => {
                            res.context("vsock -> stream copy failed")?;
                        },
                        res = &mut server_to_client => {
                            res.context("stream -> vsock copy failed")?;
                        },
                    }

                    debug!(peer = peer_address.to_string(), "Proxy operation completed");
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

        Some(HostRequest::ForwardUdpMux {
            mut internal_address,
            source_address,
        }) => {
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }

            proxy_udp_mux(vsock_read, vsock_write, peer_address, internal_address, source_address).await?;
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
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let _ = tokio::io::copy_bidirectional(&mut vsock, &mut stream).await?;
    debug!(peer = peer_address.to_string(), "Proxy operation completed");
    Ok(())
}

/// Manages a single UDP client's session.
async fn forward_udp_client_mux(
    mut rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<UdpMuxPacket>,
    internal_address: SocketAddr,
    source_address: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()> {
    let socket = UdpSocket::bind(source_address).await?;

    let mut read_buf = vec![0u8; 8192];

    loop {
        select! {
            biased;

            Some(data) = rx.recv() => {
                if let Err(e) = socket.send_to(&data, internal_address).await {
                    error!(client = %client_addr, "Failed to send to internal service: {e}");
                    break;
                }
            },

            result = socket.recv(&mut read_buf) => {
                match result {
                    Ok(n) => {
                        let data = read_buf[..n].to_vec();
                        let packet = UdpMuxPacket {
                            client_addr,
                            data,
                        };
                        if reply_tx.send(packet).await.is_err() {
                            debug!(client = %client_addr, "Reply channel closed, client task shutting down.");
                            break;
                        }
                    },
                    Err(e) => {
                        error!(client = %client_addr, "Failed to recv from internal socket: {e}");
                        break;
                    }
                }
            },

            _ = tokio::time::sleep(UDP_CLIENT_TIMEOUT) => {
                debug!(client = %client_addr, "Client timed out, shutting down.");
                break;
            }
        }
    }
    Ok(())
}

/// Manages the single vsock stream for all UDP clients.
async fn proxy_udp_mux(
    mut vsock_read: tokio::io::ReadHalf<VsockStream>,
    vsock_write: tokio::io::WriteHalf<VsockStream>,
    peer_address: VsockAddr,
    internal_address: SocketAddr,
    source_address: SocketAddr,
) -> Result<()> {
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "initializing multiplexed udp proxy"
    );

    let mut clients: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMuxPacket>(256);

    let mut vsock_write = BufWriter::new(vsock_write);

    loop {
        select! {
            result = read_event::<_, UdpMuxPacket>(&mut vsock_read) => {
                match result {
                    Ok(Some(packet)) => {
                        let client_addr = packet.client_addr;
                        
                        if let Some(tx) = clients.get(&client_addr) {
                             if tx.send(packet.data).await.is_err() {
                                clients.remove(&client_addr);
                             }
                        } else {
                            let (tx, rx) = mpsc::channel(16);
                            if tx.send(packet.data).await.is_ok() {
                                let reply_tx_clone = reply_tx.clone();
                                tokio::spawn(async move {
                                    debug!(client = %client_addr, "Spawning new UDP client handler");
                                    if let Err(e) = forward_udp_client_mux(rx, reply_tx_clone, internal_address, source_address, client_addr).await {
                                        error!(client = %client_addr, "Client handler error: {e}");
                                    } else {
                                        debug!(client = %client_addr, "Client handler finished");
                                    }
                                });
                                clients.insert(client_addr, tx);
                            }
                        }
                    },
                    Ok(None) => {
                        info!("Host closed vsock stream, shutting down mux proxy.");
                        break;
                    }
                    Err(e) => {
                        error!("Failed to read from vsock: {e}. Shutting down mux proxy.");
                        break;
                    }
                }
            },

            Some(reply_packet) = reply_rx.recv() => {
                if write_event(&mut vsock_write, &reply_packet).await.is_err() {
                    error!("Failed to write to vsock, shutting down mux proxy.");
                    break;
                }
                if vsock_write.flush().await.is_err() {
                     error!("Failed to flush vsock, shutting down mux proxy.");
                    break;
                }
            },

            else => {
                break;
            }
        }
    }
    
    info!("UDP Mux proxy shut down.");
    Ok(())
}
