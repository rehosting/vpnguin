//! Guest implementation.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::wan::{L2Conn, RawConn, WanConn, WanStack};
use crate::{parse_iface_spec, read_event, Guest, HostRequest, Transport};
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
    let mut listener = VsockListener::bind(VsockAddr::new(command.context_id, command.command_port))
        .context("unable to bind vsock listener")?;

    // Bring up the set of owned interfaces (each a tap-backed userspace TCP/IP
    // stack). Specs come from `--own-iface`; a lone `--wan-iface` is accepted as a
    // deprecated alias for one entry. With neither, the map is empty and only the
    // default loopback ("LAN") path is served — byte-identical to the old default.
    let mut specs: Vec<crate::wan::WanConfig> = Vec::new();
    for spec in &command.own_iface {
        match parse_iface_spec(spec) {
            Ok(cfg) => specs.push(cfg),
            Err(e) => error!("ignoring bad --own-iface '{spec}': {e:#}"),
        }
    }
    if specs.is_empty() {
        if let Some(iface) = &command.wan_iface {
            warn!("--wan-iface is deprecated; prefer --own-iface NAME:HOST/GUEST/PREFIX");
            specs.push(crate::wan::WanConfig::new(
                iface.clone(),
                command.wan_host_ip,
                command.wan_guest_ip,
                command.wan_prefix,
            ));
        }
    }

    let mut ifaces: HashMap<String, Arc<WanStack>> = HashMap::new();
    for cfg in specs {
        let name = cfg.iface.clone();
        match WanStack::new(cfg) {
            Ok(s) => {
                info!(iface = name, "owned-interface datapath enabled");
                ifaces.insert(name, Arc::new(s));
            }
            Err(e) => {
                // Non-fatal: loopback exposure still works; only forwards routed
                // to this interface fail.
                error!("failed to start datapath on '{name}': {e:#}");
            }
        }
    }
    let ifaces = Arc::new(ifaces);

    // Lower-layer datapaths get their own vsock ports: raw L3 (whole IP packets)
    // on command_port+1. Bound unconditionally — inert unless a host connects and
    // names an owned interface.
    let raw_l3 = VsockListener::bind(VsockAddr::new(
        command.context_id,
        command.command_port + 1,
    ))
    .context("unable to bind raw-L3 vsock listener")?;
    {
        let ifaces = ifaces.clone();
        tokio::spawn(async move { accept_raw_l3(raw_l3, ifaces).await });
    }

    // Raw L2 (whole Ethernet frames) on command_port+2.
    let raw_l2 = VsockListener::bind(VsockAddr::new(
        command.context_id,
        command.command_port + 2,
    ))
    .context("unable to bind raw-L2 vsock listener")?;
    {
        let ifaces = ifaces.clone();
        tokio::spawn(async move { accept_raw_l2(raw_l2, ifaces).await });
    }

    loop {
        let (vsock, peer_address) = listener
            .accept()
            .await
            .context("unable to accept vsock client")?;
        let ifaces = ifaces.clone();
        tokio::spawn(async move {
            if let Err(e) = process_client(vsock, peer_address, ifaces).await {
                error!("unable to process client: {e:#?}");
            }
        });
    }
}

/// Accept loop for the raw-L3 vsock port.
async fn accept_raw_l3(
    mut listener: VsockListener,
    ifaces: Arc<HashMap<String, Arc<WanStack>>>,
) {
    loop {
        match listener.accept().await {
            Ok((vsock, peer)) => {
                let ifaces = ifaces.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_raw_l3_client(vsock, peer, ifaces).await {
                        error!("raw-L3 client error: {e:#}");
                    }
                });
            }
            Err(e) => {
                error!("raw-L3 accept error: {e}");
                break;
            }
        }
    }
}

/// Handle a raw-L3 connection: read the `RawL3` header, open a raw socket on the
/// named interface, then bridge whole IP packets between vsock and the stack.
async fn process_raw_l3_client(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    ifaces: Arc<HashMap<String, Arc<WanStack>>>,
) -> Result<()> {
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read RawL3 init event")?;
    let (iface, proto) = match e {
        Some(HostRequest::RawL3 { iface, proto }) => (iface, proto),
        _ => return Err(anyhow!("raw-L3 port expects a RawL3 request")),
    };
    let stack = ifaces
        .get(&iface)
        .ok_or_else(|| anyhow!("RawL3 iface='{iface}' but no such owned interface"))?
        .clone();
    info!(iface = iface.as_str(), proto, "raw-L3 channel opened");
    let conn = stack.open_raw(proto).await?;
    proxy_raw_l3(vsock, peer_address, conn).await
}

/// Bridge whole IP packets between a vsock client and a raw socket. Each direction
/// is length-delimited: `u16 len` then `len` bytes (one IP packet).
async fn proxy_raw_l3(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    conn: RawConn,
) -> Result<()> {
    let RawConn {
        to_stack,
        mut from_stack,
    } = conn;
    let (mut vsock_read, mut vsock_write) = vsock.split();

    let host_to_stack = async {
        loop {
            let n = match vsock_read.read_u16().await {
                Ok(n) => n as usize,
                Err(_) => break,
            };
            let mut buf = vec![0u8; n];
            if vsock_read.read_exact(&mut buf).await.is_err() {
                break;
            }
            if to_stack.send(buf).is_err() {
                break;
            }
        }
    };

    let stack_to_host = async {
        loop {
            match from_stack.recv().await {
                Some(pkt) => {
                    if vsock_write.write_u16(pkt.len() as u16).await.is_err() {
                        break;
                    }
                    if vsock_write.write_all(&pkt).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    };

    select! {
        _ = host_to_stack => {},
        _ = stack_to_host => {},
    }

    debug!(peer = peer_address.to_string(), "raw-L3 bridge completed");
    Ok(())
}

/// Accept loop for the raw-L2 vsock port.
async fn accept_raw_l2(
    mut listener: VsockListener,
    ifaces: Arc<HashMap<String, Arc<WanStack>>>,
) {
    loop {
        match listener.accept().await {
            Ok((vsock, peer)) => {
                let ifaces = ifaces.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_raw_l2_client(vsock, peer, ifaces).await {
                        error!("raw-L2 client error: {e:#}");
                    }
                });
            }
            Err(e) => {
                error!("raw-L2 accept error: {e}");
                break;
            }
        }
    }
}

/// Handle a raw-L2 connection: read the `RawL2` header, open an L2 bridge on the
/// named interface, then bridge whole Ethernet frames between vsock and the tap.
async fn process_raw_l2_client(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    ifaces: Arc<HashMap<String, Arc<WanStack>>>,
) -> Result<()> {
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read RawL2 init event")?;
    let iface = match e {
        Some(HostRequest::RawL2 { iface }) => iface,
        _ => return Err(anyhow!("raw-L2 port expects a RawL2 request")),
    };
    let stack = ifaces
        .get(&iface)
        .ok_or_else(|| anyhow!("RawL2 iface='{iface}' but no such owned interface"))?
        .clone();
    info!(iface = iface.as_str(), "raw-L2 bridge opened");
    let conn = stack.open_l2().await?;
    proxy_raw_l2(vsock, peer_address, conn).await
}

/// Bridge whole Ethernet frames between a vsock client and the tap. Each
/// direction is length-delimited: `u16 len` then `len` bytes (one frame).
async fn proxy_raw_l2(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    conn: L2Conn,
) -> Result<()> {
    let L2Conn {
        to_tap,
        mut from_tap,
    } = conn;
    let (mut vsock_read, mut vsock_write) = vsock.split();

    let host_to_tap = async {
        loop {
            let n = match vsock_read.read_u16().await {
                Ok(n) => n as usize,
                Err(_) => break,
            };
            let mut buf = vec![0u8; n];
            if vsock_read.read_exact(&mut buf).await.is_err() {
                break;
            }
            if to_tap.send(buf).is_err() {
                break;
            }
        }
    };

    let tap_to_host = async {
        loop {
            match from_tap.recv().await {
                Some(frame) => {
                    if vsock_write.write_u16(frame.len() as u16).await.is_err() {
                        break;
                    }
                    if vsock_write.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    };

    select! {
        _ = host_to_tap => {},
        _ = tap_to_host => {},
    }

    debug!(peer = peer_address.to_string(), "raw-L2 bridge completed");
    Ok(())
}

/// Process a vsock client.
async fn process_client(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    ifaces: Arc<HashMap<String, Arc<WanStack>>>,
) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    // Process the init event
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read init event")?;
    let req = match e {
        Some(req) => req,
        None => return Err(anyhow!("unable to read init event (no event received)")),
    };
    let HostRequest::Forward {
        mut internal_address,
        transport,
        source_address,
        iface,
    } = req
    else {
        return Err(anyhow!("control port expects a Forward request"));
    };

    // Interface-routed forward: ingress on a tap-backed stack so the firmware's
    // netfilter `INPUT -i <iface>` chain is exercised. A `wan_status` byte
    // precedes any payload so the host learns how the firewall treated it.
    if let Some(name) = iface {
        let stack = match ifaces.get(&name) {
            Some(s) => s.clone(),
            None => {
                let _ = vsock.write_u8(crate::wan_status::ERROR).await;
                return Err(anyhow!(
                    "Forward iface='{name}' but no such owned interface (check --own-iface)"
                ));
            }
        };
        match transport {
            Transport::Tcp => {
                // On the interface path the destination IP is the interface's
                // configured guest IP; only the port from internal_address matters.
                let port = internal_address.port();
                match stack.connect(port).await {
                    Ok(conn) => {
                        info!("{name} connect to :{port} established (open)");
                        vsock
                            .write_u8(crate::wan_status::CONNECTED)
                            .await
                            .context("unable to write status byte")?;
                        proxy_tcp_wan(vsock, peer_address, conn).await?;
                    }
                    Err(e) => {
                        let code = match e {
                            crate::wan::ConnError::Filtered => crate::wan_status::FILTERED,
                            crate::wan::ConnError::Refused => crate::wan_status::REFUSED,
                            _ => crate::wan_status::ERROR,
                        };
                        warn!("{name} connect to :{port} -> {e}");
                        let _ = vsock.write_u8(code).await;
                    }
                }
            }
            Transport::Udp => {
                let _ = vsock.write_u8(crate::wan_status::ERROR).await;
                return Err(anyhow!("interface-routed UDP forwarding not yet implemented"));
            }
        }
        return Ok(());
    }

    // Default loopback ("LAN") path — unchanged: connect to 127.0.0.1 so traffic
    // ingresses on `lo`.
    match transport {
        Transport::Tcp => {
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
                }
                Ok(Err(e)) => {
                    warn!("Failed to connect to {}: {}", internal_address, e);
                    return Err(e).context(format!("Failed to connect to {}", internal_address));
                }
                Err(_) => {
                    warn!("Connection attempt to {} timed out", internal_address);
                    return Err(anyhow!("Connection attempt timed out"));
                }
            }
        }
        Transport::Udp => {
            // Check for wildcard addresses and replace with localhost
            if internal_address.ip() == IpAddr::V4([0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V4([127, 0, 0, 1].into()));
            } else if internal_address.ip() == IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()) {
                internal_address.set_ip(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()));
            }
            proxy_udp(vsock, peer_address, internal_address, source_address).await?;
        }
    }

    Ok(())
}

/// Proxy a vsock client over a WAN connection (smoltcp-backed), bridging bytes
/// between the vsock stream and the WAN socket's channels.
async fn proxy_tcp_wan(
    mut vsock: VsockStream,
    peer_address: VsockAddr,
    conn: WanConn,
) -> Result<()> {
    let WanConn {
        to_wan,
        mut from_wan,
    } = conn;
    let (mut vsock_read, mut vsock_write) = vsock.split();

    let vsock_to_wan = async {
        let mut buffer = [0u8; 8192];
        loop {
            match vsock_read.read(&mut buffer).await {
                Ok(0) => break, // EOF; dropping `to_wan` closes the WAN socket
                Ok(n) => {
                    if to_wan.send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let wan_to_vsock = async {
        loop {
            match from_wan.recv().await {
                Some(data) => {
                    if vsock_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                None => {
                    let _ = vsock_write.shutdown().await;
                    break;
                }
            }
        }
    };

    select! {
        _ = vsock_to_wan => {},
        _ = wan_to_vsock => {},
    }

    debug!(peer = peer_address.to_string(), "WAN proxy completed");
    Ok(())
}

/// Proxy TCP.
async fn proxy_tcp(
    mut vsock: VsockStream,
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
