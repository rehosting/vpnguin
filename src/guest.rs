//! Guest implementation.

use std::net::{IpAddr, SocketAddr};

use crate::{read_event, Guest, HostRequest, Transport};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    select,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use std::process::Command;
use std::str::FromStr;
use tokio::time::timeout;
use std::time::Duration;


const BUSYBOX_PATH: &str = "/igloo/utils/busybox";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

async fn connect_with_route_check(addr: SocketAddr) -> Result<TcpStream> {
    info!("Attempting to connect to {}", addr);
    match timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            info!("Successfully connected to {}", addr);
            Ok(stream)
        },
        Ok(Err(e)) => {
            warn!("Failed to connect to {}: {}. Checking and repairing route.", addr, e);
            ensure_route_exists(addr.ip())?;
            info!("Retrying connection to {} after route check/repair", addr);
            match timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    info!("Successfully connected to {} after route check/repair", addr);
                    Ok(stream)
                },
                Ok(Err(e)) => {
                    warn!("Failed to connect to {} after route check/repair: {}", addr, e);
                    Err(e).context("Failed to connect after checking/repairing route")
                },
                Err(e) => {
                    warn!("Connection timeout to {} after route check/repair", addr);
                    Err(anyhow::Error::new(e)).context("Connection timeout after checking/repairing route")
                },
            }
        }
        Err(e) => {
            warn!("Initial connection attempt to {} timed out", addr);
            Err(anyhow::Error::new(e)).context("Initial connection attempt timed out")
        },
    }
}

fn ensure_route_exists(ip: IpAddr) -> Result<()> {
    info!("Ensuring route exists for IP: {}", ip);
    let route_info = get_route_info(ip)?;

    if route_info.is_none() {
        info!("No route found for {}. Adding new route.", ip);
        add_route(ip)?;
    } else {
        info!("Existing route found for {}. Attempting to repair.", ip);
        repair_route(ip, route_info.unwrap())?;
    }

    info!("Route check/repair completed for IP: {}", ip);
    Ok(())
}

fn get_route_info(ip: IpAddr) -> Result<Option<RouteInfo>> {
    let cmd = vec![
        "route".to_string(),
        "get".to_string(),
        ip.to_string()
    ];

    let output = run_ip_command(&cmd)?;

    if output.is_empty() {
        return Ok(None); // No route exists
    }

    parse_route_info(&output)
}

#[derive(Debug)]
struct RouteInfo {
    interface: String,
    via: Option<IpAddr>,
}

fn parse_route_info(output: &str) -> Result<Option<RouteInfo>> {
    let mut interface = None;
    let mut via = None;

    for line in output.lines() {
        if let Some(dev_index) = line.find("dev ") {
            interface = line[dev_index + 4..].split_whitespace().next().map(String::from);
        }
        if let Some(via_index) = line.find("via ") {
            via = line[via_index + 4..].split_whitespace().next()
                .and_then(|s| IpAddr::from_str(s).ok());
        }
    }

    match interface {
        Some(iface) => Ok(Some(RouteInfo { interface: iface, via })),
        None => Ok(None),
    }
}

fn add_route(ip: IpAddr) -> Result<()> {
    let interface = find_appropriate_interface(ip)?;
    let mut args = vec![
        "route".to_string(),
        "add".to_string(),
        ip.to_string(),
        "dev".to_string(),
        interface.clone()
    ];

    if !is_local_route(&interface, ip)? {
        let gateway = find_default_gateway(&interface)?;
        args.extend_from_slice(&["via".to_string(), gateway.to_string()]);
    }

    run_ip_command(&args)?;
    Ok(())
}

fn repair_route(ip: IpAddr, route_info: RouteInfo) -> Result<()> {
    // First, try to remove the existing route
    let mut del_args = vec![
        "route".to_string(),
        "del".to_string(),
        ip.to_string(),
        "dev".to_string(),
        route_info.interface.clone()
    ];
    if let Some(via) = route_info.via {
        del_args.extend_from_slice(&["via".to_string(), via.to_string()]);
    }

    if let Err(e) = run_ip_command(&del_args) {
        warn!("Failed to remove existing route: {}. Proceeding with add.", e);
    }

    // Now add the route back
    add_route(ip)
}

fn find_appropriate_interface(ip: IpAddr) -> Result<String> {
    let cmd = vec![
        "addr".to_string(),
        "show".to_string(),
    ];
    let output = run_ip_command(&cmd)?;

    let mut current_interface = String::new();
    let mut found_interface = None;

    for line in output.lines() {
        if line.starts_with(char::is_numeric) {
            current_interface = line.split_whitespace().nth(1)
                .ok_or_else(|| anyhow!("Invalid interface line format"))?
                .trim_end_matches(':')
                .to_string();
        } else if line.trim_start().starts_with("inet") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(addr) = IpAddr::from_str(parts[1].split('/').next().unwrap_or("")) {
                    if addr.is_loopback() == ip.is_loopback() {
                        found_interface = Some(current_interface.clone());
                        break;
                    }
                }
            }
        }
    }

    found_interface.ok_or_else(|| anyhow!("No appropriate interface found for IP: {}", ip))
}

fn is_local_route(interface: &str, ip: IpAddr) -> Result<bool> {
    info!("Checking if {} is a local route on interface {}", ip, interface);

    let cmd = vec![
        "addr".to_string(),
        "show".to_string(),
        "dev".to_string(),
        interface.to_string(),
    ];
    let output = run_ip_command(&cmd)?;

    for line in output.lines() {
        if line.trim_start().starts_with("inet") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let cidr = parts[1];
                let (addr, prefix_len) = cidr.split_once('/')
                    .ok_or_else(|| anyhow!("Invalid CIDR format"))?;
                let network_ip = IpAddr::from_str(addr)
                    .context("Failed to parse network address")?;
                let prefix_len: u8 = prefix_len.parse()
                    .context("Failed to parse prefix length")?;

                if is_ip_in_network(ip, network_ip, prefix_len)? {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn is_ip_in_network(ip: IpAddr, network: IpAddr, prefix_len: u8) -> Result<bool> {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            Ok((u32::from(ip) & mask) == (u32::from(network) & mask))
        },
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = !((1u128 << (128 - prefix_len)) - 1);
            Ok((u128::from(ip) & mask) == (u128::from(network) & mask))
        },
        _ => Err(anyhow!("IP version mismatch")),
    }
}

fn find_default_gateway(interface: &str) -> Result<IpAddr> {
    let cmd = vec![
        "route".to_string(),
        "show".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "default".to_string()
    ];
    let output = run_ip_command(&cmd)?;

    let gateway = output.split_whitespace()
        .nth(2)
        .ok_or_else(|| anyhow!("Invalid route output format"))?;

    IpAddr::from_str(gateway).context("Failed to parse gateway IP address")
}

fn run_ip_command(args: &[String]) -> Result<String> {
    let command_str = format!("{} ip {}", BUSYBOX_PATH, args.join(" "));
    info!("Executing command: {}", command_str);

    let mut command = Command::new(BUSYBOX_PATH);
    command.arg("ip");
    command.args(args);

    let output = command.output().context("Failed to execute busybox ip command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ip command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}



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

            proxy_tcp(vsock, peer_address, internal_address).await?;
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
    vsock: VsockStream,
    peer_address: VsockAddr,
    internal_address: SocketAddr,
) -> Result<()> {
    let mut stream = connect_with_route_check(internal_address).await?;

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
