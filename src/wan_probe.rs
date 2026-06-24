//! WAN reachability probe (host side).
//!
//! Drives interface-routed `Forward` requests through a guest's owned-interface
//! datapath (smoltcp-over-tap) and reports, per port, how the firmware's firewall
//! treated the connection: `open` (ACCEPT, handshake completed), `filtered` (DROP,
//! no SYN-ACK), or `refused` (RST). This is the "nmap the WAN IP through the
//! firewall" prover — it reaches the device's services exactly as an external
//! client on that interface would.

use std::net::SocketAddr;

use crate::host::connect_to_socket;
use crate::{wan_status, write_event, HostRequest, Transport, WanProbe};
use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

/// Execute the WAN probe.
pub async fn execute(command: &WanProbe) -> Result<()> {
    let ports = parse_ports(&command.ports)?;
    println!("Probing {} WAN port(s) through the guest firewall:", ports.len());
    for port in ports {
        let label = match probe_one(command, port).await {
            Ok(s) => s.to_string(),
            Err(e) => format!("error ({e:#})"),
        };
        println!("  {port:>5}/tcp  {label}");
    }
    Ok(())
}

/// Probe a single port; returns a human-readable verdict.
async fn probe_one(command: &WanProbe, port: u16) -> Result<&'static str> {
    let mut vsock = connect_to_socket(
        command.vhost_user_path.clone(),
        command.command_port,
        command.context_id,
    )
    .await
    .context("unable to connect to guest vsock")?;

    // Interface-routed forward: the destination IP is the interface's configured
    // guest IP, so only the port matters — send a wildcard address.
    let request = HostRequest::Forward {
        internal_address: SocketAddr::from(([0, 0, 0, 0], port)),
        transport: Transport::Tcp,
        source_address: SocketAddr::from(([0, 0, 0, 0], 0)),
        iface: Some(command.iface.clone()),
    };
    write_event(&mut vsock, &request)
        .await
        .context("unable to send Forward request")?;

    let status = match timeout(Duration::from_secs(command.timeout), vsock.read_u8()).await {
        Ok(Ok(b)) => b,
        // Connection closed before any status — treat as no response.
        Ok(Err(_)) => return Ok("no-response (vsock closed)"),
        Err(_) => return Ok("filtered (probe timeout)"),
    };

    Ok(match status {
        wan_status::CONNECTED => "open",
        wan_status::FILTERED => "filtered",
        wan_status::REFUSED => "refused",
        _ => "error",
    })
}

/// Parse a comma-separated port list.
fn parse_ports(s: &str) -> Result<Vec<u16>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u16>().with_context(|| format!("invalid port '{p}'")))
        .collect()
}
