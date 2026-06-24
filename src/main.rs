//! vsock VPN.

#[macro_use]
extern crate tracing;

use anyhow::{Context, Result};
use daemonize::Daemonize;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Display;
use std::path::PathBuf;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use structopt::StructOpt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

mod guest;
mod wan;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod host;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wan_probe;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wan_raw;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wan_l2;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod host {
    use anyhow::{anyhow, Result};
    use crate::Host;
    pub async fn execute(command: &Host) -> Result<()> {
        Err(anyhow!("VPN not implemented on target_arch: {}", std::env::consts::ARCH))
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod wan_probe {
    use anyhow::{anyhow, Result};
    use crate::WanProbe;
    pub async fn execute(_command: &WanProbe) -> Result<()> {
        Err(anyhow!("wan-probe not implemented on target_arch: {}", std::env::consts::ARCH))
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod wan_raw {
    use anyhow::{anyhow, Result};
    use crate::Raw;
    pub async fn execute(_command: &Raw) -> Result<()> {
        Err(anyhow!("raw not implemented on target_arch: {}", std::env::consts::ARCH))
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod wan_l2 {
    use anyhow::{anyhow, Result};
    use crate::RawAttach;
    pub async fn execute(_command: &RawAttach) -> Result<()> {
        Err(anyhow!("raw-attach not implemented on target_arch: {}", std::env::consts::ARCH))
    }
}

/// Status byte the guest sends on an interface-routed `Forward` request (one with
/// `iface = Some(_)`), before any payload, so the host can tell how the firmware's
/// firewall on that interface treated the connection.
pub mod wan_status {
    /// Handshake completed — the port is open (firewall ACCEPTed).
    pub const CONNECTED: u8 = 0;
    /// No SYN-ACK within the timeout — the firewall DROPped it.
    pub const FILTERED: u8 = 1;
    /// RST — port closed / service down (not firewalled).
    pub const REFUSED: u8 = 2;
    /// Setup/other error.
    pub const ERROR: u8 = 3;
}

/// vsock read timeout.
const VSOCK_READ_TIMEOUT_SECS: u64 = 60;

/// vsock VPN.
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Config {
    /// Daemonize.
    #[structopt(short, long)]
    daemonize: bool,
    #[structopt(subcommand)]
    command: Command,
}

/// Command.
#[derive(StructOpt)]
enum Command {
    Guest(Guest),
    Host(Host),
    WanProbe(WanProbe),
    Raw(Raw),
    RawAttach(RawAttach),
}

/// Guest endpoint.
#[derive(Clone, StructOpt)]
pub struct Guest {
    /// Context ID.
    #[structopt(short, long, default_value = "3")]
    context_id: u32,
    /// Command port.
    #[structopt(short = "p", long, default_value = "1234")]
    command_port: u32,
    /// Owned interface spec, repeatable. Each `NAME:HOST_IP/GUEST_IP/PREFIX`
    /// stands up a tap-backed userspace TCP/IP stack (smoltcp) on `NAME` so that
    /// `Forward` requests carrying `iface=NAME` ingress on that interface and
    /// traverse its netfilter `INPUT -i NAME` chain. `NAME` must match the
    /// firmware's interface name (e.g. `wan_ifname`). Missing addressing fields
    /// fall back to the WAN defaults (203.0.113.1/203.0.113.2/24). Example:
    /// `--own-iface wan0:203.0.113.1/203.0.113.2/24`.
    #[structopt(long = "own-iface")]
    own_iface: Vec<String>,
    /// Deprecated alias for a single `--own-iface` (uses --wan-host-ip etc.).
    /// Kept for one release; prefer `--own-iface`.
    #[structopt(long)]
    wan_iface: Option<String>,
    /// Address the (deprecated) WAN stack owns (the "external" peer side).
    #[structopt(long, default_value = "203.0.113.1")]
    wan_host_ip: Ipv4Addr,
    /// The firmware's WAN IP (connect target on the tap segment).
    #[structopt(long, default_value = "203.0.113.2")]
    wan_guest_ip: Ipv4Addr,
    /// Prefix length of the WAN subnet shared on the tap.
    #[structopt(long, default_value = "24")]
    wan_prefix: u8,
}

/// Host endpoint.
#[derive(Clone, StructOpt)]
pub struct Host {
    /// Guest context ID.
    #[structopt(short, long, default_value = "3")]
    context_id: u32,
    /// Command socket.
    #[structopt(short = "p", long, default_value = "1234")]
    command_port: u32,
    /// Event source path.
    #[structopt(short, long, default_value = "/tmp/guest_network_events")]
    event_path: PathBuf,
    /// Vhost-user-vsock socket
    #[structopt(short = "u", long)]
    vhost_user_path: Option<PathBuf>,
    /// Event source path.
    #[structopt(short, long)]
    outdir: Option<PathBuf>,
    /// Path to pcap file
    #[structopt(short = "l", long)]
    pcap_path: Option<PathBuf>,
}

/// WAN reachability probe: drive `ForwardWan` requests through the guest's WAN
/// datapath and report, per port, how the firmware's firewall treated each
/// connection (open / filtered / refused). The "nmap the WAN IP" prover.
#[derive(Clone, StructOpt)]
pub struct WanProbe {
    /// Guest context ID.
    #[structopt(short, long, default_value = "3")]
    context_id: u32,
    /// Command port (guest vsock listener).
    #[structopt(short = "p", long, default_value = "1234")]
    command_port: u32,
    /// Vhost-user-vsock socket (same one the host VPN uses).
    #[structopt(short = "u", long)]
    vhost_user_path: Option<PathBuf>,
    /// Owned interface name to probe through (must match a guest `--own-iface`).
    #[structopt(long, default_value = "wan0")]
    iface: String,
    /// Comma-separated TCP ports to probe on the firmware's WAN IP.
    #[structopt(long)]
    ports: String,
    /// Per-port timeout (seconds) waiting for the status reply.
    #[structopt(long, default_value = "12")]
    timeout: u64,
}

/// Raw L3 probe: open a raw-IP channel on an owned interface and send ICMP echo
/// requests (or a user-supplied hex packet) to the firmware's WAN IP, proving
/// that a non-TCP protocol traverses `INPUT -i <iface>`. Replies are printed; a
/// silent timeout means the firewall dropped it.
#[derive(Clone, StructOpt)]
pub struct Raw {
    /// Guest context ID.
    #[structopt(short, long, default_value = "3")]
    context_id: u32,
    /// Base command port (raw L3 listens on command_port + 1).
    #[structopt(short = "p", long, default_value = "1234")]
    command_port: u32,
    /// Vhost-user-vsock socket (same one the host VPN uses).
    #[structopt(short = "u", long)]
    vhost_user_path: Option<PathBuf>,
    /// Owned interface to originate on (must match a guest `--own-iface`).
    #[structopt(long, default_value = "wan0")]
    iface: String,
    /// IP protocol number for the raw channel (1=ICMP, 47=GRE, 50=ESP, 51=AH).
    #[structopt(long, default_value = "1")]
    proto: u8,
    /// Source IP (the stack's host-side address on the segment).
    #[structopt(long, default_value = "203.0.113.1")]
    src_ip: Ipv4Addr,
    /// Destination IP (the firmware's IP on the segment).
    #[structopt(long, default_value = "203.0.113.2")]
    dst_ip: Ipv4Addr,
    /// Number of ICMP echo requests to send (ignored when --packet is given).
    #[structopt(long, default_value = "3")]
    count: u32,
    /// Optional raw IP packet as a hex string to send verbatim instead of ICMP.
    #[structopt(long)]
    packet: Option<String>,
    /// Seconds to wait for replies after sending.
    #[structopt(long, default_value = "5")]
    timeout: u64,
}

/// Attach a host-side TAP to an owned interface's L2 bridge, so a real host stack
/// (assign an IP, drop it in a netns, or point scapy/nmap/a VPN client at it) can
/// drive the firmware's `INPUT -i <iface>` chain with arbitrary L2/L3 traffic.
#[derive(Clone, StructOpt)]
pub struct RawAttach {
    /// Guest context ID.
    #[structopt(short, long, default_value = "3")]
    context_id: u32,
    /// Base command port (raw L2 listens on command_port + 2).
    #[structopt(short = "p", long, default_value = "1234")]
    command_port: u32,
    /// Vhost-user-vsock socket (same one the host VPN uses).
    #[structopt(short = "u", long)]
    vhost_user_path: Option<PathBuf>,
    /// Owned interface (guest side) to bridge (must match a guest `--own-iface`).
    #[structopt(long, default_value = "wan0")]
    iface: String,
    /// Host-side TAP interface name to create and bridge.
    #[structopt(long, default_value = "vpnguin0")]
    tap: String,
}

/// Guest request.
#[derive(Debug, Deserialize, Serialize)]
pub enum GuestRequest {
}

/// Host request.
#[derive(Debug, Deserialize, Serialize)]
pub enum HostRequest {
    /// Forward data.
    Forward {
        /// Internal address.
        internal_address: SocketAddr,
        /// Transport.
        transport: Transport,
        /// Source address (for spoofing).
        source_address: SocketAddr,
        /// Owned interface to route through. `None` → the default loopback path
        /// (connect to 127.0.0.1, traffic ingresses on `lo`). `Some(name)` →
        /// route through that interface's tap-backed stack so the connection
        /// genuinely ingresses on `name` and traverses `INPUT -i name`. On the
        /// `Some` path only `internal_address.port()` is used (the destination
        /// IP is the interface's configured guest IP), and a `wan_status` byte
        /// precedes any payload.
        #[serde(default)]
        iface: Option<String>,
    },
    /// Open a raw L3 (IPv4) channel on an owned interface, bound to an IP protocol
    /// number. Sent as the first message on the raw-L3 vsock port; thereafter the
    /// connection is a length-delimited (`u16 len || packet`) duplex of whole IP
    /// packets. Lets non-TCP protocols (ICMP/ESP/GRE/AH) traverse `INPUT -i iface`.
    RawL3 {
        /// Owned interface to originate on.
        iface: String,
        /// IP protocol number (1=ICMP, 47=GRE, 50=ESP, 51=AH, ...).
        proto: u8,
    },
    /// Open a raw L2 (Ethernet) bridge on an owned interface. Sent as the first
    /// message on the raw-L2 vsock port; thereafter the connection is a
    /// length-delimited (`u16 len || frame`) duplex of whole Ethernet frames.
    RawL2 {
        /// Owned interface to bridge.
        iface: String,
    },
}

/// Transport.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Transport::Tcp => write!(f, "tcp"),
            Transport::Udp => write!(f, "udp"),
        }
    }
}

/// This tracks packet direction when logging
#[derive(Debug, Clone, Copy)]
pub enum PacketDirection {
    HostToGuest,
    GuestToHost,
}

/// Parse an `--own-iface` spec `NAME:HOST_IP/GUEST_IP/PREFIX` into a `WanConfig`.
/// Missing addressing fields fall back to the WAN defaults so a bare
/// `NAME:` (or `NAME`) is valid.
fn parse_iface_spec(spec: &str) -> Result<crate::wan::WanConfig> {
    const DEF_HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const DEF_GUEST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
    const DEF_PREFIX: u8 = 24;

    let (name, rest) = match spec.split_once(':') {
        Some((n, r)) => (n, r),
        None => (spec, ""),
    };
    if name.is_empty() {
        anyhow::bail!("interface spec '{spec}' has an empty name");
    }
    let mut parts = rest.split('/');
    let parse_or = |p: Option<&str>, def: Ipv4Addr| -> Result<Ipv4Addr> {
        match p {
            Some(s) if !s.is_empty() => s
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid IP '{s}' in iface spec '{spec}'")),
            _ => Ok(def),
        }
    };
    let host_ip = parse_or(parts.next(), DEF_HOST)?;
    let guest_ip = parse_or(parts.next(), DEF_GUEST)?;
    let prefix = match parts.next() {
        Some(s) if !s.is_empty() => s
            .parse::<u8>()
            .with_context(|| format!("invalid prefix '{s}' in iface spec '{spec}'"))?,
        _ => DEF_PREFIX,
    };
    Ok(crate::wan::WanConfig::new(
        name.to_string(),
        host_ip,
        guest_ip,
        prefix,
    ))
}

/// Main.
pub fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let conf = Config::from_args();
    if conf.daemonize {
        Daemonize::new().start()?;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let result = match conf.command {
                Command::Guest(ref command) => guest::execute(command).await,
                Command::Host(ref command) => host::execute(command).await,
                Command::WanProbe(ref command) => wan_probe::execute(command).await,
                Command::Raw(ref command) => wan_raw::execute(command).await,
                Command::RawAttach(ref command) => wan_l2::execute(command).await,
            };

            if let Err(e) = result {
                error!("{e:?}");
                ::std::process::exit(1);
            }
        });

    Ok(())
}

/// Read an event.
async fn read_event<R, E>(r: &mut R) -> Result<Option<E>>
where
    R: AsyncReadExt + Unpin,
    E: DeserializeOwned,
{
    let n = match timeout(Duration::from_secs(VSOCK_READ_TIMEOUT_SECS), r.read_u16()).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(None),
    };
    let mut buffer = vec![0u8; n as _];
    timeout(
        Duration::from_secs(VSOCK_READ_TIMEOUT_SECS),
        r.read_exact(&mut buffer),
    )
    .await
    .context("unable to read event (timeout)")?
    .context("unable to read event (I/O error)")?;
    let event: E = bincode::deserialize(&buffer).context("unable to deserialize event")?;
    Ok(Some(event))
}

/// Write an event.
async fn write_event<W, E>(w: &mut W, e: &E) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    E: Serialize,
{
    let buffer = bincode::serialize(e).context("unable to serialize event")?;
    w.write_u16(buffer.len() as _)
        .await
        .context("unable to write event size")?;
    w.write_all(&buffer)
        .await
        .context("unable to write event")?;
    Ok(())
}
