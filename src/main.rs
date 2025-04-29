//! vsock VPN.

#[macro_use]
extern crate tracing;

use anyhow::{Context, Result};
use daemonize::Daemonize;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Display;
use std::path::PathBuf;
use std::{net::SocketAddr, time::Duration};
use structopt::StructOpt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

mod guest;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod host;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod host {
    use anyhow::{anyhow, Result};
    use crate::Host;
    pub async fn execute(command: &Host) -> Result<()> {
        Err(anyhow!("VPN not implemented on target_arch: {}", std::env::consts::ARCH))
    }
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
