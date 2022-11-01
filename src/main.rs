//! vsock VPN.

#[macro_use]
extern crate tracing;

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod guest;
mod host;

/// vsock VPN.
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Config {
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
    #[structopt(default_value = "3")]
    context_id: u32,
    /// Command port.
    #[structopt(default_value = "1234")]
    command_port: u32,
}

/// Host endpoint.
#[derive(Clone, StructOpt)]
pub struct Host {
    /// Guest context ID.
    #[structopt(default_value = "3")]
    context_id: u32,
    /// Command socket.
    #[structopt(default_value = "1234")]
    command_port: u32,
    /// Event source path.
    #[structopt(default_value = "/tmp/guest_network_events")]
    event_path: PathBuf,
}

/// Guest request.
#[derive(Deserialize, Serialize)]
pub enum GuestRequest {
    /// Send data from server to client.
    SendData {
        /// Data.
        data: Vec<u8>,
    },
}

/// Host request.
#[derive(Debug, Deserialize, Serialize)]
pub enum HostRequest {
    /// Open a connection.
    OpenConnection {
        /// Internal address.
        address: SocketAddr,
    },
    /// Send data from client to server.
    SendData {
        /// Data.
        data: Vec<u8>,
    },
}

/// Main.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let conf = Config::from_args();
    let result = match conf.command {
        Command::Guest(ref command) => guest::execute(command).await,
        Command::Host(ref command) => host::execute(command).await,
    };

    if let Err(e) = result {
        error!("{e}");
        ::std::process::exit(1);
    }

    Ok(())
}

/// Read an event.
async fn read_event<R, E>(r: &mut R) -> Result<E>
where
    R: AsyncReadExt + Unpin,
    E: DeserializeOwned,
{
    let n = r.read_u16().await.context("unable to read event size")?;
    let mut buffer = Box::new(vec![0u8; n as _]);
    r.read_exact(&mut buffer)
        .await
        .context("unable to read event")?;
    let event: E = bincode::deserialize(&buffer).context("unable to deserialize event")?;
    Ok(event)
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
