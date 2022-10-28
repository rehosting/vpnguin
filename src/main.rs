//! vsock VPN.

#[macro_use]
extern crate tracing;

use std::net::SocketAddr;

use anyhow::Result;
use structopt::StructOpt;

mod guest;
mod host;

/// vsock port.
const VSOCK_PORT: u32 = 1234;

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
#[derive(StructOpt)]
pub struct Guest {
    /// Command socket.
    #[structopt()]
    command_socket: SocketAddr,
}

/// Host endpoint.
#[derive(StructOpt)]
pub struct Host {
    /// Command socket.
    #[structopt()]
    command_socket: SocketAddr,
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
