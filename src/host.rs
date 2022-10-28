//! Host implementation.

use crate::{Host, VSOCK_PORT};
use anyhow::{Context, Result};
use tokio_vsock::VsockListener;

/// Execute the host endpoint.
pub async fn execute(command: &Host) -> Result<()> {
    // Create a vsock listener and process control commands
    let listener =
        VsockListener::bind(libc::VMADDR_CID_HOST, VSOCK_PORT).context("unable to bind vsock")?;

    Ok(())
}
