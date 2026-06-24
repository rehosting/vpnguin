//! Raw L2 attach (host side).
//!
//! Creates a host-side TAP interface and bridges whole Ethernet frames between it
//! and an owned interface's L2 bridge in the guest (the raw-L2 vsock port). Once
//! attached, anything you point at the host TAP — assign it an IP, move it into a
//! netns, run scapy/nmap raw, or a real IPsec/PPTP client — reaches the firmware's
//! WAN exactly as an external attacker would, traversing its `INPUT -i <iface>`
//! chain.
//!
//! Run as root (TAP creation needs CAP_NET_ADMIN). Configure the host TAP after
//! attach, e.g.:
//!   ip addr add 203.0.113.9/24 dev vpnguin0
//!   ping 203.0.113.2     # the firmware's WAN IP

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::host::connect_to_socket;
use crate::{write_event, HostRequest, RawAttach};
use anyhow::{anyhow, Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// TUNSETIFF = _IOW('T', 202, int); TAP, no packet-info header.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const IFF_UP_RUNNING: i32 = 0x1 | 0x40; // IFF_UP | IFF_RUNNING
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
/// Max frame we read from the tap (jumbo-safe).
const FRAME_CAP: usize = 9000;

/// Execute the raw-L2 attach.
pub async fn execute(command: &RawAttach) -> Result<()> {
    // 1. Connect the raw-L2 vsock port and send the RawL2 header.
    let vsock = connect_to_socket(
        command.vhost_user_path.clone(),
        command.command_port + 2,
        command.context_id,
    )
    .await
    .context("unable to connect to raw-L2 vsock port")?;
    let (mut vsock_read, mut vsock_write) = vsock.socksplit();
    write_event(
        &mut vsock_write,
        &HostRequest::RawL2 {
            iface: command.iface.clone(),
        },
    )
    .await
    .context("unable to send RawL2 header")?;

    // 2. Create and bring up the host TAP.
    let tap = create_tap(&command.tap).context("unable to create host TAP")?;
    set_link_up(&command.tap).context("unable to bring host TAP up")?;
    let afd = AsyncFd::new(tap).context("unable to register host TAP with tokio")?;
    let raw = afd.get_ref().as_raw_fd();

    println!(
        "Bridged host TAP '{}' <-> guest interface '{}'. Configure it, e.g.:",
        command.tap, command.iface
    );
    println!("  sudo ip addr add 203.0.113.9/24 dev {}", command.tap);
    println!("  ping 203.0.113.2      # the firmware's WAN IP");
    println!("Ctrl-C to detach.");

    // 3. Bridge frames until either side closes.
    loop {
        tokio::select! {
            readable = afd.readable() => {
                let mut guard = readable.context("tap readiness error")?;
                match guard.try_io(|_| read_tap_frame(raw)) {
                    Ok(Ok(frame)) => {
                        vsock_write.write_u16(frame.len() as u16).await
                            .context("unable to write frame length to vsock")?;
                        vsock_write.write_all(&frame).await
                            .context("unable to write frame to vsock")?;
                    }
                    Ok(Err(e)) => return Err(e).context("tap read failed"),
                    Err(_would_block) => {}
                }
            }
            frame = read_frame(&mut vsock_read) => {
                match frame? {
                    Some(frame) => write_tap_frame(&afd, raw, &frame).await?,
                    None => break, // vsock closed
                }
            }
        }
    }
    Ok(())
}

/// Read one length-delimited frame (`u16 len || bytes`) from the vsock side.
async fn read_frame(
    r: &mut Box<dyn tokio::io::AsyncRead + Unpin + Send>,
) -> Result<Option<Vec<u8>>> {
    let n = match r.read_u16().await {
        Ok(n) => n as usize,
        Err(_) => return Ok(None),
    };
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .await
        .context("unable to read frame body from vsock")?;
    Ok(Some(buf))
}

/// One non-blocking read from the tap fd → a single Ethernet frame.
fn read_tap_frame(fd: RawFd) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; FRAME_CAP];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Write one Ethernet frame to the tap fd, awaiting writability as needed.
async fn write_tap_frame(afd: &AsyncFd<OwnedFd>, fd: RawFd, frame: &[u8]) -> Result<()> {
    loop {
        let mut guard = afd.writable().await.context("tap write readiness error")?;
        let res = guard.try_io(|_| {
            let n = unsafe {
                libc::write(fd, frame.as_ptr() as *const libc::c_void, frame.len())
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
        match res {
            Ok(r) => return r.context("tap write failed"),
            Err(_would_block) => continue,
        }
    }
}

/// Create a non-blocking TAP interface named `name`.
fn create_tap(name: &str) -> Result<OwnedFd> {
    if name.len() >= 16 {
        return Err(anyhow!("tap name '{name}' too long"));
    }
    let fd = unsafe {
        libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    let flags = (IFF_TAP | IFF_NO_PI).to_ne_bytes();
    ifr[16] = flags[0];
    ifr[17] = flags[1];
    let r = unsafe { libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr()) };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF");
    }
    Ok(owned)
}

/// Bring an interface administratively UP (IFF_UP|IFF_RUNNING) via ioctl.
fn set_link_up(name: &str) -> Result<()> {
    if name.len() >= 16 {
        return Err(anyhow!("interface name too long"));
    }
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket");
        }
        let mut ifr = [0u8; 40];
        ifr[..name.len()].copy_from_slice(name.as_bytes());
        if libc::ioctl(fd, SIOCGIFFLAGS as _, ifr.as_mut_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e).context("SIOCGIFFLAGS");
        }
        let mut flags = i16::from_ne_bytes([ifr[16], ifr[17]]) as i32;
        flags |= IFF_UP_RUNNING;
        let fb = (flags as i16).to_ne_bytes();
        ifr[16] = fb[0];
        ifr[17] = fb[1];
        let r = libc::ioctl(fd, SIOCSIFFLAGS as _, ifr.as_mut_ptr());
        libc::close(fd);
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS");
        }
    }
    Ok(())
}
