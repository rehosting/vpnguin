//! WAN datapath: a userspace TCP/IP stack (smoltcp) bound to a guest TAP
//! interface, so connections we originate genuinely ingress on the firmware's
//! WAN interface and traverse its netfilter `INPUT -i <wan>` chain.
//!
//! See `docs/WAN_BRIDGE.md`. The kernel owns the WAN IP (e.g. 203.0.113.2) on
//! the tap; smoltcp here is the remote peer (e.g. 203.0.113.1) on the same L2
//! segment. A connect that the firewall ACCEPTs completes its handshake (port
//! *open*); one that is DROPped never gets a SYN-ACK (reported *filtered*); a RST
//! is reported *refused*.
//!
//! smoltcp is poll-driven and not async, so the stack runs on a dedicated thread
//! and is reached from the tokio side via channels.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Instant as StdInstant;

use anyhow::{anyhow, Result};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    wait as phy_wait, Device, DeviceCapabilities, Medium, RxToken, TunTapInterface,
};
use smoltcp::socket::{raw, tcp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpProtocol, IpVersion};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// How long to wait for a SYN-ACK before declaring a port filtered (DROP).
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// Upper bound on each poll-loop sleep so channel activity is serviced promptly.
const MAX_WAIT: SmolDuration = SmolDuration::from_millis(5);
/// Per-socket buffer size.
const SOCK_BUF: usize = 64 * 1024;

/// Why a WAN connect did not yield a usable stream.
#[derive(Debug, Error)]
pub enum ConnError {
    /// No response to the SYN within the timeout — the firewall dropped it.
    #[error("filtered (no response to SYN within timeout)")]
    Filtered,
    /// Connection reset — the port is closed/service down (not firewalled).
    #[error("refused (RST)")]
    Refused,
    /// The WAN stack thread is gone.
    #[error("WAN stack unavailable")]
    StackGone,
    /// Other smoltcp/setup error.
    #[error("WAN error: {0}")]
    Io(String),
}

/// Configuration for the tap-backed WAN stack.
#[derive(Clone, Debug)]
pub struct WanConfig {
    /// TAP interface name; must match the firmware's `wan_ifname`.
    pub iface: String,
    /// Address smoltcp owns (the "external" peer / upstream side).
    pub host_ip: Ipv4Addr,
    /// The firmware's WAN IP (the connect target).
    pub guest_ip: Ipv4Addr,
    /// Prefix length of the shared subnet.
    pub prefix: u8,
    /// MAC for the smoltcp side (locally administered).
    pub mac: [u8; 6],
}

impl WanConfig {
    pub fn new(iface: String, host_ip: Ipv4Addr, guest_ip: Ipv4Addr, prefix: u8) -> Self {
        Self {
            iface,
            host_ip,
            guest_ip,
            prefix,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }
    }
}

/// A live WAN connection bridged to the smoltcp stack.
pub struct WanConn {
    /// Bytes from the host → write into the WAN socket.
    pub to_wan: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes from the WAN socket → forward to the host. `None` = EOF.
    pub from_wan: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// A raw L3 channel bridged to a smoltcp raw (IPv4) socket: whole IP packets in
/// both directions. The host supplies complete IP packets (header + payload);
/// smoltcp does the Ethernet framing + ARP. Lets non-TCP protocols (ICMP, ESP,
/// GRE, AH, ...) traverse the firmware's `INPUT -i <iface>` chain.
pub struct RawConn {
    /// IP packets from the host → emit on the interface.
    pub to_stack: mpsc::UnboundedSender<Vec<u8>>,
    /// IP packets received for this protocol → forward to the host.
    pub from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// A live L2 bridge to the interface's tap: whole Ethernet frames in both
/// directions. Host-supplied frames are injected as ingress (guest RX); frames
/// the guest emits on the wire are teed up to the host. Lets a real host stack
/// (scapy/nmap/tap+netns/VPN clients) drive the firmware's `INPUT -i <iface>`.
pub struct L2Conn {
    /// Ethernet frames from the host → inject into the tap (guest RX).
    pub to_tap: mpsc::UnboundedSender<Vec<u8>>,
    /// Ethernet frames the guest emitted → forward to the host.
    pub from_tap: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// Command sent to the stack thread.
enum Command {
    Connect {
        port: u16,
        resp: oneshot::Sender<Result<WanConn, ConnError>>,
    },
    OpenRaw {
        /// IP protocol number to bind the raw socket to (e.g. 1=ICMP, 47=GRE,
        /// 50=ESP, 51=AH).
        proto: u8,
        resp: oneshot::Sender<Result<RawConn, ConnError>>,
    },
    OpenL2 {
        resp: oneshot::Sender<Result<L2Conn, ConnError>>,
    },
}

/// Handle to the WAN stack (clonable via Arc by the caller).
pub struct WanStack {
    cmd_tx: mpsc::UnboundedSender<Command>,
}

impl WanStack {
    /// Create the tap, bring up the smoltcp stack on a dedicated thread.
    pub fn new(cfg: WanConfig) -> Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        thread::Builder::new()
            .name("wan-stack".into())
            .spawn(move || run_stack(cfg, cmd_rx, ready_tx))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { cmd_tx }),
            Ok(Err(e)) => Err(anyhow!("WAN stack init failed: {e}")),
            Err(_) => Err(anyhow!("WAN stack thread died during init")),
        }
    }

    /// Open a TCP connection to `<guest_ip>:port` through the WAN interface.
    pub async fn connect(&self, port: u16) -> Result<WanConn, ConnError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Connect { port, resp: resp_tx })
            .map_err(|_| ConnError::StackGone)?;
        resp_rx.await.map_err(|_| ConnError::StackGone)?
    }

    /// Open a raw IPv4 channel bound to `proto` through this interface.
    pub async fn open_raw(&self, proto: u8) -> Result<RawConn, ConnError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::OpenRaw {
                proto,
                resp: resp_tx,
            })
            .map_err(|_| ConnError::StackGone)?;
        resp_rx.await.map_err(|_| ConnError::StackGone)?
    }

    /// Open an L2 (Ethernet frame) bridge to this interface's tap. Only one L2
    /// session is active at a time; opening a new one supersedes the previous.
    pub async fn open_l2(&self) -> Result<L2Conn, ConnError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::OpenL2 { resp: resp_tx })
            .map_err(|_| ConnError::StackGone)?;
        resp_rx.await.map_err(|_| ConnError::StackGone)?
    }
}

/// A `smoltcp` device that wraps a TAP and tees every received (guest-emitted)
/// frame to an optional channel, so an L2 bridge can observe the wire while
/// smoltcp continues to run its own sockets on the same interface.
struct TeeDevice {
    inner: TunTapInterface,
    /// When an L2 session is active, each received frame is cloned here.
    rx_tap: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

/// RxToken that clones the frame to the L2 channel before handing it to smoltcp.
struct TeeRxToken<R: RxToken> {
    inner: R,
    rx_tap: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl<R: RxToken> RxToken for TeeRxToken<R> {
    fn consume<Re, F: FnOnce(&[u8]) -> Re>(self, f: F) -> Re {
        let rx_tap = self.rx_tap;
        self.inner.consume(|buf| {
            if let Some(tx) = &rx_tap {
                let _ = tx.send(buf.to_vec());
            }
            f(buf)
        })
    }
}

impl Device for TeeDevice {
    type RxToken<'a> = TeeRxToken<<TunTapInterface as Device>::RxToken<'a>> where Self: 'a;
    type TxToken<'a> = <TunTapInterface as Device>::TxToken<'a> where Self: 'a;

    fn receive(&mut self, timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let rx_tap = self.rx_tap.clone();
        self.inner
            .receive(timestamp)
            .map(|(rx, tx)| (TeeRxToken { inner: rx, rx_tap }, tx))
    }

    fn transmit(&mut self, timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(timestamp)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }
}

/// Per-connection bookkeeping on the stack thread.
struct Conn {
    started: StdInstant,
    established: bool,
    /// Reply channel + the WanConn to hand back, taken on establish/fail.
    resp: Option<oneshot::Sender<Result<WanConn, ConnError>>>,
    payload: Option<WanConn>,
    /// Host → WAN bytes awaiting the socket tx buffer.
    rx_to_wan: mpsc::UnboundedReceiver<Vec<u8>>,
    /// WAN → host bytes.
    tx_from_wan: mpsc::UnboundedSender<Vec<u8>>,
    pending: Vec<u8>,
    pending_off: usize,
    closing: bool,
}

/// Per-raw-socket bookkeeping on the stack thread.
struct RawState {
    /// Host → stack IP packets awaiting emission.
    rx_to_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Stack → host received IP packets.
    tx_from_stack: mpsc::UnboundedSender<Vec<u8>>,
}

/// The smoltcp poll loop (runs on its own thread).
fn run_stack(
    cfg: WanConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    // Open the tap ourselves rather than via smoltcp's `TunTapInterface::new`.
    // smoltcp 0.12 writes the TUNSETIFF flags into a 32-bit `ifr_data`, but the
    // kernel reads a 16-bit `ifr_flags` short at that offset: on big-endian
    // targets (mipseb, mips64eb, powerpc64) the flag bits land in the wrong half,
    // so TUNSETIFF fails with EINVAL and no tap ever comes up. `open_tap_fd`
    // writes a correctly-sized 16-bit `ifr_flags`, then we hand the fd to
    // `from_fd`, which is endian-safe on every arch.
    let tap_fd = match open_tap_fd(&cfg.iface) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("open tap '{}': {e}", cfg.iface)));
            return;
        }
    };
    let tuntap = match TunTapInterface::from_fd(tap_fd, Medium::Ethernet, TAP_MTU) {
        Ok(d) => d,
        Err(e) => {
            // SAFETY: tap_fd is ours and not yet owned by smoltcp on this path.
            unsafe { libc::close(tap_fd) };
            let _ = ready_tx.send(Err(format!("open tap '{}': {e}", cfg.iface)));
            return;
        }
    };
    let fd = tuntap.as_raw_fd();
    let mut device = TeeDevice {
        inner: tuntap,
        rx_tap: None,
    };

    // smoltcp creates the tap but leaves it admin-DOWN. Writing to a down tap
    // returns EIO (which smoltcp turns into a panic), and the firmware's WAN
    // bring-up sees "no carrier" and skips configuring it. Bring the link UP so
    // both the datapath and the firmware's rc WAN setup work.
    if let Err(e) = set_link_up(&cfg.iface) {
        // Non-fatal: the firmware may still bring it up; log and continue.
        warn!("could not bring '{}' up ({e}); WAN writes may fail", cfg.iface);
    }

    // Assign the configured guest IP to the interface so the guest kernel has a
    // local address on this segment (turnkey: many firmwares don't actually bring
    // their WAN up under emulation, so connections to guest_ip would otherwise hit
    // no local IP and never reach a listener). nvram should set the same address,
    // so this is idempotent on firmwares that do configure it.
    if let Err(e) = set_ip_addr(&cfg.iface, cfg.guest_ip, cfg.prefix) {
        warn!(
            "could not assign {}/{} to '{}' ({e}); firmware must configure it",
            cfg.guest_ip, cfg.prefix, cfg.iface
        );
    }

    let base = StdInstant::now();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(cfg.mac)));
    let mut iface = Interface::new(config, &mut device, smol_now(base));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(cfg.host_ip), cfg.prefix))
            .ok();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut conns: HashMap<SocketHandle, Conn> = HashMap::new();
    let mut raws: HashMap<SocketHandle, RawState> = HashMap::new();
    // Host → tap frame injector for the active L2 session (at most one).
    let mut l2_inject: Option<mpsc::UnboundedReceiver<Vec<u8>>> = None;
    let mut next_port: u16 = 49152;

    let _ = ready_tx.send(Ok(()));
    info!(
        iface = cfg.iface,
        host_ip = %cfg.host_ip,
        guest_ip = %cfg.guest_ip,
        "WAN stack up"
    );

    loop {
        // 1. Drain pending commands.
        loop {
            match cmd_rx.try_recv() {
                Ok(Command::Connect { port, resp }) => {
                    open_connection(
                        &mut iface,
                        &mut sockets,
                        &mut conns,
                        &cfg,
                        &mut next_port,
                        port,
                        resp,
                    );
                }
                Ok(Command::OpenRaw { proto, resp }) => {
                    open_raw(&mut sockets, &mut raws, proto, resp);
                }
                Ok(Command::OpenL2 { resp }) => {
                    // host → tap (inject) and tap → host (tee) channels.
                    let (to_tap_tx, to_tap_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    let (from_tap_tx, from_tap_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    l2_inject = Some(to_tap_rx);
                    device.rx_tap = Some(from_tap_tx);
                    info!(iface = cfg.iface, "L2 bridge session opened");
                    let _ = resp.send(Ok(L2Conn {
                        to_tap: to_tap_tx,
                        from_tap: from_tap_rx,
                    }));
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    info!("WAN stack shutting down (no more handles)");
                    return;
                }
            }
        }

        // 2. Poll the stack + service connections. smoltcp's tap phy panics on a
        // non-WouldBlock send error; catch it so a transient tap I/O error can't
        // tear down the whole WAN stack (the borrow guards release on unwind, so
        // the next iteration retries cleanly).
        let now = smol_now(base);
        let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = iface.poll(now, &mut device, &mut sockets);
            service_conns(&mut sockets, &mut conns);
            service_raws(&mut sockets, &mut raws);
        }));
        if poll.is_err() {
            warn!("WAN poll iteration panicked (tap I/O?); continuing");
        }

        // 3. Inject any host-supplied L2 frames straight to the tap fd (writing a
        // frame to the tap injects it as ingress / guest RX). Single-threaded, so
        // this never races smoltcp's own writes to the same fd.
        if let Some(rx) = l2_inject.as_mut() {
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(frame) => {
                        if let Err(e) = write_frame_to_fd(fd, &frame) {
                            debug!("L2 inject write failed ({} bytes): {e}", frame.len());
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                l2_inject = None;
                device.rx_tap = None;
                info!("L2 bridge session closed");
            }
        }

        // 4. Sleep until the next deadline (bounded so channels stay responsive).
        let wait = match iface.poll_delay(now, &sockets) {
            Some(d) if d < MAX_WAIT => d,
            _ => MAX_WAIT,
        };
        let _ = phy_wait(fd, Some(wait));
    }
}

fn open_connection(
    iface: &mut Interface,
    sockets: &mut SocketSet,
    conns: &mut HashMap<SocketHandle, Conn>,
    cfg: &WanConfig,
    next_port: &mut u16,
    port: u16,
    resp: oneshot::Sender<Result<WanConn, ConnError>>,
) {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);

    let local_port = *next_port;
    *next_port = next_port.checked_add(1).unwrap_or(49152);
    if *next_port < 49152 {
        *next_port = 49152;
    }

    let remote = (IpAddress::Ipv4(cfg.guest_ip), port);
    if let Err(e) = socket.connect(iface.context(), remote, local_port) {
        let _ = resp.send(Err(ConnError::Io(format!("connect: {e:?}"))));
        return;
    }
    let handle = sockets.add(socket);

    let (to_tx, to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_tx, from_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    conns.insert(
        handle,
        Conn {
            started: StdInstant::now(),
            established: false,
            resp: Some(resp),
            payload: Some(WanConn {
                to_wan: to_tx,
                from_wan: from_rx,
            }),
            rx_to_wan: to_rx,
            tx_from_wan: from_tx,
            pending: Vec::new(),
            pending_off: 0,
            closing: false,
        },
    );
    debug!(port, local_port, "WAN connect armed");
}

fn service_conns(sockets: &mut SocketSet, conns: &mut HashMap<SocketHandle, Conn>) {
    let mut to_remove: Vec<SocketHandle> = Vec::new();

    for (handle, conn) in conns.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);

        // Establishment / failure detection.
        if !conn.established {
            if socket.may_send() {
                conn.established = true;
                if let (Some(resp), Some(payload)) = (conn.resp.take(), conn.payload.take()) {
                    let _ = resp.send(Ok(payload));
                }
            } else if socket.state() == tcp::State::Closed {
                if let Some(resp) = conn.resp.take() {
                    let _ = resp.send(Err(ConnError::Refused));
                }
                to_remove.push(*handle);
                continue;
            } else if conn.started.elapsed() > CONNECT_TIMEOUT {
                if let Some(resp) = conn.resp.take() {
                    let _ = resp.send(Err(ConnError::Filtered));
                }
                socket.close();
                to_remove.push(*handle);
                continue;
            } else {
                continue; // still handshaking
            }
        }

        // Host → WAN: pull from the channel into the pending buffer, then push
        // as much as the socket tx buffer accepts.
        loop {
            match conn.rx_to_wan.try_recv() {
                Ok(data) => conn.pending.extend_from_slice(&data),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    conn.closing = true;
                    break;
                }
            }
        }
        while socket.can_send() && conn.pending_off < conn.pending.len() {
            match socket.send_slice(&conn.pending[conn.pending_off..]) {
                Ok(0) => break,
                Ok(n) => conn.pending_off += n,
                Err(_) => {
                    to_remove.push(*handle);
                    break;
                }
            }
        }
        if conn.pending_off > 0 && conn.pending_off == conn.pending.len() {
            conn.pending.clear();
            conn.pending_off = 0;
        }
        if conn.closing && conn.pending_off >= conn.pending.len() {
            socket.close();
        }

        // WAN → host.
        while socket.can_recv() {
            match socket.recv(|buf| {
                let v = buf.to_vec();
                (v.len(), v)
            }) {
                Ok(v) => {
                    if conn.tx_from_wan.send(v).is_err() {
                        socket.close();
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if conn.established && socket.state() == tcp::State::Closed {
            to_remove.push(*handle);
        }
    }

    for h in to_remove {
        conns.remove(&h);
        sockets.remove(h);
    }
}

/// Buffered metadata slots / payload bytes for a raw socket.
const RAW_META: usize = 32;
const RAW_BUF: usize = 64 * 1024;

fn open_raw(
    sockets: &mut SocketSet,
    raws: &mut HashMap<SocketHandle, RawState>,
    proto: u8,
    resp: oneshot::Sender<Result<RawConn, ConnError>>,
) {
    let rx_buf = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; RAW_META],
        vec![0u8; RAW_BUF],
    );
    let tx_buf = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; RAW_META],
        vec![0u8; RAW_BUF],
    );
    let socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::from(proto), rx_buf, tx_buf);
    let handle = sockets.add(socket);

    let (to_tx, to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_tx, from_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    raws.insert(
        handle,
        RawState {
            rx_to_stack: to_rx,
            tx_from_stack: from_tx,
        },
    );
    debug!(proto, "raw L3 socket opened");
    let _ = resp.send(Ok(RawConn {
        to_stack: to_tx,
        from_stack: from_rx,
    }));
}

fn service_raws(sockets: &mut SocketSet, raws: &mut HashMap<SocketHandle, RawState>) {
    let mut to_remove: Vec<SocketHandle> = Vec::new();

    for (handle, st) in raws.iter_mut() {
        let socket = sockets.get_mut::<raw::Socket>(*handle);

        // Host → stack: emit each supplied IP packet (smoltcp frames L2 + ARPs).
        loop {
            match st.rx_to_stack.try_recv() {
                Ok(pkt) => {
                    if let Err(e) = socket.send_slice(&pkt) {
                        debug!("raw send dropped {} bytes: {e}", pkt.len());
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    to_remove.push(*handle);
                    break;
                }
            }
        }

        // Stack → host: forward each received IP packet.
        while socket.can_recv() {
            match socket.recv() {
                Ok(pkt) => {
                    let v = pkt.to_vec();
                    if st.tx_from_stack.send(v).is_err() {
                        to_remove.push(*handle);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    for h in to_remove {
        raws.remove(&h);
        sockets.remove(h);
    }
}

fn smol_now(base: StdInstant) -> SmolInstant {
    SmolInstant::from_micros(base.elapsed().as_micros() as i64)
}

/// TUNSETIFF ioctl request number (`_IOW('T', 202, int)`). MIPS/PowerPC/SPARC
/// use a different `_IOC` direction encoding (`0x8…` vs `0x4…`); this mirrors
/// smoltcp's per-arch table so the tap opens on every guest arch. The endianness
/// variants collapse (the number is byte-order independent), but they are listed
/// to match upstream exactly.
const TUNSETIFF: libc::c_ulong = if cfg!(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc64",
)) {
    0x8004_54CA
} else {
    0x4004_54CA
};

/// MTU of the tap-backed ethernet segment (standard 1500-byte IP payload). Kept
/// explicit because we build the interface via `from_fd`, which (unlike `new`)
/// does not query `SIOCGIFMTU`.
const TAP_MTU: usize = 1500;

/// The two `ifr_flags` bytes for a no-packet-info TAP (`IFF_TAP | IFF_NO_PI`),
/// laid out as the kernel's native 16-bit `short`.
///
/// This is the crux of the big-endian fix: the field is a `short`, so it must be
/// written as exactly two bytes in native order. smoltcp instead wrote a 32-bit
/// `c_int`, whose significant bits sit in the high half on big-endian, making the
/// kernel read `flags == 0` and reject TUNSETIFF with EINVAL.
fn tap_ifr_flags() -> [u8; 2] {
    const IFF_TAP: u16 = 0x0002;
    const IFF_NO_PI: u16 = 0x1000;
    (IFF_TAP | IFF_NO_PI).to_ne_bytes()
}

/// Build the 40-byte `ifreq` for TUNSETIFF: interface name, then the 16-bit
/// `ifr_flags` short at offset `IFNAMSIZ` (16).
fn build_tap_ifreq(iface: &str) -> [u8; 40] {
    let mut ifr = [0u8; 40];
    ifr[..iface.len()].copy_from_slice(iface.as_bytes());
    let flags = tap_ifr_flags();
    ifr[16] = flags[0];
    ifr[17] = flags[1];
    ifr
}

/// Open `/dev/net/tun` and attach a no-PI TAP named `iface`, returning the raw
/// fd for smoltcp's `TunTapInterface::from_fd` (which closes it on drop). See the
/// call site in `run_stack` for why we bypass `TunTapInterface::new`.
fn open_tap_fd(iface: &str) -> std::io::Result<std::os::fd::RawFd> {
    if iface.len() >= 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: standard /dev/net/tun open + TUNSETIFF on a 40-byte ifreq.
    unsafe {
        let fd = libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NONBLOCK,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr = build_tap_ifreq(iface);
        if libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr() as *mut libc::c_void) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

/// Assign an IPv4 address + netmask to `iface` via ioctl (SIOCSIFADDR /
/// SIOCSIFNETMASK). ifreq: 16-byte name, then a `sockaddr_in` (family u16 at
/// offset 16, addr bytes at offset 20).
fn set_ip_addr(iface: &str, ip: Ipv4Addr, prefix: u8) -> std::io::Result<()> {
    use libc::{c_void, close, ioctl, socket, AF_INET, SOCK_DGRAM};
    const SIOCSIFADDR: libc::c_ulong = 0x8916;
    const SIOCSIFNETMASK: libc::c_ulong = 0x891c;

    if iface.len() >= 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };

    // Build an ifreq with `addr` (4 bytes) at offset 20 and AF_INET at offset 16.
    let mk_ifreq = |addr: [u8; 4]| -> [u8; 40] {
        let mut ifr = [0u8; 40];
        ifr[..iface.len()].copy_from_slice(iface.as_bytes());
        let fam = (AF_INET as u16).to_ne_bytes();
        ifr[16] = fam[0];
        ifr[17] = fam[1];
        ifr[20..24].copy_from_slice(&addr);
        ifr
    };

    // SAFETY: standard SIOCSIF* ioctls on an AF_INET socket with a 40-byte ifreq.
    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let do_ioctl = |req: libc::c_ulong, addr: [u8; 4]| -> std::io::Result<()> {
            let mut ifr = mk_ifreq(addr);
            if ioctl(fd, req as _, ifr.as_mut_ptr() as *mut c_void) < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        let r = do_ioctl(SIOCSIFADDR, ip.octets())
            .and_then(|()| do_ioctl(SIOCSIFNETMASK, mask.to_be_bytes()));
        close(fd);
        r?;
    }
    info!(iface, ip = %ip, prefix, "assigned IP to interface");
    Ok(())
}

/// Write one Ethernet frame directly to the tap fd, injecting it as ingress.
fn write_frame_to_fd(fd: std::os::fd::RawFd, frame: &[u8]) -> std::io::Result<()> {
    // SAFETY: fd is the tap's valid fd for the life of the stack thread.
    let n = unsafe {
        libc::write(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Bring an interface administratively UP (IFF_UP|IFF_RUNNING) via ioctl, so the
/// tap has carrier and accepts injected frames. ifreq layout: 16-byte name then
/// the flags union (ifr_flags is a c_short at offset 16).
fn set_link_up(iface: &str) -> std::io::Result<()> {
    use libc::{
        c_void, close, ioctl, socket, AF_INET, IFF_RUNNING, IFF_UP, SIOCGIFFLAGS, SIOCSIFFLAGS,
        SOCK_DGRAM,
    };
    let name = iface.as_bytes();
    if name.len() >= 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: ifreq is a 40-byte struct; we fill the name and the flags short.
    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr = [0u8; 40];
        ifr[..name.len()].copy_from_slice(name);
        let r = |req, buf: *mut u8| ioctl(fd, req as _, buf as *mut c_void);
        if r(SIOCGIFFLAGS, ifr.as_mut_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            close(fd);
            return Err(e);
        }
        let mut flags = i16::from_ne_bytes([ifr[16], ifr[17]]) as i32;
        flags |= IFF_UP | IFF_RUNNING;
        let fb = (flags as i16).to_ne_bytes();
        ifr[16] = fb[0];
        ifr[17] = fb[1];
        if r(SIOCSIFFLAGS, ifr.as_mut_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            close(fd);
            return Err(e);
        }
        close(fd);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression guard for the big-endian TUNSETIFF bug. The kernel reads
    // `ifr_flags` as a native 16-bit `short` at offset 16 of the ifreq; our two
    // flag bytes must decode back to `IFF_TAP | IFF_NO_PI` there. (The bug was
    // smoltcp writing a 32-bit int, whose low half is zero in the kernel's short
    // on big-endian -> EINVAL. The definitive coverage is the owned_iface CI test
    // on the big-endian arches; this locks the byte layout regardless of host.)
    #[test]
    fn tap_ifr_flags_land_in_the_kernel_short() {
        let ifr = build_tap_ifreq("wan0");
        assert_eq!(&ifr[..4], b"wan0");
        // Native short at offset 16 == IFF_TAP | IFF_NO_PI.
        assert_eq!(i16::from_ne_bytes([ifr[16], ifr[17]]), 0x1002);
        // The flags occupy exactly the 16-bit field; the rest of the union stays
        // zero (a 32-bit write would spill into offset 18/19 on little-endian and,
        // worse, leave offset 16 zero on big-endian).
        assert_eq!(&ifr[18..24], &[0u8; 6]);
        assert_eq!(tap_ifr_flags().len(), 2);
    }

    #[test]
    fn tunsetiff_matches_target_arch_encoding() {
        let expected: libc::c_ulong = if cfg!(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc64",
        )) {
            0x8004_54CA
        } else {
            0x4004_54CA
        };
        assert_eq!(TUNSETIFF, expected);
    }
}
