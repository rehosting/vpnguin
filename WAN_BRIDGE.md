# Owned-interface datapaths (WAN bridge)

## Problem

The default vpnguin service exposure proxies a forwarded connection by
`connect()`ing to `127.0.0.1:<port>` inside the guest. Locally-generated traffic
is delivered over `lo`, so the guest's netfilter `INPUT -i <iface>` rules never
match — the firewall is bypassed. That makes it impossible to validate, end to
end, that a guest's firewall actually blocks (or allows) traffic arriving on a
given interface (e.g. a WAN/uplink), or to reach a service the way an external
peer on that interface would.

It is also TCP-only: the socket-proxy can't carry ICMP or other IP protocols, so
the firewall can't be exercised against non-TCP services.

## Mechanism

Writing a frame to a **TAP** injects it as ingress (RX) on that interface. So if
the agent *owns* the interface as a tap, traffic it originates genuinely arrives
on that interface and traverses `INPUT -i <iface>`.

```
host tool ── vsock ── vpnguin (smoltcp / tee) ── tap/<iface> ── [netfilter INPUT -i <iface>] ── service
```

The agent runs a userspace TCP/IP stack (smoltcp) as the peer on that L2 segment.
The guest kernel owns one address on the segment; smoltcp owns another, so to the
firewall this is a genuine remote peer (ARP, rp_filter, anti-spoof all behave as
against a real external host).

## What it provides

The guest agent can own **N named interfaces**, each a tap-backed stack, declared
in config. With none declared, behaviour is unchanged (the default loopback
path). Each owned interface offers three datapaths, on distinct vsock ports:

1. **TCP forward** (control port) — a `Forward` request with `iface: Some(name)`
   originates a TCP connection on that interface. The agent returns a status byte
   (`open` / `filtered` / `refused`) reflecting how the firewall treated it, then
   bridges the stream. Routed per-service via the interface matrix (below).
2. **Raw L3** (control port + 1) — `RawL3{iface, proto}` then a length-delimited
   stream of whole IP packets (smoltcp `socket-raw`). Lets the host drive any IP
   protocol (ICMP, ESP, GRE, AH, …) through the firewall; smoltcp handles
   Ethernet framing + ARP.
3. **Raw L2** (control port + 2) — `RawL2{iface}` then a length-delimited stream
   of whole Ethernet frames. The agent tees frames the guest emits up to the host
   and injects host frames into the tap. Point a real host stack (a host TAP via
   `raw-attach`, scapy, nmap, a VPN client) at the guest interface.

For turnkey use the agent assigns the configured guest IP to the tap on startup
(many firmwares don't bring an uplink up under emulation), so connections to it
reach a listener without manual setup.

## Configuration (penguin)

```yaml
plugins:
  vpn:
    interfaces:
      <iface>:                 # becomes a tap-backed stack the agent owns
        host_ip: 198.51.100.1  # smoltcp's address on the segment
        guest_ip: 198.51.100.2 # the guest's address on the segment
        prefix: 24
    default_interface: <iface> # route unmatched binds here (else loopback)
    routes:                    # the interface matrix, keyed like `spoof`
      "tcp:<guest_ip>:<port>": <iface>
```

`routes` is the parallel of the existing `spoof` (origin-IP) matrix: same key
space (`<proto>:<guest_ip>:<port>`), but it selects the **ingress interface**
while `spoof` selects the source IP — the two compose independently. The vpn
plugin emits the owned-interface set as `IGLOO_OWN_IFACES`, which the guest init
turns into `--own-iface` flags. With no `interfaces` declared, nothing changes.

## CLI (vpnguin)

- `guest --own-iface NAME:HOST_IP/GUEST_IP/PREFIX` (repeatable) — own interfaces.
- `wan-probe -u <sock> --iface NAME --ports 80,443,…` — report open/filtered/
  refused per port, through the firewall.
- `raw -u <sock> --iface NAME --proto <n> [--packet <hex>]` — send ICMP (or any
  IP protocol / a raw packet) and print replies.
- `raw-attach -u <sock> --iface NAME --tap <hosttap>` — create a host TAP bridged
  to the guest interface; configure it and run any host tooling against it.

## Implementation

- `src/wan.rs` — per-interface `WanStack`: owns a tap + smoltcp `Interface` on a
  dedicated thread; TCP connect, raw (`socket-raw`) channel, and an L2 tee
  (`TeeDevice`) + frame injector; brings the link up and assigns the guest IP.
- `src/guest.rs` — builds the `HashMap<name, WanStack>`; binds the control / raw
  L3 / raw L2 vsock ports and bridges each to its stack.
- `src/main.rs` — CLI + the `Forward{…, iface}` / `RawL3` / `RawL2` protocol.
- `src/wan_probe.rs`, `src/wan_raw.rs`, `src/wan_l2.rs` — host-side drivers.

`Dockerfile.wan-minimal` builds a 2-arch (one guest + host) `vpn.tar.gz` for fast
iteration; the normal multi-arch build is unchanged.
