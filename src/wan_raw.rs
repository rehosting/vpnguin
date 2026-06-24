//! Raw L3 probe (host side).
//!
//! Opens a raw-IP channel on an owned interface (the guest's smoltcp `socket-raw`
//! path) and sends ICMP echo requests — or a user-supplied hex packet — to the
//! firmware's WAN IP. This proves a *non-TCP* protocol traverses the firmware's
//! `INPUT -i <iface>` chain: a reply means it was allowed and answered; a silent
//! timeout means it was dropped (or nothing responded). Swap `--proto`/`--packet`
//! to exercise ESP/GRE/AH against the device's VPN-server surface.

use std::net::Ipv4Addr;

use crate::host::connect_to_socket;
use crate::{write_event, HostRequest, Raw};
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

/// Execute the raw probe.
pub async fn execute(command: &Raw) -> Result<()> {
    let mut vsock = connect_to_socket(
        command.vhost_user_path.clone(),
        command.command_port + 1,
        command.context_id,
    )
    .await
    .context("unable to connect to raw-L3 vsock port")?;

    let req = HostRequest::RawL3 {
        iface: command.iface.clone(),
        proto: command.proto,
    };
    write_event(&mut vsock, &req)
        .await
        .context("unable to send RawL3 header")?;

    let packets: Vec<Vec<u8>> = match &command.packet {
        Some(hex) => vec![decode_hex(hex)?],
        None => (0..command.count)
            .map(|seq| build_icmp_echo(command.src_ip, command.dst_ip, 0x1234, seq as u16))
            .collect(),
    };

    println!(
        "Raw L3 on {} (proto {}): {} -> {}",
        command.iface, command.proto, command.src_ip, command.dst_ip
    );
    for (i, pkt) in packets.iter().enumerate() {
        vsock
            .write_u16(pkt.len() as u16)
            .await
            .context("unable to write packet length")?;
        vsock
            .write_all(pkt)
            .await
            .context("unable to write packet")?;
        println!("  -> sent #{i} ({} bytes)", pkt.len());
    }

    let deadline = Duration::from_secs(command.timeout);
    let mut replies = 0u32;
    loop {
        match timeout(deadline, read_frame(&mut vsock)).await {
            Ok(Ok(Some(pkt))) => {
                replies += 1;
                println!("  <- {}", describe(&pkt));
            }
            Ok(Ok(None)) => break, // channel closed
            Ok(Err(e)) => {
                eprintln!("read error: {e}");
                break;
            }
            Err(_) => break, // timeout: no (more) replies
        }
    }

    if replies == 0 {
        println!("No replies within {}s — filtered (dropped) or no responder.", command.timeout);
    } else {
        println!("{replies} reply/replies received — the protocol traversed and was answered.");
    }
    Ok(())
}

/// Read one length-delimited frame (`u16 len || bytes`). `None` on clean EOF.
async fn read_frame(
    vsock: &mut Box<dyn crate::host::AsyncReadWrite + Unpin>,
) -> Result<Option<Vec<u8>>> {
    let n = match vsock.read_u16().await {
        Ok(n) => n as usize,
        Err(_) => return Ok(None),
    };
    let mut buf = vec![0u8; n];
    vsock
        .read_exact(&mut buf)
        .await
        .context("unable to read reply body")?;
    Ok(Some(buf))
}

/// Build an IPv4 + ICMP echo-request packet with valid checksums.
fn build_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let payload = b"penguin-wan-probe";

    // ICMP echo request.
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // type: echo request
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    // IPv4 header.
    let total_len = (20 + icmp.len()) as u16;
    let mut ip = Vec::with_capacity(total_len as usize);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF, fragment offset 0
    ip.push(64); // TTL
    ip.push(1); // protocol: ICMP
    ip.extend_from_slice(&[0, 0]); // header checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let hc = checksum(&ip);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());

    ip.extend_from_slice(&icmp);
    ip
}

/// One's-complement Internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Decode a hex string (optionally with spaces/colons) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if clean.len() % 2 != 0 {
        return Err(anyhow!("hex packet has an odd number of digits"));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {i}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_basic_and_separators() {
        assert_eq!(decode_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_hex("de:ad be ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(decode_hex("abc").is_err()); // odd length
        assert!(decode_hex("zz").is_err()); // non-hex
    }

    #[test]
    fn checksum_zeroes_out() {
        // The Internet checksum of a buffer that already contains its own
        // checksum must be zero (the standard verification property).
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"payload!");
        let c = checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&icmp), 0);
    }

    #[test]
    fn icmp_echo_is_wellformed() {
        let p = build_icmp_echo(Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2), 0x1234, 0);
        assert_eq!(p[0] >> 4, 4); // IPv4
        assert_eq!(p[9], 1); // protocol ICMP
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        assert_eq!(p[ihl], 8); // ICMP echo request
        assert_eq!(checksum(&p[..ihl]), 0); // valid IP header checksum
        assert_eq!(checksum(&p[ihl..]), 0); // valid ICMP checksum
    }
}

/// Human summary of a received IPv4 packet.
fn describe(pkt: &[u8]) -> String {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return format!("{} bytes (non-IPv4)", pkt.len());
    }
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let extra = if proto == 1 && pkt.len() > ihl {
        match pkt[ihl] {
            0 => " ICMP echo-reply".to_string(),
            3 => " ICMP dest-unreachable".to_string(),
            11 => " ICMP time-exceeded".to_string(),
            t => format!(" ICMP type {t}"),
        }
    } else {
        String::new()
    };
    format!("{} bytes proto {proto} {src} -> {dst}{extra}", pkt.len())
}
