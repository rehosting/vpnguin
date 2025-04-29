use crate::{Transport, PacketDirection, PacketDirection::{HostToGuest, GuestToHost}};

use std::{
    net::{SocketAddr, IpAddr},
    sync::Arc,
    path::PathBuf,
    time::SystemTime,
    fs::File,
};

use tokio::sync::mpsc;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use etherparse::PacketBuilder;

// Since TCP is stateful, we need to track this stuff
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct TcpFlow {
    source: SocketAddr,
    dest: SocketAddr,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug, Default)]
struct TcpState {
    next_seq: u32,
    next_ack: u32,
}

// Decided to make this a struct so things are more readable
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
}

use dashmap::DashMap;

type TcpFlowMap = DashMap<TcpFlow, TcpState>;

#[derive(Clone)]
pub struct PcapLogger {
    tx: Option<Arc<mpsc::Sender<(SystemTime, Arc<[u8]>)>>>,
    tcp_flows: Option<Arc<TcpFlowMap>>,
}

impl PcapLogger {
    pub fn new(pcap_path: &Option<PathBuf>) -> Self {
        if let Some(path) = pcap_path.clone() {
            let (tx, mut rx): (mpsc::Sender<(SystemTime, Arc<[u8]>)>, mpsc::Receiver<(SystemTime, Arc<[u8]>)>) = mpsc::channel(1000);
            tokio::spawn(async move {
                let file = File::create(path).unwrap();
                let header = PcapHeader::default();
                let mut writer = PcapWriter::with_header(file, header).unwrap();

                while let Some((ts, data)) = rx.recv().await {
                    let dur = ts.duration_since(std::time::UNIX_EPOCH).unwrap();
                    let pkt = PcapPacket::new(dur, data.len().try_into().unwrap(), &data);
                    writer.write_packet(&pkt).unwrap();
                }
            });
            Self { tx: Some(Arc::new(tx)), tcp_flows: Some(Arc::new(TcpFlowMap::new())) }
        } else {
            Self { tx: None, tcp_flows: None }
        }
    }

    // For raw packets, but we'll probably use log_packet to build up ip and tcp/udp headers
    pub async fn log(&self, data: &[u8]) {
        if let Some(tx) = &self.tx {
            let _ = tx
                .send((SystemTime::now(), Arc::from(data.to_vec().into_boxed_slice())))
                .await;
        }
    }

    // Since TCP is stateful, we'll fake out sequence numbers as well as SYN stuff
    pub async fn init_tcp_stream(&self, peer_address: SocketAddr, internal_address: SocketAddr) {
        if let Some(tcp_map) = &self.tcp_flows {
            // Ensure both directions are initialized
            tcp_map.entry(TcpFlow {
                source: internal_address,
                dest: peer_address,
            })
            .or_insert_with(TcpState::default);

            tcp_map.entry(TcpFlow {
                source: peer_address,
                dest: internal_address,
            })
            .or_insert_with(TcpState::default);

            // SYN (peer -> internal)
            self.log_packet(
                &[],
                Transport::Tcp,
                peer_address,
                internal_address,
                Some(TcpFlags{syn: true, ack: false, fin: false}),
                HostToGuest,
            ).await;

            // SYN+ACK (internal -> peer)
            self.log_packet(
                &[],
                Transport::Tcp,
                internal_address,
                peer_address,
                Some(TcpFlags{syn: true, ack: true, fin: false}),
                GuestToHost,
            ).await;

            // ACK (peer -> internal)
            self.log_packet(
                &[],
                Transport::Tcp,
                peer_address,
                internal_address,
                Some(TcpFlags{syn: false, ack: true, fin: false}),
                HostToGuest,
            ).await;
        }
    }

    pub async fn close_tcp_stream(&self, peer_address: SocketAddr, internal_address: SocketAddr) {
        // WARNING: this code is untested, we don't really tear down connections in vpnguin
        if let Some(tcp_map) = &self.tcp_flows {
            // FIN (peer -> internal)
            self.log_packet(
                &[],
                Transport::Tcp,
                peer_address,
                internal_address,
                Some(TcpFlags{syn: false, ack: false, fin: true}),
                HostToGuest,
            ).await;

            // FIN+ACK (internal -> peer)
            self.log_packet(
                &[],
                Transport::Tcp,
                internal_address,
                peer_address,
                Some(TcpFlags{syn: false, ack: true, fin: true}),
                GuestToHost,
            ).await;

            // ACK (peer -> internal)
            self.log_packet(
                &[],
                Transport::Tcp,
                peer_address,
                internal_address,
                Some(TcpFlags{syn: false, ack: true, fin: false}),
                HostToGuest,
            ).await;

            // Clean up the map
            tcp_map.remove(&TcpFlow {
                source: internal_address,
                dest: peer_address,
            });
            tcp_map.remove(&TcpFlow {
                source: peer_address,
                dest: internal_address,
            });
        }
    }

    /// This logs a packet. It fakes out the various headers and then passes the packet to a background writer task that handles the writing to disk
    pub async fn log_packet(
        &self,
        payload: &[u8],
        proto: Transport,
        src: SocketAddr,
        dest: SocketAddr,
        flags: Option<TcpFlags>,
        direction: PacketDirection,
    ) {
        let mut buf: Vec<u8> = Vec::new();

        // Always use static MAC addresses to help make host/guest identifiable
        let host_mac = [0x48, 0x4F, 0x53, 0x54, 0x00, 0x00]; // "HOST"
        let guest_mac = [0x47, 0x55, 0x45, 0x53, 0x54, 0x00]; // "GUEST"

        // Flip the MAC addresses based on the direction
        let (src_mac, dest_mac) = match direction {
            HostToGuest => (host_mac, guest_mac),
            GuestToHost => (guest_mac, host_mac),
        };

        let builder = PacketBuilder::ethernet2( src_mac, dest_mac);

        let builder = match (src.ip(), dest.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => builder.ipv4(
                src_ip.octets(),
                dest_ip.octets(),
                64, // TTL
            ),
            (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => builder.ipv6(
                src_ip.octets(),
                dest_ip.octets(),
                64, // Hop limit
            ),
            _ => {
                error!("Source and destination IP versions do not match");
                return;
            }
        };

        match proto {
            Transport::Tcp => {
                let mut seq = 0;
                let mut ack = 0;

                if let Some(tcp_map) = &self.tcp_flows {
                    // Fetch and update the sequence number for the current flow
                    if let Some(mut state) = tcp_map.get_mut(&TcpFlow { source: src, dest }) {
                        seq = state.next_seq;
                        // If SYN or FIN, we need to add 1 (payload.len is 0)
                        state.next_seq += payload.len() as u32 + if flags.as_ref().map_or(false, |f| f.syn || f.fin) { 1 } else { 0 };
                    }

                    // Fetch and update the acknowledgment number for the opposite flow
                    if let Some(mut opposite_state) = tcp_map.get_mut(&TcpFlow { source: dest, dest: src }) {
                        ack = opposite_state.next_seq;
                        // next ACK updates only if there's date or SYN|FIN (i.e., no update on pure ACK from handshake)
                        if payload.len() > 0 || flags.as_ref().map_or(false, |f| f.syn || f.fin) {
                            opposite_state.next_ack = seq + payload.len() as u32 + if flags.as_ref().map_or(false, |f| f.syn || f.fin) { 1 } else { 0 };
                        }
                    }
                }

                let builder = builder
                    .tcp(src.port(), dest.port(), seq, 0)
                    .apply_if(flags.as_ref().map_or(false, |f| f.syn), |b| b.syn())
                    .apply_if(flags.as_ref().map_or(false, |f| f.ack), |b| b.ack(ack))
                    .apply_if(flags.as_ref().map_or(false, |f| f.fin), |b| b.fin());

                builder.write(&mut buf, payload).unwrap();
            }
            Transport::Udp => {
                let builder = builder.udp(src.port(), dest.port());
                builder.write(&mut buf, payload).unwrap();
            }
        }

        self.log(&buf).await;
    }
}

// This extension courtesy of copilot
trait PacketBuilderExt {
    fn apply_if<F>(self, condition: bool, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
        Self: Sized;
}

impl<T> PacketBuilderExt for T {
    fn apply_if<F>(self, condition: bool, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
        Self: Sized,
    {
        if condition {
            f(self)
        } else {
            self
        }
    }
}
