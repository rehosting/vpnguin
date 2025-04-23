use crate::Transport;

use std::{
    net::{SocketAddr, IpAddr},
    sync::Arc,
    path::PathBuf,
    time::SystemTime,
    fs::File,
};

use tokio::sync::mpsc;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, TcpHeader, UdpHeader, Ethernet2Header, EtherType};

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
    last_payload_len: usize,
    seen_syn: bool,
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
            let internal_to_peer_seq = {
                let mut internal_to_peer = tcp_map
                    .entry(TcpFlow {
                        source: internal_address,
                        dest: peer_address,
                    })
                    .or_insert_with(TcpState::default);
                let seq = internal_to_peer.next_seq;
                internal_to_peer.next_seq += 1;
                seq
            };

            let peer_to_internal_seq = {
                let mut peer_to_internal = tcp_map
                    .entry(TcpFlow {
                        source: peer_address,
                        dest: internal_address,
                    })
                    .or_insert_with(TcpState::default);
                let seq = peer_to_internal.next_seq;
                peer_to_internal.next_seq += 1;
                seq
            };

            // SYN (internal -> peer)
            self.log_packet(
                &[],
                Transport::Tcp,
                internal_address,
                peer_address,
                Some((internal_to_peer_seq, 0, true, false)), // SYN flag
            ).await;

            // SYN+ACK (peer -> internal)
            self.log_packet(
                &[],
                Transport::Tcp,
                peer_address,
                internal_address,
                Some((peer_to_internal_seq, internal_to_peer_seq + 1, true, true)), // SYN and ACK flags
            ).await;

            // ACK (internal -> peer)
            self.log_packet(
                &[],
                Transport::Tcp,
                internal_address,
                peer_address,
                Some((internal_to_peer_seq + 1, peer_to_internal_seq + 1, false, true)), // ACK flag
            ).await;
        }
    }

    pub async fn close_tcp_stream(&self, peer_address: SocketAddr, internal_address: SocketAddr) {
        if let Some(tcp_map) = &self.tcp_flows {
            // Get the TCP states for both directions
            let internal_to_peer = tcp_map.get(&TcpFlow {
                source: internal_address,
                dest: peer_address,
            });
            let peer_to_internal = tcp_map.get(&TcpFlow {
                source: peer_address,
                dest: internal_address,
            });

            if let (Some(internal_to_peer), Some(peer_to_internal)) = (internal_to_peer, peer_to_internal) {

                let internal_to_peer_seq  = internal_to_peer.next_seq + 1;
                let internal_to_peer_next_ack =  internal_to_peer.next_ack;
                let peer_to_internal_seq= peer_to_internal.next_seq + 1;

                // FIN (internal -> peer)
                self.log_packet(
                    &[],
                    Transport::Tcp,
                    internal_address,
                    peer_address,
                    Some((internal_to_peer_seq, internal_to_peer_next_ack, true, false)),
                ).await;

                // FIN+ACK (peer -> internal)
                self.log_packet(
                    &[],
                    Transport::Tcp,
                    peer_address,
                    internal_address,
                    Some((peer_to_internal_seq, internal_to_peer_seq + 1, true, true)),
                ).await;

                // ACK (internal -> peer)
                self.log_packet(
                    &[],
                    Transport::Tcp,
                    internal_address,
                    peer_address,
                    Some((internal_to_peer_seq + 1, peer_to_internal_seq + 1, false, true)),
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
    }

    pub async fn log_packet(
        &self,
        payload: &[u8],
        proto: Transport,
        src: SocketAddr,
        dest: SocketAddr,
        tcp_flags: Option<(u32, u32, bool, bool)>,
    ) {
        let (transport_len, ip_number): (u16, IpNumber) = match proto {
            Transport::Tcp => {
                ((20 + payload.len()).try_into().unwrap(), IpNumber::TCP)
            }
            Transport::Udp => {
                ((8 + payload.len()).try_into().unwrap(), IpNumber::UDP)
            }
        };

        let mut buf: Vec<u8> = Vec::new();

        // TODO: grab MACs from Host and Guest
        let eth = Ethernet2Header {
            source: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            destination: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: match (src.ip(), dest.ip()) {
                (IpAddr::V4(_), IpAddr::V4(_)) => EtherType::IPV4,
                (IpAddr::V6(_), IpAddr::V6(_)) => EtherType::IPV6,
                _ => {
                    error!("Unable to parse packet from {} to {}", src, dest);
                    return;
                }
            },
        };
        eth.write(&mut buf).unwrap();

        let mut ip_header = Vec::with_capacity(60);
        match (src.ip(), dest.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => {
                let bytes = Ipv4Header::new(
                    transport_len,
                    64,
                    ip_number,
                    src_ip.octets(),
                    dest_ip.octets(),
                )
                .unwrap()
                .to_bytes();
                ip_header.extend_from_slice(&bytes);
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => {
                let bytes = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: transport_len,
                    next_header: ip_number,
                    hop_limit: 64,
                    source: src_ip.octets(),
                    destination: dest_ip.octets(),
                }
                .to_bytes();
                ip_header.extend_from_slice(&bytes);
            }
            _ => {
                error!("Unable to parse packet from {} to {}", src, dest);
                return;
            }
        };
        buf.extend_from_slice(&ip_header);

        match proto {
            Transport::Tcp => {
                let (mut seq , ack, syn, ack_flag) = tcp_flags.unwrap_or((0, 0, false, false));
                if let Some(tcp_map) = &self.tcp_flows {
                    if let Some(mut state) = tcp_map.get_mut(&TcpFlow { source: src, dest }) {
                        if seq == 0 { seq = state.next_seq; } // Not rusty, sorry
                        state.next_seq += payload.len() as u32;
                    }
                }

                let mut tcp_header = TcpHeader::new(src.port(), dest.port(), seq, 0);
                tcp_header.acknowledgment_number = ack;
                tcp_header.syn = syn;
                tcp_header.ack = ack_flag;
                let checksum = match src.ip() {
                    IpAddr::V4(_) => tcp_header.calc_checksum_ipv4(&Ipv4Header::from_slice(&ip_header).unwrap().0, payload),
                    IpAddr::V6(_) => tcp_header.calc_checksum_ipv6(&Ipv6Header::from_slice(&ip_header).unwrap().0, payload)
                }.unwrap();
                tcp_header.checksum = checksum;
                buf.extend_from_slice(&tcp_header.to_bytes());
            }
            Transport::Udp => {
                let udp_header = match src.ip() {
                    IpAddr::V4(_) => UdpHeader::with_ipv4_checksum(
                        src.port(),
                        dest.port(),
                        &Ipv4Header::from_slice(&ip_header).unwrap().0,
                        payload,
                    ),
                    IpAddr::V6(_) => UdpHeader::with_ipv6_checksum(
                        src.port(),
                        dest.port(),
                        &Ipv6Header::from_slice(&ip_header).unwrap().0,
                        payload,
                    ),
                };
                buf.extend_from_slice(&udp_header.unwrap().to_bytes());
            }
        }
        buf.extend_from_slice(payload);

        self.log(&buf).await;
    }
}
