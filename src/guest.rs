//! Guest implementation.

use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

use crate::{read_event, Guest, HostRequest, Transport, HyperBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
    //task::yield_now,
};
use tokio_vsock::{SockAddr, VsockListener, VsockStream};
use anyhow::{anyhow, Context, Result};
use std::io::Cursor;
use std::mem;
use std::time::{SystemTime};

#[cfg(target_arch = "mips")]
use std::arch::asm;

// DEBUG
//use crate::HostRequest::Forward;
//use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


const GET_DATA : u32 = 6001;
const INPUT_FINISHED : u32 = 6002;

#[cfg(target_arch = "mips")]
fn hypercall(num: u32, a1: u32) {
    unsafe {
            asm!(
                "movz $0, {num}, {a1}",
                num = in(reg) num,
                a1 = in(reg) a1,
                )
    }
}

// For now x86 is a no-op. TODO: add arm
#[cfg(not(target_arch = "mips"))]
fn hypercall(_num: u32, _a1: u32) {
}


#[cfg(target_arch = "mips")]
fn page_in(buf: u32) {
    let contents : u32 = 0;
    unsafe {
            asm!(
                "lw {contents}, ({buf})", // Deref buf
                //"movz $0, {num}, {a1}",
                contents = in(reg) contents,
                buf = in(reg) buf,
                )
    }
}
#[cfg(not(target_arch = "mips"))]
fn page_in(_buf: u32) {
}

// Execute the guest endpoint in vsock mode
pub async fn execute_vsock(command: &Guest) -> Result<()> {
    // Set up a vsock listener
    info!(
        context = command.context_id,
        port = command.command_port,
        "listening for events"
    );
    let mut listener = VsockListener::bind(command.context_id, command.command_port)
        .context("unable to bind vsock listener")?;

    loop {
        let (vsock, peer_address) = listener
            .accept()
            .await
            .context("unable to accept vsock client")?;
        tokio::spawn(async move {
            if let Err(e) = process_client(vsock, peer_address).await {
                error!("unable to process client: {e:#?}");
            }
        });
    }
}

/// Process a vsock client
async fn process_client(mut vsock: VsockStream, peer_address: SockAddr) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    // Process the init event
    let e: Option<HostRequest> = read_event(&mut vsock)
        .await
        .context("unable to read init event")?;
    match e {
        Some(HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Tcp,
        }) => {
            let stream = TcpStream::connect(internal_address)
                .await
                .context("unable to connect to guest server")?;
            proxy_tcp(vsock, peer_address, stream).await?;
        }

        Some(HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Udp,
        }) => {
            proxy_udp(vsock, peer_address, internal_address).await?;
        }

        None => {
            return Err(anyhow!("unable to read init event (no event received)"));
        }
    };

    Ok(())
}

// Execute guest in hypercall mode
pub async fn execute_hypercall() -> Result<()> {
    let mut buffer : Vec<u8> = vec![0_u8; mem::size_of::<HyperBuf>()];
    //let buffer: Vec<u8> = Vec::with_capacity(mem::size_of::<HyperBuf>());


    /* For testing of encoding
    let foo = HyperBuf {
            command : 0xffffffff,
            target : Forward  {
                internal_address : SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0x8006),
                //internal_address : SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8081),
                transport : Transport::Tcp,
            },
            payload: [1; 1024],
        };
    let encoded: Vec<u8> = bincode::serialize(&foo).unwrap();
    println!("Encoded: ipv4 {:?}", encoded);
    */

    loop {
        // First hypercall: "Get data" with arg of buffer
        buffer[0] = 2;  // Initialize as "RETRY_PAGE_IN" if hypercall fails we should retry right away with page in
        let buffer_addr : u32 = buffer.as_ptr() as u32;

        hypercall(GET_DATA, buffer_addr);

        if buffer[0] == 0 {
            println!("[VPN] SLEEP 2s");
            sleep(Duration::from_millis(2000)).await;
            continue;
        } else if buffer[0] == 1 {
            println!("[VPN] RETRY");
            //yield_now().await;
            continue;
        } else if buffer[0] == 2 {
            page_in(buffer_addr);
            continue;

        } else if buffer[0] != 0xff {
            hypercall(INPUT_FINISHED, 2); // 2 indicates internal error
            error!("[VPN] Unexpected command in hypercall message: {:?}", buffer[0]);
        }
        let cur = Cursor::new(&buffer);
        match bincode::deserialize_from::<_, HyperBuf>(cur) {
            Ok(request) => {
                println!("[VPN] Sending data to target: {:?}", request.target);
                //println!("Request command: {:?}", request.command);
                //println!("Request data: {:?}", request.payload);

                tokio::spawn(async move {
                    if let Err(e) = process_buffer(request).await {
                        hypercall(INPUT_FINISHED, 1); // 1 indicates error connecting
                        // TODO: distinguish between connection reset (i.e., target didn't like the message) and other codes
                        // that might indicate that it failed to get the message? Or maybe these
                        // errors all should just indicate end of processing...?/Wait
                        error!("[VPN] Unable to process client: {e:#?}");
                    }
                });
            },
            Err(e) => {
                hypercall(INPUT_FINISHED, 2); // 2 indicates internal error
                println!("[VPN] Error deserializing data from hypercall {:?}", e);
            },
        }
    }
}

/// Execute the guest endpoint - vsock or hypercall
pub async fn execute(command: &Guest) -> Result<()> {

    if !command.hypercall {
        execute_vsock(command).await
    } else  {
        // Hypercall doesn't take an argument from us, it will
        // get the input data itself by running a hypercall
        execute_hypercall().await
    }
}

/// Process a vsock client.
async fn process_buffer(buffer: HyperBuf) -> Result<()> {
    // Process the init event
    match buffer.target {
        HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Tcp,
        } => {
            let stream = TcpStream::connect(internal_address)
                .await
                .context("unable to connect to guest server")?;
            forward_tcp(&buffer.payload, stream).await?;
        }

        HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Udp,
        } => {
            forward_udp(&buffer.payload, internal_address).await?;
        }

        //None => {
        //    return Err(anyhow!("unable to read init event (no event received)"));
        //}
    };

    Ok(())
}

/// Proxy TCP (hypercall)
async fn forward_tcp(
    data: &[u8],
    mut stream: TcpStream,
) -> Result<()> {

    // Send data on stream
    //let send_buf = String::from_utf8_lossy(&data);
    //println!("[VPN] {:?} Connecting to {:?} and sending request: {:?}", SystemTime::now(), stream, send_buf);
    stream.write(data).await?;

    // Just for debugging, let's try printing any response we get. First 100 bytes only
    // Read from the current data in the TcpStream
    //println!("[VPN] {:?} Wait for response (tcp)", SystemTime::now());
    let mut rx_bytes = [0u8; 100];
    //let n = stream.read(&mut rx_bytes).await.context("unable to read response")?;
    let rx = stream.read(&mut rx_bytes);

    match timeout(Duration::from_millis(999), rx).await {
        Err(t) => {
            println!("[VPN] {:?} Timeout - waited for {t}", SystemTime::now());
            hypercall(INPUT_FINISHED, 3);
        },
        Ok(n) => {
            let received = String::from_utf8_lossy(&rx_bytes);
            println!("[VPN]  {:?} Got {:?} byte response, ready to shutdown: {:?}", SystemTime::now(), n, received);
            hypercall(INPUT_FINISHED, 0);
        }
    };
    Ok(())
}

/// Proxy TCP (vsock)
async fn proxy_tcp(
    mut vsock: VsockStream,
    peer_address: SockAddr,
    mut stream: TcpStream,
) -> Result<()> {
    // Forward data
    debug!(peer = peer_address.to_string(), "forwarding data to host");
    tokio::io::copy_bidirectional(&mut vsock, &mut stream)
        .await
        .context("unable to forward data to host")?;
    debug!(
        peer = peer_address.to_string(),
        "terminated forwarding to host"
    );
    Ok(())
}


/// Proxy UDP (hypercall)
async fn forward_udp(
    data: &[u8],
    internal_address: SocketAddr,
) -> Result<()> {
    debug!(
        internal = internal_address.to_string(),
        "forwarding udp data to host"
    );

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("unable to bind udp socket")?;

    socket
        .send_to(&data, &internal_address)
        .await
        .context("unable to write client datagram")?;

    println!("[VPN] Wait for response (udp XXX response unexpected)");
    let mut rx_bytes = [0u8; 100];
    let n = socket.recv(&mut rx_bytes).await.context("unable to read response")?;
    println!("[VPN] Got {:?} byte response, ready to shutdown: {:?}", n, rx_bytes);
    let received = std::str::from_utf8(&rx_bytes).expect("valid utf8");
    eprintln!("[VPN] {}", received);

    hypercall(INPUT_FINISHED, 0);
    Ok(())
}

/// Proxy UDP (vsock)
async fn proxy_udp(
    mut vsock: VsockStream,
    peer_address: SockAddr,
    internal_address: SocketAddr,
) -> Result<()> {
    debug!(
        peer = peer_address.to_string(),
        internal = internal_address.to_string(),
        "forwarding udp datagrams"
    );

    let mut buffer = [0u8; 8192];
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("unable to bind udp socket")?;

    loop {
        debug!("reading client datagram");
        let n = vsock
            .read_u16()
            .await
            .context("unable to read client datagram size")? as _;
        vsock
            .read_exact(&mut buffer[..n])
            .await
            .context("unable to read client datagram")?;
        debug!(
            peer = peer_address.to_string(),
            internal = internal_address.to_string(),
            size = n,
            "forwarding udp datagram"
        );
        socket
            .send_to(&buffer[..n], &internal_address)
            .await
            .context("unable to write client datagram")?;
        debug!("reading server datagram");
        let n = socket
            .recv(&mut buffer)
            .await
            .context("unable to read server datagram")?;
        debug!("forwarding server datagram");
        // TODO: Buffer this and similar to reduce syscalls if perf becomes an issue
        vsock
            .write_u16(n as _)
            .await
            .context("unable to write server datagram size")?;
        vsock
            .write_all(&buffer[..n])
            .await
            .context("unable to write server datagram")?;
    }
}
