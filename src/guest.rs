//! Guest implementation.

use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

use crate::{read_event, Guest, HostRequest, Transport, HyperBuf};
use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::yield_now,
};
use tokio_vsock::{SockAddr, VsockListener, VsockStream};
use std::arch::asm;
use std::io::Cursor;
use std::mem;

// DEBUG
use crate::HostRequest::Forward;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


const GET_DATA : u32 = 6001;

fn hypercall(num: u32, a1: u32) {
    unsafe {
            asm!(
                "movz $0, {num}, {a1}",
                num = in(reg) num,
                a1 = in(reg) a1,
                )
    }
}


/// Execute the guest endpoint.
pub async fn execute(command: &Guest) -> Result<()> {

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
        let buffer_addr : u32 = buffer.as_ptr() as u32;

        hypercall(GET_DATA, buffer_addr);

        if buffer[0] == 0 {
            println!("SLEEP 2s");
            sleep(Duration::from_millis(2000)).await;
            continue;
        } else if buffer[0] == 1 {
            println!("RETRY");
            //yield_now().await;
            continue;
        } else if buffer[0] != 0xff {
            error!("Unexpected command in hypercall message: {:?}", buffer[0]);
        }
        let mut cur = Cursor::new(&buffer);
        match bincode::deserialize_from::<_, HyperBuf>(cur) {
            Ok(request) => {
                println!("Sending data to target: {:?}", request.target);
                //println!("Request command: {:?}", request.command);
                //println!("Request data: {:?}", request.payload);

                tokio::spawn(async move {
                    if let Err(e) = process_buffer(request).await {
                        error!("unable to process client: {e:#?}");
                    }
                });
            },
            Err(e) => println!("Error deserializing data from hypercall {:?}", e),
        }
    }
}

/// Process a vsock client.
//async fn process_client(mut vsock: VsockStream, peer_address: SockAddr) -> Result<()> {

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
            return Err(anyhow!("NYI UDP"));
            //proxy_udp(vsock, peer_address, internal_address).await?;
        }

        //None => {
        //    return Err(anyhow!("unable to read init event (no event received)"));
        //}
    };

    Ok(())
}

/// Proxy TCP.
async fn forward_tcp(
    data: &[u8],
    mut stream: TcpStream,
) -> Result<()> {

    // Send data on stream
    println!("Connecting to {:?} and sending request: {:?}", stream, data);
    stream.write(data).await?;

    // Just for debugging, let's try printing any response we get. First 100 bytes only
    // Read from the current data in the TcpStream TODO: timeout
    let mut rx_bytes = [0u8; 100];
    println!("Wait for response");
    stream.read(&mut rx_bytes).await?;
    println!("Got response; {:?}", rx_bytes);
    let received = std::str::from_utf8(&rx_bytes).expect("valid utf8");
    eprintln!("{}", received);
    Ok(())
}

/// Proxy TCP.
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

/// Proxy UDP.
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
