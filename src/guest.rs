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


    // Set up a vsock listener
    //info!(
    //    context = command.context_id,
    //    port = command.command_port,
    //    "listening for events"
    //);
    //let mut listener = VsockListener::bind(command.context_id, command.command_port)
    //    .context("unable to bind vsock listener")?;

    let mut buffer = vec![0_u8; 1024];

    loop {
        // First hypercall: "Get data" with arg of buffer
        buffer[0] = 0; // Always clear command
        let buffer_addr : u32 = buffer.as_ptr() as u32;

        hypercall(GET_DATA, buffer_addr);

        if buffer[0] == 0 {
            sleep(Duration::from_millis(2000)).await;
            continue;
        } else if buffer[0] == 1 {
            yield_now().await;
            continue;
        } else if buffer[1] != 2 {
            error!("Unexpected control bytes in hypercall message");
        }
        // If we're here the first byte was 2. Should consume the buffer!

        println!( "GOT BUFFER {:?}", buffer[0]);
        //tokio::spawn(async move {
        //    if let Err(e) = process_buffer(buffer).await {
        //        error!("unable to process client: {e:#?}");
        //    }
        //});
    }
}

/// Process a vsock client.
//async fn process_client(mut vsock: VsockStream, peer_address: SockAddr) -> Result<()> {
/*
async fn process_client(mut buffer: HyperBuf) -> Result<()> {
    info!(peer = peer_address.to_string(), "processing client");

    // Process the init event
    match buffer.request {
        Some(HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Tcp,
        }) => {
            let stream = TcpStream::connect(internal_address)
                .await
                .context("unable to connect to guest server")?;
            forward_tcp(peer_address, buffer.data, stream).await?;
        }

        Some(HostRequest::Forward {
            internal_address,
            transport: _transport @ Transport::Udp,
        }) => {
            return Err(anyhow!("NYI UDP"));
            //proxy_udp(vsock, peer_address, internal_address).await?;
        }

        None => {
            return Err(anyhow!("unable to read init event (no event received)"));
        }
    };

    Ok(())
}
*/

/// Proxy TCP.
async fn forward_tcp(
    peer_address: SockAddr,
    data: &[u8],
    mut stream: TcpStream,
) -> Result<()> {
    /*
    // Forward data
    debug!(peer = peer_address.to_string(), "forwarding data to host");
    //stream.send(data);
    //let (rx, tx) = stream.split();
    //Independently use tx/rx for sending/receiving
    //tx.send_to(data);
    stream.send_to(data);
    */
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
