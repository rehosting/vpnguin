# vsock "VPN"

## Quickstart

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release
./target/x86_64-unknown-linux-musl/release/vsock_vpn
```

The event source should produce bind directives of the following form:

```
tcp|udp,server_ip:server_port,external_ip:external_port
```

Note that `server_ip` can be IPv6 if it is enclosed in square brackets, but external IPs must be IPv4.

```
tcp,[::1]:80,127.0.0.1:80
```
