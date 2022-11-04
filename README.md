# vsock "VPN"

## Quickstart

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release
./target/x86_64-unknown-linux-musl/release/vsock_vpn
```

The event source should produce bind directives of the following form:

```
bind tcp|udp server_ip:server_port [external_ip:external_port]
```
