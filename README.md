# vsock "VPN"

Intended for use with our [penguin](https://github.com/rehosting/penguin) rehosting platform.

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

# Distribution

DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
 
This material is based upon work supported under Air Force Contract No. FA8702-15-D-0001 or FA8702-25-D-B002. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the U.S. Air Force.
 
© 2025 Massachusetts Institute of Technology
 
The software/firmware is provided to you on an As-Is basis.
 
Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.
