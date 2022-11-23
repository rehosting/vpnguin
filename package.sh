#!/bin/bash
set -eux

echo "Building for 4 target arches"
cargo build --target x86_64-unknown-linux-musl --release
cargo build --target arm-unknown-linux-musleabi  --release
RUSTFLAGS='-C target-feature=+crt-static' cargo build --target mips-unknown-linux-musl --release
RUSTFLAGS='-C target-feature=+crt-static' cargo build --target mipsel-unknown-linux-musl --release

OUT=bundle
echo "Packaging into ${OUT} and packaging as vpn.tar.gz"
rm  -rf $OUT
mkdir -p $OUT

echo "vsock_vpn at $(git rev-parse HEAD) built at $(date)" > $OUT/README.txt

for x in target/*/release/vsock_vpn; do 
  ARCH=$(basename $(dirname $(dirname $x)))
  cp $x ${OUT}/vpn.${ARCH}
done

tar cvfz vpn.tar.gz bundle/
