#!/bin/bash
set -eux

echo "Building for 5 target arches"
cargo build --target x86_64-unknown-linux-musl --release
cargo build --target arm-unknown-linux-musleabi  --release
cargo build --target aarch64-unknown-linux-musl  --release
RUSTFLAGS='-C target-feature=+crt-static' cargo build --target mips-unknown-linux-musl --release
RUSTFLAGS='-C target-feature=+crt-static' cargo build --target mipsel-unknown-linux-musl --release


OUT=vpn
echo "Packaging into ${OUT} and packaging as vpn.tar.gz"
rm  -rf $OUT
mkdir -p $OUT

git config --global --add safe.directory /app
echo "vsock_vpn at $(git rev-parse HEAD) built at $(date)" > $OUT/README.txt

for x in target/*/release/vsock_vpn; do
  ARCH=$(basename $(dirname $(dirname $x)))
  case $ARCH in
    x86_64-unknown-linux-musl)
      SUFFIX="x86_64"
      ;;
    arm-unknown-linux-musleabi)
      SUFFIX="armel"
      ;;
    aarch64-unknown-linux-musl)
      SUFFIX="arm64"
      ;;
    mips-unknown-linux-musl)
      SUFFIX="mipseb"
      ;;
    mipsel-unknown-linux-musl)
      SUFFIX="mipsel"
      ;;
      *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac
  cp $x ${OUT}/vpn.${SUFFIX}
  if [ "$SUFFIX" == "mipseb" ]; then
    cp $x ${OUT}/vpn.mips64eb
  fi
done

tar cvfz vpn.tar.gz ${OUT}/
