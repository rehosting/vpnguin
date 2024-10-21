#!/bin/bash
set -eux

echo "Building for 5 target arches"
cargo build --target x86_64-unknown-linux-musl --release
cargo build --target arm-unknown-linux-musleabi  --release
rustup target add aarch64-unknown-linux-musl # this shouldn't be necessary, but seems to be
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
      ARCH_DIR="x86_64"
      ;;
    arm-unknown-linux-musleabi)
      ARCH_DIR="armel"
      ;;
    aarch64-unknown-linux-musl)
      ARCH_DIR="aarch64"
      ;;
    mips-unknown-linux-musl)
      ARCH_DIR="mipseb"
      ;;
    mipsel-unknown-linux-musl)
      ARCH_DIR="mipsel"
      ;;
      *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac
  mkdir -p ${OUT}/${ARCH_DIR}
  cp $x ${OUT}/${ARCH_DIR}/vpn
  if [ "$ARCH_DIR" == "mipseb" ]; then
      mkdir -p ${OUT}/mips64eb
      cp $x ${OUT}/mips64eb/vpn
    elif [ "$ARCH_DIR" == "mipsel" ]; then
      mkdir -p ${OUT}/mips64el
      cp $x ${OUT}/mips64el/vpn
  fi
done

tar cvfz vpn.tar.gz ${OUT}/
