FROM rust:1.71.1-slim-buster AS mips
# Cross tools
RUN rustup target add mips-unknown-linux-musl mipsel-unknown-linux-musl

COPY --from=ghcr.io/rehosting/embedded-toolchains:latest /opt/cross/mipseb-linux-musl /opt/cross/mipseb-linux-musl
COPY --from=ghcr.io/rehosting/embedded-toolchains:latest /opt/cross/mipsel-linux-musl /opt/cross/mipsel-linux-musl
WORKDIR /app
COPY Cargo.toml /app
COPY ./src /app/src

ENV CC=/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-gcc

# RUN cargo build --target x86_64-unknown-linux-musl --release
# RUN cargo build --target arm-unknown-linux-musleabi  --release
# RUN rustup target add aarch64-unknown-linux-musl # this shouldn't be necessary, but seems to be
# RUN cargo build --target aarch64-unknown-linux-musl  --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/mipseb-linux-musl/bin/mipseb-linux-musl-gcc' \
    cargo build --target mips-unknown-linux-musl --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-gcc' \
    cargo build --target mipsel-unknown-linux-musl --release

FROM rust:1.85.1-slim-bullseye AS builder

RUN  rustup target add x86_64-unknown-linux-musl \
        arm-unknown-linux-musleabi       \
        arm-unknown-linux-musleabihf     \
        powerpc-unknown-linux-gnu        \
        powerpc64-unknown-linux-gnu      \
        powerpc64le-unknown-linux-gnu    \
        loongarch64-unknown-linux-gnu    \
        riscv64gc-unknown-linux-gnu     \
        aarch64-unknown-linux-musl

# Install GNU toolchains for powerpc, powerpc64, powerpc64le, and riscv64
RUN apt-get update && apt-get install -y \
    gcc-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu \
    gcc-powerpc64le-linux-gnu \
    gcc-riscv64-linux-gnu \
    git \
    && apt-get clean

COPY --from=ghcr.io/rehosting/embedded-toolchains:latest /opt/cross/ /opt/cross/

WORKDIR /app
COPY Cargo.toml /app
COPY ./src /app/src

RUN RUSTFLAGS='-C target-feature=+crt-static' \
        cargo build --target x86_64-unknown-linux-musl --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-gcc' \
        cargo build --target arm-unknown-linux-musleabi --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/arm-linux-musleabihf/bin/arm-linux-musleabihf-gcc' \
        cargo build --target arm-unknown-linux-musleabihf --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-gcc' \
        cargo build --target aarch64-unknown-linux-musl --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=powerpc-linux-gnu-gcc' \
        cargo build --target powerpc-unknown-linux-gnu --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=powerpc64-linux-gnu-gcc' \
        cargo build --target powerpc64-unknown-linux-gnu --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=powerpc64le-linux-gnu-gcc' \
        cargo build --target powerpc64le-unknown-linux-gnu --release

RUN rustup target add riscv64gc-unknown-linux-musl

RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/riscv64-linux-musl-cross/bin/riscv64-linux-musl-gcc' \
        cargo build --target riscv64gc-unknown-linux-musl --release
RUN RUSTFLAGS='-C target-feature=+crt-static -C linker=/opt/cross/loongarch64-linux-gcc-cross/bin/loongarch64-unknown-linux-gnu-gcc' \
        cargo build --target loongarch64-unknown-linux-gnu --release

COPY --from=mips /app/target/mips-unknown-linux-musl/release/vsock_vpn /app/target/mips-unknown-linux-musl/release/
COPY --from=mips /app/target/mipsel-unknown-linux-musl/release/vsock_vpn /app/target/mipsel-unknown-linux-musl/release/

# Final packaging stage
FROM debian:bullseye-slim AS packager

RUN apt-get update && apt-get install -y \
    git \
    && apt-get clean

WORKDIR /app

# Copy all the built binaries from the builder stage
COPY --from=builder /app/target/ /app/target/

COPY .git /app/.git

# Create vpn directory and package artifacts
RUN mkdir -p vpn && \
    echo "vsock_vpn at $(git rev-parse HEAD) built at $(date)" > vpn/README.txt && \
    # x86_64
    mkdir -p vpn/x86_64 && \
    cp /app/target/x86_64-unknown-linux-musl/release/vsock_vpn vpn/x86_64/vpn && \
    # armel
    mkdir -p vpn/armel && \
    cp /app/target/arm-unknown-linux-musleabi/release/vsock_vpn vpn/armel/vpn && \
    # aarch64
    mkdir -p vpn/aarch64 && \
    cp /app/target/aarch64-unknown-linux-musl/release/vsock_vpn vpn/aarch64/vpn && \
    # mipseb and mips64eb
    mkdir -p vpn/mipseb vpn/mips64eb && \
    cp /app/target/mips-unknown-linux-musl/release/vsock_vpn vpn/mipseb/vpn && \
    cp /app/target/mips-unknown-linux-musl/release/vsock_vpn vpn/mips64eb/vpn && \
    # mipsel and mips64el
    mkdir -p vpn/mipsel vpn/mips64el && \
    cp /app/target/mipsel-unknown-linux-musl/release/vsock_vpn vpn/mipsel/vpn && \
    cp /app/target/mipsel-unknown-linux-musl/release/vsock_vpn vpn/mips64el/vpn && \
    # powerpc
    mkdir -p vpn/powerpc && \
    cp /app/target/powerpc-unknown-linux-gnu/release/vsock_vpn vpn/powerpc/vpn && \
    # powerpc64
    mkdir -p vpn/powerpc64 && \
    cp /app/target/powerpc64-unknown-linux-gnu/release/vsock_vpn vpn/powerpc64/vpn && \
    # powerpc64le
    mkdir -p vpn/powerpc64le && \
    cp /app/target/powerpc64le-unknown-linux-gnu/release/vsock_vpn vpn/powerpc64le/vpn && \
    # riscv64
    mkdir -p vpn/riscv64 && \
    cp /app/target/riscv64gc-unknown-linux-musl/release/vsock_vpn vpn/riscv64/vpn && \
    # loongarch64
    mkdir -p vpn/loongarch64 && \
    cp /app/target/loongarch64-unknown-linux-gnu/release/vsock_vpn vpn/loongarch64/vpn && \
    # Create the tarball
    tar cvfz vpn.tar.gz -C vpn .
