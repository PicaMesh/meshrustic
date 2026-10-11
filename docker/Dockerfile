
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/opt/rustup/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl git pkg-config sudo ca-certificates \
        libudev-dev libusb-1.0-0-dev libssl-dev \
        protobuf-compiler \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        usbutils picocom gdb-multiarch rsync openssh-client python3 python3-pip \
    && pip3 install --break-system-packages --no-cache-dir adafruit-nrfutil \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal \
    && chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

RUN rustup component add rust-src llvm-tools clippy rustfmt \
    && rustup target add \
        thumbv7em-none-eabihf \
        thumbv6m-none-eabi \
        riscv32imc-unknown-none-elf \
        riscv32imac-unknown-none-elf \
        aarch64-unknown-linux-gnu
RUN mkdir -p /opt/cargo-config && \
    printf '[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\n' \
        > /opt/cargo-config/config.toml
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh \
    | bash

RUN cargo binstall -y \
        just \
        probe-rs-tools \
        espflash \
        cargo-binutils \
        flip-link \
        defmt-print
RUN cargo binstall -y espup \
    && espup install --targets esp32s3 --export-file /opt/export-esp.sh \
    && chmod 644 /opt/export-esp.sh \
    && chmod -R a+w "$RUSTUP_HOME"
RUN set -eux; \
    userdel -r ubuntu 2>/dev/null || true; \
    if getent group 1000 >/dev/null; then \
        existing="$(getent group 1000 | cut -d: -f1)"; \
        if [ "$existing" != dev ]; then groupmod -n dev "$existing"; fi; \
    else \
        groupadd -g 1000 dev; \
    fi; \
    useradd -m -u 1000 -g dev -s /bin/bash dev; \
    usermod -aG dialout,plugdev dev; \
    echo "dev ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers; \
    chown -R 1000:1000 /opt/cargo /opt/rustup

USER dev
WORKDIR /workspace
