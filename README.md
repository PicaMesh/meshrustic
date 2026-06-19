# MeshRustic

LoRa router firmware in Rust, wire-compatible with the public mesh packet format
used by Meshtastic-class devices on the air. The goal is efficient routing using
SignalRouting, NodeRateLimit, and ChannelQoS with a minimal memory footprint.

**Copyright:** PicaMesh — dual-licensed under [AGPL-3.0](LICENSE) or a
[commercial license](LICENSE-COMMERCIAL.md). See [LICENSE.md](LICENSE.md).
All Rust sources and wire schemas here are original PicaMesh work; no Meshtastic
firmware source is incorporated.

This project is not sponsored by, affiliated with, or endorsed by the Meshtastic project.

## Development environment

Edit on your host in whatever IDE you like (Cursor, VS Code, Neovim, …). **The only host dependency is Docker** (with Compose v2). Rust, `just`, probe-rs, espflash, and every other build tool live inside the shared dev container.

From the repository root, use the **`./just`** wrapper script — it starts the container and runs recipes there:

```bash
./just image                 # once — build the dev container (~few minutes)
./just build nrf52840        # release firmware for the active nRF52840 target
./just test rpi-app          # host integration tests for shared crates
```

Firmware binary (SWD / probe-rs):

`target/thumbv7em-none-eabihf/release/nrf52840`

UF2 for **nice!nano** (Adafruit bootloader, double-tap reset → copy to `NICENANO` drive):

```bash
./just uf2 nrf52840
```

Output:

`target/thumbv7em-none-eabihf/release/nrf52840-nicenano.uf2`

Works on macOS — no USB passthrough needed; copy the `.uf2` in Finder like any USB drive.

The Pro Micro DIY + HT-RA62 pin map in this firmware matches the MT variant on a
nice!nano carrier board. `uf2` links at **0x26000** (Adafruit UF2 + SoftDevice S140 v6);
`./just build` without `uf2` still targets 0x0 for SWD/probe-rs workflows.

### Prerequisites

| Tool | Purpose |
|------|---------|
| [Docker](https://docs.docker.com/get-docker/) + Compose v2 | Runs the dev container (build, test, flash, deploy) |

Start Docker Desktop (macOS/Windows) or the Docker daemon (Linux) before running `./just`.

**Optional on the host:** install [rustup](https://rustup.rs/) so your IDE's rust-analyzer can use each board's `rust-toolchain.toml`. Builds and tests still go through `./just` and Docker.

### Boards

| Board | Status | Role |
|-------|--------|------|
| `nrf52840` | **Active** | nRF52840 + HT-RA62 (Pro Micro DIY pin map; nice!nano carrier) |
| `rpi-app` | **Active** | Host `std` binary; runs the integration test suite for shared crates |
| `rp2040`, `esp32-c3`, `esp32-c6`, `esp32-s3` | Scaffold | Toolchain + `.cargo/config.toml` only — not in the workspace yet |

CI currently builds **`nrf52840`** and **`rpi-app`** only.

### Common commands

Run from the repo root (always prefix with `./`):

```
./just image                 # build/refresh the shared dev image
./just build  <board>        # cargo build --release
./just test   <board>        # cargo test (meaningful for rpi-app today)
./just clippy <board>        # cargo clippy -D warnings
./just fmt    <board>        # cargo fmt
./just fmt-check <board>     # cargo fmt --check (same as CI)
./just flash  <board>        # build + flash via probe-rs/espflash (Linux/WSL2 + USB)
./just uf2    nrf52840       # build + UF2 for nice!nano (drag-and-drop)
./just shell                 # interactive shell in the dev container
./just deploy-rpi <user@host> # build aarch64 binary, rsync + restart on a Pi
./just help                  # quick usage summary
```

Inside the container you can also run `just` directly (same recipes as in `justfile`).

Equivalent without the wrapper (bash — set HOST_UID/GID; do not use `UID` on macOS):

```bash
export HOST_UID="$(id -u)" HOST_GID="$(id -g)"
docker compose build dev
docker compose run --rm dev just build nrf52840
```

### Host setup by OS

#### Linux

- Install Docker Engine and the `docker compose` plugin; add your user to the `docker` group.
- `./just image` once, then e.g. `./just build nrf52840`.
- USB probes (CMSIS-DAP / ST-Link / J-Link) and ESP32 serial ports are passed through via `docker-compose.override.yml` — `./just flash nrf52840` works with hardware attached.

#### Windows / WSL2

- Install Docker Desktop with the **WSL2 backend** (required).
- Clone the repo **inside the WSL filesystem** (e.g. `~/code/meshrustic`), not under `/mnt/c/…` — bind mounts and file permissions are unreliable on the Windows drive.
- Run all `./just` commands from a **WSL2 bash shell**, not PowerShell or CMD.
- For flashing: install [`usbipd-win`](https://github.com/dorssel/usbipd-win), attach the probe with `usbipd attach --wsl --busid <BUSID>` (`usbipd list`), then `./just flash <board>` from WSL2.

#### macOS

- Install Docker Desktop only.
- **`./just build`**, **`./just test rpi-app`**, **`./just clippy`**, and **`./just fmt`** work fully in Docker.
- **`./just flash` does not work** — Docker Desktop's Linux VM has no USB passthrough to probes or ESP32 serial. Build on macOS; flash from Linux or WSL2 with the board attached.
- The image is built with a fixed in-container user (`1000:1000`); at run time `./just` maps your macOS user (`501:20`, etc.) so workspace files keep the correct owner.

**View defmt logs** after flashing on Linux/WSL2 (RTT over the debug probe, inside the container):

```bash
./just shell
defmt-print -e target/thumbv7em-none-eabihf/release/nrf52840
```

### Testing

- **`./just test rpi-app`** — runs host integration tests for protocol, crypto, store, radio airtime, etc. (no hardware).
- Embedded boards (`nrf52840`, …) are `no_std` / `no_main`; their board crates are not unit-tested on the host. Shared logic is tested through `rpi-app` and the `crates/*` libraries.

## Why this design

- **Docker-only host setup.** No rustup, probe-rs, or `just` install on the developer machine — only `./just` + Docker.
- **No devcontainers / Remote-Containers.** The editor never runs inside the container, so it works the same with Cursor, VS Code, or anything else — nothing IDE-specific to configure.
- **One Dockerfile, used by devs and CI.** No drift between local builds and CI — same image.
- **probe-rs** for nRF52840/RP2040 flashing and debugging; **espflash** for ESP32 (USB serial/JTAG, no external probe). Both are wired through each board's `.cargo/config.toml` `runner =`, so `cargo run --release` builds and flashes in one step where USB is available.
- **ESP32-S3 (Xtensa)** uses Espressif's Rust fork via `espup` (toolchain name `esp`). ESP32-C3/C6 are RISC-V and use upstream stable Rust, like the ARM boards.
- **Raspberry Pi target** is a cross-compiled Linux binary — deploy with `./just deploy-rpi`, no USB flashing.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. Builds [`docker/Dockerfile`](docker/Dockerfile) — the same file developers build locally — and pushes it to GHCR.
2. Matrix over **`nrf52840`** and **`rpi-app`**: `./just build`, `./just clippy`, `./just fmt-check`, and (for `rpi-app` only) `./just test`.

CI sets `COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml`, which **skips** [`docker-compose.override.yml`](docker-compose.override.yml) (USB / `privileged`). Locally, Compose auto-loads the override so probes and serial ports work without extra flags.

[`docker-compose.ci.yml`](docker-compose.ci.yml) bind-mounts `./.ci-cache/` for the cargo registry so GitHub Actions can cache it between runs.

## Licensing

MeshRustic is **dual-licensed** ([LICENSE.md](LICENSE.md)):

- **[GNU AGPL v3](LICENSE)** — free for hobbyists, researchers, and others who can comply with copyleft (including source obligations when you distribute devices or offer modified software to users over a network).
- **[Commercial license](LICENSE-COMMERCIAL.md)** — required when you cannot or will not comply with AGPL (typical for commercial products, integrators, service providers, and many government procurements).

Third-party Rust crates and tools keep their own licenses — see [NOTICE](NOTICE) and run `cargo license` before shipping.

This repository does not contain Meshtastic firmware source. On-air compatibility is by wire specification only.

## Known trade-offs

- The dev container runs `privileged: true` in `docker-compose.override.yml` (local only) to reach `/dev/ttyUSB*` / `/dev/ttyACM*` for espflash. If that is not acceptable, replace it with explicit `--device=/dev/ttyACM0` entries and a stable udev rule on the host. CI skips this file entirely.
- The image is large (multiple toolchains + Xtensa). Build once with `./just image` and reuse; CI pulls a cached image from the registry.
- macOS cannot flash through Docker. Build with `./just build`; use Linux or WSL2 for `./just flash`.
- WSL2: keep the git checkout on the Linux filesystem, not `/mnt/c`.
