# Recipes run inside the dev container — invoke from the repo root via ./just
#
#   ./just image              build/refresh the dev image (host wrapper)
#   ./just build  <board>     cargo build --release for boards/<board>
#   ./just test   <board>     cargo test for boards/<board>
#   ./just clippy <board>     cargo clippy (warnings as errors) for boards/<board>
#   ./just flash  <board>     build + flash/run on real hardware (Linux/WSL2 + USB)
#   ./just uf2    <board>     build + UF2 for nice!nano (Adafruit bootloader @ 0x26000)
#   ./just shell              interactive shell in the dev container (host wrapper)
#   ./just deploy-rpi <host>  build + rsync + restart the RPi app over SSH
#
# Boards: nrf52840, rp2040, esp32-s3, esp32-c3, esp32-c6, rpi-app

# Source the Xtensa env (needed only for esp32-s3) if present, then run a command.
_in_board cmd board:
    bash -lc '\
        mkdir -p /workspace/.ci-cache/tmp; \
        [ -f /opt/export-esp.sh ] && source /opt/export-esp.sh; \
        cd boards/{{board}} && {{cmd}}'

build board:
    just _in_board "cargo build --release" {{board}}

test board:
    just _in_board "cargo test" {{board}}

clippy board:
    just _in_board "cargo clippy --bins -- -D warnings" {{board}}

fmt board:
    just _in_board "cargo fmt" {{board}}

fmt-check board:
    just _in_board "cargo fmt --check" {{board}}

# Requires the target hardware attached and visible to Docker (see README).
flash board:
    just _in_board "cargo run --release" {{board}}

# UF2 drag-and-drop image for nice!nano (double-tap reset → copy to NICENANO drive).
uf2 board:
    just _in_board "bash scripts/make-uf2.sh" {{board}}

deploy-rpi host:
    bash -lc '\
        cd boards/rpi-app && \
        cargo build --release --target aarch64-unknown-linux-gnu && \
        rsync -avz target/aarch64-unknown-linux-gnu/release/rpi-app \
            {{host}}:/home/pi/rpi-app && \
        ssh {{host}} "sudo systemctl restart rpi-app"'
