_in_board cmd board:
    bash -lc '\
        mkdir -p /workspace/.ci-cache/tmp || exit 1; \
        [ -f /opt/export-esp.sh ] && source /opt/export-esp.sh; \
        cd boards/{{board}} && {{cmd}}'

build board *args:
    just _in_board "cargo build --release {{args}}" {{board}}

test board *args:
    just _in_board "cargo test {{args}}" {{board}}

clippy board *args:
    just _in_board "cargo clippy {{args}} -- -D warnings" {{board}}

fmt board:
    just _in_board "cargo fmt --all" {{board}}

fmt-check board:
    just _in_board "cargo fmt --all --check" {{board}}
flash board:
    just _in_board "cargo run --release" {{board}}
uf2 board:
    just _in_board "bash scripts/make-uf2.sh" {{board}}
ota board:
    just _in_board "bash scripts/make-ota.sh" {{board}}
size board:
    just _in_board "bash scripts/size.sh" {{board}}

deploy-rpi host:
    bash -lc '\
        cd boards/rpi-app && \
        cargo build --release --target aarch64-unknown-linux-gnu && \
        rsync -avz ../../target/aarch64-unknown-linux-gnu/release/rpi-app \
            {{host}}:/home/pi/rpi-app && \
        ssh {{host}} "sudo systemctl restart rpi-app"'
