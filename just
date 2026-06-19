#!/usr/bin/env bash
# Host entry point — only Docker is required on the machine. All recipes run
# inside the dev container via the in-container justfile.
#
# Compatible with Linux, macOS, and Windows/WSL2 (run from a bash shell in the
# repo root; clone inside the WSL filesystem, not /mnt/c).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found — install Docker Desktop or Docker Engine" >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "error: docker compose v2 not found — install the Compose plugin" >&2
    exit 1
fi

# Do not use UID/GID here — bash on macOS treats UID as read-only.
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

COMPOSE=(docker compose)

run_dev() {
    # docker compose run does not accept docker run's combined -it shorthand.
    # Compose allocates a TTY automatically when stdin is a terminal.
    "${COMPOSE[@]}" run --rm dev "$@"
}

run_dev_interactive() {
    local flags=()
    if [ -t 0 ]; then
        flags+=(-i)
    fi
    "${COMPOSE[@]}" run --rm "${flags[@]}" dev "$@"
}

case "${1:-}" in
    image)
        "${COMPOSE[@]}" build dev
        ;;
    shell)
        run_dev_interactive bash
        ;;
    help | --help | -h)
        cat <<'EOF'
Usage: ./just <recipe> [args…]

Host-only recipes (run Docker directly):
  image                 build/refresh the dev container image
  shell                 interactive shell in the dev container

All other recipes run just inside the container, e.g.:
  ./just build nrf52840
  ./just test rpi-app
  ./just uf2 nrf52840
  ./just flash nrf52840        # Linux/WSL2 + USB only

Only Docker (+ Compose v2) must be installed on the host.
Use bash: ./just …  (WSL2/Linux/macOS). Do not use a globally installed `just`.
EOF
        ;;
    "")
        run_dev just --list
        ;;
    *)
        run_dev just "$@"
        ;;
esac
