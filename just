#!/usr/bin/env bash
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
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

# Build/test must also work on hosts without USB passthrough; hardware access is opt-in.
COMPOSE=(docker compose)
if [ -z "${COMPOSE_FILE:-}" ]; then
    COMPOSE+=(-f docker-compose.yml)
    if [ "${1:-}" = flash ]; then
        COMPOSE+=(-f docker-compose.override.yml)
    fi
fi
# Docker creates absent bind sources as root, which makes codegen scratch unwritable.
ensure_cache_dirs() {
    mkdir -p "$ROOT/.ci-cache/tmp" \
             "$ROOT/.ci-cache/cargo-registry" \
             "$ROOT/.ci-cache/cargo-git"
}

run_dev() {
    ensure_cache_dirs
    "${COMPOSE[@]}" run --rm dev "$@"
}

run_dev_interactive() {
    local flags=()
    if [ -t 0 ]; then
        flags+=(-i)
    fi
    ensure_cache_dirs
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
  ./just ota nrf52840
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
