#!/usr/bin/env bash
set -euo pipefail

BOARD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${BOARD_DIR}/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

bash "${SCRIPT_DIR}/make-uf2.sh"

TARGET=thumbv7em-none-eabihf
PROFILE=release
OUT="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/${TARGET}/${PROFILE}"
BIN="${OUT}/mr-nrf52840-nicenano.bin"
ZIP="${OUT}/mr-nrf52840-nicenano-ota.zip"

if ! command -v adafruit-nrfutil >/dev/null 2>&1; then
    python3 -m pip install --user --break-system-packages -q adafruit-nrfutil
    export PATH="${HOME}/.local/bin:${PATH}"
fi
adafruit-nrfutil dfu genpkg --dev-type 0x0052 --application "${BIN}" "${ZIP}"

echo "OTA zip ready: ${ZIP}"
echo "Enter DFU on the node (PKI DM: ENTER DFU), then flash this zip with the nRF DFU app."
