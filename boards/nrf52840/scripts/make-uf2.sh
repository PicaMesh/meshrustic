#!/usr/bin/env bash
set -euo pipefail

BOARD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${BOARD_DIR}/../.." && pwd)"
cd "${BOARD_DIR}"

TARGET=thumbv7em-none-eabihf
PROFILE=release
FEATURES=nicenano
OUT="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/${TARGET}/${PROFILE}"
ELF="${OUT}/nrf52840"
BIN="${OUT}/mr-nrf52840-nicenano.bin"
UF2="${OUT}/mr-nrf52840-nicenano.uf2"
UF2CONV="${BOARD_DIR}/scripts/uf2/uf2conv.py"
UF2_BASE=0x26000
UF2_FAMILY=0xADA52840

cargo build --"${PROFILE}" --features "${FEATURES}"
rust-objcopy -O binary "${ELF}" "${BIN}"
python3 "${UF2CONV}" -f "${UF2_FAMILY}" "${BIN}" -c -b "${UF2_BASE}" -o "${UF2}"

echo "UF2 ready: ${UF2}"
echo "Double-tap reset on the nice!nano, then copy this file to the NICENANO drive."
