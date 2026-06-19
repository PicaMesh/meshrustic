#!/usr/bin/env bash
# Build release firmware and pack a UF2 for Adafruit UF2 bootloaders (nice!nano).
set -euo pipefail

BOARD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${BOARD_DIR}/../.." && pwd)"
cd "${BOARD_DIR}"

TARGET=thumbv7em-none-eabihf
PROFILE=release
FEATURES=nicenano
OUT="${REPO_ROOT}/target/${TARGET}/${PROFILE}"
ELF="${OUT}/nrf52840"
BIN="${OUT}/nrf52840-nicenano.bin"
UF2="${OUT}/nrf52840-nicenano.uf2"
UF2CONV="${BOARD_DIR}/scripts/uf2/uf2conv.py"

# Adafruit nRF52840 UF2 family; app base with SoftDevice S140 v6.x.
UF2_BASE=0x26000
UF2_FAMILY=0xADA52840

cargo build --"${PROFILE}" --features "${FEATURES}"
rust-objcopy -O binary "${ELF}" "${BIN}"
python3 "${UF2CONV}" -f "${UF2_FAMILY}" "${BIN}" -c -b "${UF2_BASE}" -o "${UF2}"

echo "UF2 ready: ${UF2}"
echo "Double-tap reset on the nice!nano, then copy this file to the NICENANO drive."
