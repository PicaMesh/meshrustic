#!/usr/bin/env bash
# RAM/flash usage and the largest stack frames of the release build. Run via `just size nrf52840`.
# Two boot regressions came from numbers this prints: a Router built on the stack that no longer
# fit above the statics, and statics growing past what the stack needed.
set -euo pipefail
ELF=/workspace/target/thumbv7em-none-eabihf/release/nrf52840
cargo build --release >/dev/null
echo "== sections (text data bss)"; rust-size "$ELF" | tail -1
echo "== largest statics"; rust-nm -S --size-sort -C "$ELF" | tail -5
echo "== largest stack frames"
rust-objdump -d --no-show-raw-insn -C "$ELF" | python3 -c '
import sys, re
fn=None; out=[]
for l in sys.stdin:
    m=re.match(r"^[0-9a-f]+ <(.*)>:$", l)
    if m: fn=m.group(1); continue
    m=re.search(r"sub(?:\.w)?\s+sp, sp, #(0x[0-9a-f]+|\d+)", l) or re.search(r"sub\s+sp, #(0x[0-9a-f]+|\d+)", l)
    if m and fn: out.append((int(m.group(1),0), fn))
out.sort(reverse=True)
for sz,f in out[:8]: print(f"{sz:7d}  {f[:100]}")
'
