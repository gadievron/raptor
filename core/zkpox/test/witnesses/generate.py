#!/usr/bin/env python3
"""Generate the Phase-0 witness corpus for target #1 (stack BOF).

Each witness is a raw byte file. Filenames encode the expected gadget
verdict (suffix `-benign` → crashed=false, `-crash` → crashed=true) so
the regression harness can assert without a side table.

The corpus deliberately includes edge cases that probe the gadget's
semantics:
  - boundary inputs at exactly buf_size and buf_size+1
  - high-entropy and low-entropy patterns
  - a `-canarymatch` case where the byte that lands on the trailing
    shadow canary happens to equal the canary value (0x42). The naive
    crash_only gadget misses this overflow: it only sees that the canary
    byte still reads 0x42 post-call. Phase 1's oob_write gadget (with a
    shadow allocation table) catches it; we keep the witness here as a
    soundness probe for the simpler gadget. Filename therefore says
    `-canarymatch-fn` (false negative — gadget reports benign though
    overflow occurred).
"""
import os
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
BUF_SIZE = 16
CANARY = 0xA5  # must match harness/guest/src/main.rs CANARY constant

# Spot-check that no 'crash' witness coincidentally fills its overflow
# bytes with the canary value (which would silently masquerade as a
# false negative). The `-fn` witness is deliberately exempt.
def _assert_not_canarymatch(name: bytes, data: bytes) -> None:
    if not name.endswith(b"-crash.bin"):
        return
    if len(data) > BUF_SIZE and all(b == CANARY for b in data[BUF_SIZE:]):
        raise SystemExit(
            f"witness {name!r}: every overflow byte equals CANARY (0x{CANARY:02x}); "
            "this would silently false-negative against crash_only. "
            "Rename to *-fn.bin or pick different bytes."
        )

CORPUS = {
    # Benign cases — fit in or exactly fill buf, no overflow.
    "01-empty-benign.bin":         b"",
    "01-1byte-benign.bin":         b"X",
    "01-benign.bin":               b"hello",
    "01-15bytes-benign.bin":       b"A" * 15,
    "01-fill16-benign.bin":        b"A" * BUF_SIZE,

    # Crash cases — overflow by one or more bytes. None of the bytes
    # below equal the canary 0xA5 (asserted at write time).
    "01-overflow1-crash.bin":      b"A" * (BUF_SIZE + 1),
    "01-overflow2-crash.bin":      b"A" * (BUF_SIZE + 2),
    "01-crash.bin":                b"A" * 32,
    "01-deep-crash.bin":           b"X" * 100,
    "01-allzero-crash.bin":        b"\x00" * 32,
    "01-highbit-crash.bin":        b"\xff" * 32,

    # Soundness probe: every overflow byte equals CANARY. Real overflow
    # occurred but the naive crash_only gadget cannot tell — the trailing
    # redzone reads canary post-call exactly as it did pre-call. Filename
    # says `-fn` (known false negative for this gadget; closed by oob_write).
    "01-canarymatch-overflow1-fn.bin": b"A" * BUF_SIZE + bytes([CANARY]),
    "01-canarymatch-deep-fn.bin":      b"A" * BUF_SIZE + bytes([CANARY]) * 50,
}


def main() -> int:
    # Wipe stale .bin files so renamed/removed witnesses don't linger.
    for stale in OUT.glob("*.bin"):
        stale.unlink()

    written = 0
    for name, data in CORPUS.items():
        _assert_not_canarymatch(name.encode(), data)
        path = OUT / name
        path.write_bytes(data)
        written += 1
    print(f"wrote {written} witnesses to {OUT}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
