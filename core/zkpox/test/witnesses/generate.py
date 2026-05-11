#!/usr/bin/env python3
"""Generate the zkpox witness corpus.

Each witness is a raw byte file. Filenames encode three things:
  - target id prefix:  `01-` (stack BOF) or `02-` (off-by-one).
  - case shape:        free-form descriptor.
  - expected verdict:  `-benign`, `-crash`, or `-fn` (deliberate
                       false-negative against the naive uniform-canary
                       gadget, but caught by the position-varying one).

The regression harness `run-tests.sh` parses the prefix + suffix to
decide which `--target` flag to pass and what verdict to assert.

Target 01 — stack BOF, `for (i = 0; i < n; i++) buf[i] = input[i]`
  Bug: ignores `buf_size` entirely. Any `n > buf_size` writes
  `(n - buf_size)` bytes past the buffer.

Target 02 — off-by-one, `for (i = 0; i <= buf_size && i < n; i++) ...`
  Bug: `<=` instead of `<`. Any `n > buf_size` writes EXACTLY ONE byte
  past the buffer, at offset `buf_size`. The trailing input bytes
  (input[buf_size+1..n]) are never written.

That difference shows up in `oob_count`: target 01 reports up to the
witness length minus buf_size; target 02 always reports exactly 1.
"""
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
BUF_SIZE = 16
CANARY = 0xA5  # uniform fill in crash_only; must match guest's redzone.rs


def _assert_not_canarymatch(name: bytes, data: bytes, target: str) -> None:
    """Spot-check that no `-crash` witness happens to fill the EXACT
    redzone bytes that the gadget reads with the canary value.

    - Target 01 reads bytes [buf_size .. n) — checks the whole overflow.
    - Target 02 reads byte [buf_size] only (off-by-one writes one byte).

    A coincidental canarymatch on these would silently false-negative
    against `crash_only`. Move the witness to a `-fn` filename if that
    coincidence is the test's whole point.
    """
    if not name.endswith(b"-crash.bin"):
        return
    if target == "01":
        overflow = data[BUF_SIZE:]
        if overflow and all(b == CANARY for b in overflow):
            raise SystemExit(
                f"witness {name!r}: every overflow byte equals CANARY "
                f"(0x{CANARY:02x}). Rename to *-fn.bin or pick different bytes."
            )
    elif target == "02":
        if len(data) > BUF_SIZE and data[BUF_SIZE] == CANARY:
            raise SystemExit(
                f"witness {name!r}: off-by-one writes byte index {BUF_SIZE} "
                f"which equals CANARY (0x{CANARY:02x}). Rename to *-fn.bin."
            )


CORPUS: dict[str, bytes] = {
    # ---------- Target 01: stack BOF (ignores buf_size) -----------------
    "01-empty-benign.bin":         b"",
    "01-1byte-benign.bin":         b"X",
    "01-benign.bin":               b"hello",
    "01-15bytes-benign.bin":       b"A" * 15,
    "01-fill16-benign.bin":        b"A" * BUF_SIZE,

    "01-overflow1-crash.bin":      b"A" * (BUF_SIZE + 1),
    "01-overflow2-crash.bin":      b"A" * (BUF_SIZE + 2),
    "01-crash.bin":                b"A" * 32,
    "01-deep-crash.bin":           b"X" * 100,
    "01-allzero-crash.bin":        b"\x00" * 32,
    "01-highbit-crash.bin":        b"\xff" * 32,

    "01-canarymatch-overflow1-fn.bin": b"A" * BUF_SIZE + bytes([CANARY]),
    "01-canarymatch-deep-fn.bin":      b"A" * BUF_SIZE + bytes([CANARY]) * 50,

    # ---------- Target 02: off-by-one (writes 1 byte past buf_size) -----
    "02-empty-benign.bin":         b"",
    "02-1byte-benign.bin":         b"X",
    "02-benign.bin":               b"hello",
    "02-15bytes-benign.bin":       b"A" * 15,
    "02-fill16-benign.bin":        b"A" * BUF_SIZE,

    # Crash cases — n >= buf_size + 1. Off-by-one always writes EXACTLY
    # one byte past the buffer (at offset buf_size); subsequent input
    # bytes are unreached. The byte at index BUF_SIZE must not equal
    # CANARY — that case lives at -canarymatch-fn.bin below.
    "02-overflow1-crash.bin":      b"A" * (BUF_SIZE + 1),     # exactly the off-by-one byte
    "02-overflow2-crash.bin":      b"A" * (BUF_SIZE + 2),     # extra bytes are unreached but valid stdin
    "02-crash.bin":                b"A" * 32,
    "02-deep-crash.bin":           b"A" * 16 + b"X" * 80,     # byte 16 is 'X' (0x58), distinct from canary
    "02-highbit-crash.bin":        b"A" * 16 + b"\xff" * 16,  # byte 16 is 0xFF
    "02-zerobyte-crash.bin":       b"A" * 16 + b"\x00",       # byte 16 is 0x00

    # Soundness probe: off-by-one writes byte 16 = CANARY exactly. Naive
    # uniform-canary crash_only sees the canary post-call and reports
    # benign. oob_write's position-varying pattern catches it (pattern
    # at offset 16 is 0xA5 XOR ((16*0x9E3779B1)>>24), NOT 0xA5).
    "02-canarymatch-fn.bin":       b"A" * BUF_SIZE + bytes([CANARY]),
}


def main() -> int:
    for stale in OUT.glob("*.bin"):
        stale.unlink()

    written = 0
    for name, data in CORPUS.items():
        target = name[:2]  # "01" or "02"
        _assert_not_canarymatch(name.encode(), data, target)
        (OUT / name).write_bytes(data)
        written += 1
    print(f"wrote {written} witnesses to {OUT}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
