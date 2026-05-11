#!/usr/bin/env python3
"""Generate the zkpox witness corpus.

Each witness is a raw byte file. Filenames encode three things:
  - target id prefix:  `01-` (stack BOF), `02-` (off-by-one),
                       `03-` (CVE-2017-9047 extraction).
  - case shape:        free-form descriptor.
  - expected verdict:  `-benign`, `-crash`, or `-fn` (deliberate
                       false-negative against the naive uniform-canary
                       gadget, but caught by the position-varying one).

The regression harness `run-tests.sh` parses the prefix + suffix to
decide which `--target` flag to pass and what verdict to assert.

Target 01 — stack BOF, `for (i = 0; i < n; i++) buf[i] = input[i]`
  Bug: ignores `buf_size` entirely. Any `n > buf_size` writes
  `(n - buf_size)` bytes past the buffer.
  Buffer geometry: BUF_SIZE_DEFAULT = 16.

Target 02 — off-by-one, `for (i = 0; i <= buf_size && i < n; i++) ...`
  Bug: `<=` instead of `<`. Any `n > buf_size` writes EXACTLY ONE byte
  past the buffer, at offset `buf_size`. The trailing input bytes
  (input[buf_size+1..n]) are never written.
  Buffer geometry: BUF_SIZE_DEFAULT = 16.

Target 03 — CVE-2017-9047, libxml2 xmlSnprintfElementContent stale-len.
  Bug: `len = strlen(buf)` cached at entry, then the prefix branch
  appends `prefix_len + 1` bytes but never updates `len`, so the
  subsequent name-fit check uses stale `len`. Max overflow when input
  buf is empty: `prefix_len - 8` bytes (capped by the bypass cutoffs
  at `prefix_len <= size - 10` and `name_len <= size - 10`).
  Buffer geometry: BUF_SIZE_T03 = 32 (the 16-byte default doesn't admit
  any overflow — see findings doc Phase 1.7 appendix).
  Witness encoding: [prefix_len:u8][name_len:u8][prefix...][name...].
"""
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
BUF_SIZE_DEFAULT = 16   # targets 01, 02
BUF_SIZE_T03 = 32       # target 03 — see module docstring
CANARY = 0xA5  # uniform fill in crash_only; must match guest's redzone.rs


def _t03(prefix_len: int, name_len: int,
         prefix_byte: int = ord("P"),
         name_byte: int = ord("n")) -> bytes:
    """Pack a target-03 witness from prefix/name lengths.

    Uses single-byte fills by default so the witness is human-readable;
    callers pass `name_byte=0x00` etc. for the all-zero / high-bit
    soundness probes.
    """
    return (
        bytes([prefix_len, name_len])
        + bytes([prefix_byte]) * prefix_len
        + bytes([name_byte]) * name_len
    )


def _assert_not_canarymatch(name: bytes, data: bytes, target: str) -> None:
    """Spot-check that no `-crash` witness happens to fill the EXACT
    redzone bytes that the gadget reads with the canary value.

    - Target 01 reads bytes [buf_size .. n) — checks the whole overflow.
    - Target 02 reads byte [buf_size] only (off-by-one writes one byte).
    - Target 03 always trails the OOB write with a NUL terminator (the
      bug is strcat-style), so an all-0xA5 overflow is structurally
      impossible — no check needed, only documented here so a future
      reader doesn't add a redundant arm.

    A coincidental canarymatch on these would silently false-negative
    against `crash_only`. Move the witness to a `-fn` filename if that
    coincidence is the test's whole point.
    """
    if not name.endswith(b"-crash.bin"):
        return
    if target == "01":
        overflow = data[BUF_SIZE_DEFAULT:]
        if overflow and all(b == CANARY for b in overflow):
            raise SystemExit(
                f"witness {name!r}: every overflow byte equals CANARY "
                f"(0x{CANARY:02x}). Rename to *-fn.bin or pick different bytes."
            )
    elif target == "02":
        if len(data) > BUF_SIZE_DEFAULT and data[BUF_SIZE_DEFAULT] == CANARY:
            raise SystemExit(
                f"witness {name!r}: off-by-one writes byte index "
                f"{BUF_SIZE_DEFAULT} which equals CANARY (0x{CANARY:02x}). "
                "Rename to *-fn.bin."
            )
    elif target == "03":
        # strcat-style overflow always ends with a NUL byte. Not
        # checkable as "all canary" because 0x00 != 0xA5. No-op.
        return


CORPUS: dict[str, bytes] = {
    # ---------- Target 01: stack BOF (ignores buf_size) -----------------
    "01-empty-benign.bin":         b"",
    "01-1byte-benign.bin":         b"X",
    "01-benign.bin":               b"hello",
    "01-15bytes-benign.bin":       b"A" * 15,
    "01-fill16-benign.bin":        b"A" * BUF_SIZE_DEFAULT,

    "01-overflow1-crash.bin":      b"A" * (BUF_SIZE_DEFAULT + 1),
    "01-overflow2-crash.bin":      b"A" * (BUF_SIZE_DEFAULT + 2),
    "01-crash.bin":                b"A" * 32,
    "01-deep-crash.bin":           b"X" * 100,
    "01-allzero-crash.bin":        b"\x00" * 32,
    "01-highbit-crash.bin":        b"\xff" * 32,

    "01-canarymatch-overflow1-fn.bin": b"A" * BUF_SIZE_DEFAULT + bytes([CANARY]),
    "01-canarymatch-deep-fn.bin":      b"A" * BUF_SIZE_DEFAULT + bytes([CANARY]) * 50,

    # ---------- Target 02: off-by-one (writes 1 byte past buf_size) -----
    "02-empty-benign.bin":         b"",
    "02-1byte-benign.bin":         b"X",
    "02-benign.bin":               b"hello",
    "02-15bytes-benign.bin":       b"A" * 15,
    "02-fill16-benign.bin":        b"A" * BUF_SIZE_DEFAULT,

    # Crash cases — n >= buf_size + 1. Off-by-one always writes EXACTLY
    # one byte past the buffer (at offset buf_size); subsequent input
    # bytes are unreached. The byte at index BUF_SIZE_DEFAULT must not
    # equal CANARY — that case lives at -canarymatch-fn.bin below.
    "02-overflow1-crash.bin":      b"A" * (BUF_SIZE_DEFAULT + 1),
    "02-overflow2-crash.bin":      b"A" * (BUF_SIZE_DEFAULT + 2),
    "02-crash.bin":                b"A" * 32,
    "02-deep-crash.bin":           b"A" * 16 + b"X" * 80,
    "02-highbit-crash.bin":        b"A" * 16 + b"\xff" * 16,
    "02-zerobyte-crash.bin":       b"A" * 16 + b"\x00",

    # Soundness probe: off-by-one writes byte 16 = CANARY exactly. Naive
    # uniform-canary crash_only sees the canary post-call and reports
    # benign. oob_write's position-varying pattern catches it (pattern
    # at offset 16 is 0xA5 XOR ((16*0x9E3779B1)>>24), NOT 0xA5).
    "02-canarymatch-fn.bin":       b"A" * BUF_SIZE_DEFAULT + bytes([CANARY]),

    # ---------- Target 03: CVE-2017-9047 (stale-len strcat overflow) ----
    # BUF_SIZE_T03 = 32. Bypass passes when prefix_len <= 22 AND
    # name_len <= 22. Overflow occurs when prefix_len + name_len > 30.
    #
    # Benign — bug doesn't fire, or fires but doesn't overflow.
    "03-empty-benign.bin":         b"",
    "03-noprefix-benign.bin":      _t03(0, 5),            # no prefix → bug inert
    "03-bothshort-benign.bin":     _t03(5, 5),            # sum=10, fits easily
    "03-prefixonly-benign.bin":    _t03(16, 0),           # name_len=0, strcat skipped
    "03-bigname-noprefix-benign.bin": _t03(0, 22),        # name at bypass limit, no prefix
    "03-borderline-benign.bin":    _t03(15, 15),          # sum=30, exactly fills buf
    # Benign because bypass fails — the libxml2 "safe path" returns " ...":
    "03-prefixoverbypass-benign.bin": _t03(23, 5),        # prefix_len > 22 → safe path
    "03-nameoverbypass-benign.bin":   _t03(5, 23),        # name_len > 22  → safe path

    # Soundness probe: an all-NUL prefix means strcat treats the buffer
    # as empty after the very first byte is written, so the stale-`len`
    # lag never opens. The bug structurally requires a non-NUL prefix
    # — even though the bypass arithmetic doesn't say so. Documented
    # here as a benign case rather than dropped.
    "03-nulprefix-benign.bin":     _t03(15, 22, prefix_byte=0x00, name_byte=0x00),

    # Crash — bug fires AND writes past BUF_SIZE_T03.
    "03-overflow1-crash.bin":      _t03(9, 22),           # sum=31, overflow=1 byte (the NUL)
    "03-overflow2-crash.bin":      _t03(10, 22),          # sum=32, overflow=2 bytes
    "03-deep-crash.bin":           _t03(15, 22),          # sum=37, overflow=7 bytes
    "03-max-crash.bin":            _t03(22, 22),          # sum=44, overflow=14 bytes
    # Byte-pattern coverage: zero name bytes with a non-NUL prefix
    # (0x01) still fires the bug — the prefix's NUL terminator is at
    # position prefix_len, so strcat sees correct strlen() and appends
    # zero name bytes that overflow with the trailing NUL.
    "03-nullname-crash.bin":       _t03(15, 22, prefix_byte=0x01, name_byte=0x00),
    "03-highbit-crash.bin":        _t03(15, 22, prefix_byte=0xFF, name_byte=0xFF),
}


def main() -> int:
    for stale in OUT.glob("*.bin"):
        stale.unlink()

    written = 0
    for name, data in CORPUS.items():
        target = name[:2]  # "01" or "02" or "03"
        _assert_not_canarymatch(name.encode(), data, target)
        (OUT / name).write_bytes(data)
        written += 1
    print(f"wrote {written} witnesses to {OUT}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
