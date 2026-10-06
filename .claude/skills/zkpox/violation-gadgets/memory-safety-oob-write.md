# Violation Gadget: `memory-safety::oob-write`

Stronger than `crash-only`. Detects out-of-bounds writes using a
position-varying redzone pattern, and commits structured outputs
(count + offset).

## Gadget ID

`memory-safety::oob-write@0.1.0`

## What it proves

"On this witness, the C target wrote at one or more addresses outside
the buffer it was given." Recorded with a count of OOB bytes and a
signed offset (negative = under-run; ≥ buf_size = over-run) of the
first one.

## What it leaks

- `oob_count: u32` — total OOB bytes the gadget observed.
- `oob_first_offset: i32` — signed offset from buf[0] of the first OOB
  write. Negative means a leading-redzone (under-run); ≥ BUF_SIZE
  means trailing-redzone (over-run).

These leak a coarse shape of the corruption (one byte vs many; a
buffer overflow vs an under-run) but no witness contents.

Bundle producers can blank either field via `leaked_fields` if a
specific disclosure prefers to leak less; default is to include both.

## Detection mechanism (Phase 1 implementation)

Position-varying pattern fill: for redzone position `p`, the expected
byte is
```
pattern_byte(p) = 0xA5 XOR ((p * 0x9E37_79B1) >> 24)
```
Distinct expected byte at every offset. An attacker who didn't
pre-compute the table can match any single position with probability
1/256 (same as a uniform canary), but matching N consecutive overflow
bytes drops to (1/256)^N because the expected byte differs per
position.

**Phase 1.x plan:** replace the probabilistic redzone with a true
shadow allocation table — per-store instrumentation, ASan-equivalent.
The gadget interface (the public-values shape) is designed to survive
that swap. Current implementation is fast and good enough for an
informed-vendor disclosure flow; the SAT-based version is what we'd
want for adversarial conditions.

## Cost (rough, target #1)

- Cycles: ~9,800 per witness (two C calls — one per fill pattern).
- Prove time on this Mac, `--wrap=core`: ~17 s warm pk.
- Prove time on this Mac, `--wrap=groth16`: ~17 min total.
- Proof bytes: ~2.65 MB (core) / ~1.7 KB (groth16, bundle-friendly).

## When to use it

- Memory-corruption disclosures where the bundle should distinguish
  "a write happened past the buffer" from "the program crashed."
- Any case where the simpler `crash-only` is at risk of false-negative
  via canary-match witnesses (kept in our corpus as `-fn` files).

## When NOT to use it

- Bugs that don't go through a redzone (info-leak reads, control-flow
  hijack via aliased state). Use a control-flow- or info-leak-specific
  gadget when those land in the catalogue.
- Adversarial witness generators that may pre-compute the
  position-varying pattern table. Document this in the bundle's
  `vulnerability.notes` and prefer the shadow-allocation gadget once
  it lands.

## Public outputs

In the bundle's `proof.bytes` STARK / Groth16 wrap, the public values
include:

- `crash_only_crashed: bool` — Phase 1's guest runs the simpler gadget
  in parallel; the bundle exposes both verdicts.
- `oob_detected: bool` — primary verdict for this gadget.
- `oob_count: u32`.
- `oob_first_offset: i32`.

Plus the bundle's standard fields (`target.hash`, `gadget_id`,
`gadget_hash`, `proof.system`, `proof.verifier_key_hash`).
