# Violation Gadget: `crash-only`

The simplest gadget. Returns true iff the modeled program would have
aborted on the witness.

## Gadget ID

`crash-only@0.1.0`

## What it proves

"On this witness, the C target trips the gadget's abort signal." For
memory-safety targets that abort signal is the ASan-style sentinel
canary check our Rust wrapper runs after the C `victim` returns.

## What it leaks

Nothing beyond the bundle's other public fields (target hash, gadget
id, gadget hash). The Public output is a single `bool`.

## Detection mechanism (Phase 1 implementation)

Uniform 0xA5 canary fill in the leading + trailing redzones around the
C-supplied buffer. Post-call scan: any redzone byte ≠ 0xA5 → crashed.

This is the **naive baseline** — vulnerable to a witness that
deliberately writes 0xA5 into the redzone bytes (`-canarymatch-*-fn`
in the test corpus). The `memory-safety::oob-write` gadget covers
that case with a position-varying pattern.

## Cost (rough, target #1)

- Cycles: ~6,500 per witness (single C call).
- Prove time on this Mac, `--wrap=core`: ~17 s warm pk.
- Prove time on this Mac, `--wrap=groth16`: ~17 min total.
- Proof bytes: ~2.65 MB (core) / ~1.7 KB (groth16, bundle-friendly).

## When to use it

- Low-severity bugs where "the program crashes on this input" is
  enough. Many disclosure bundles don't need more.
- Initial proof while the disclosure pipeline is being shaken out.

## When NOT to use it

- An attacker who controls witness bytes might deliberately write the
  canary value to evade detection. For adversarial conditions use
  `memory-safety::oob-write` (position-varying pattern + structured
  outputs) or wait for the Phase 1.x shadow-allocation-table gadget.
- Memory corruption that doesn't reach the redzone (e.g. a write at a
  specific offset within the buffer that flips a privileged bit) won't
  trigger `crash-only`. Use a more specific gadget if available.

## Public outputs

In the bundle's `proof.bytes` STARK / Groth16 wrap, the public values
include:

- `crash_only_crashed: bool` — the gadget verdict.

Plus the bundle's standard fields (`target.hash`, `gadget_id`,
`gadget_hash`, `proof.system`, `proof.verifier_key_hash`).
