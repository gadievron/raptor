# ZKPoX Phase 0 — Research Spike

Throwaway prototype tree. **Not** part of RAPTOR's runtime surface. Source material
for the Phase 1 PR if the spike's go/no-go answers are positive.

Plan: `docs/proposals/raptor-zkpox-design.md`. Findings (written at end of spike):
`docs/research/zkpox-phase0-findings.md`.

## Four go/no-go questions

1. Does SP1 prove a real C buffer overflow on a 100-LOC program in under 30 min CPU-only?
2. Is the LLVM-IR-mode shortcut empirically 50–100× cheaper than RISC-V mode?
3. Does `tlock-rs` round-trip a witness encrypt/decrypt cleanly with a layered vendor key?
4. Is the violation-gadget abstraction stable across ≥3 bug shapes without harness rewrites?

## Bench environment

- **Primary:** Mac (Apple Silicon, CPU only). SP1 has arm64 host support; proving
  is unaccelerated here — expect the worst-case wall-clock numbers.
- **CI target (planned):** GitHub Actions `ubuntu-latest` (x86_64). Phase 0 commits
  the harness in a way that builds clean on Linux too; CI integration itself is
  Phase 1.

Why both: a number that's tolerable on the maintainer's laptop is also tolerable
in CI; a number that's painful here may still be fine on a beefier x86_64 runner.
We want the laptop number as the conservative anchor.

## Toolchain (target)

| Tool                | Why                                       | Install                       |
|---------------------|-------------------------------------------|-------------------------------|
| Rust (stable)       | SP1 host + guest                          | `curl https://sh.rustup.rs \| sh` |
| `cargo prove` (SP1) | The zkVM itself                           | `curl -L https://sp1up.succinct.xyz \| bash && sp1up` |
| LLVM `opt`/`llc`    | Emit and inspect bitcode for IR-mode      | `brew install llvm`           |
| `tlock` (Drand)     | Time-lock encrypt witnesses               | Rust crate via cargo          |
| `age`               | Layered vendor-key encryption             | `brew install age`            |

## Layout

```
targets/      Synthetic vulnerable C programs (~50–100 LOC each).
witnesses/    Hand-crafted PoC inputs (benign + crashing pairs).
harness/      Rust SP1 workspace. NOT a RAPTOR Cargo workspace member.
  guest/      Compiled to RISC-V, runs inside the zkVM.
  host/       Native, drives the prover.
  gadgets/    Violation predicates: crash_only, oob_write, stack_canary.
envelope/     Phase 0 spike of the disclosure bundle.
  tlock_roundtrip.py   Encrypt-now / decrypt-later sanity check.
  bundle_proto.py      Throwaway CBOR shape; real schema is Phase 1.
bench.py      Wall-clock × peak RSS × proof bytes table generator.
```

## Run order

```sh
# 1. Prove targets natively crash / don't crash with their witnesses.
make -C targets verify

# 2. Build SP1 guest + host (after toolchain install).
cargo build --release --manifest-path harness/Cargo.toml

# 3. Prove each (target × gadget × witness) tuple, recording timings.
python3 bench.py --output ../zkpox-phase0-findings.md

# 4. Envelope round-trip.
python3 envelope/tlock_roundtrip.py
```
