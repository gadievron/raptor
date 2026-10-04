---
description: ZKPoX — zero-knowledge proof of exploit (beta). Subcommands: prove / verify. Tier 0/1 (eligible / bundle / reproduce) live in libexec/raptor-zkpox.
dispatch: python3 raptor.py zkpox
---

# /zkpox — Zero-Knowledge Proof of Exploit (beta)

The Tier 2/3 driver: turn an exploit witness into an SP1-backed
zero-knowledge proof bundle (`prove`), and check a produced bundle
(`verify`). **Read `packages/zkpox/docs/zkpox-scope.md` first** — it is
the source of truth for what the MVP proves and what it does NOT prove.
Companion skill: `.claude/skills/zkpox/`.

## Subcommands

```
/zkpox prove   Tier 2/3   the heavy SP1 STARK proof      (beta; #470)
/zkpox verify  Tier 2/3   check a CBOR disclosure bundle (beta; #470)
```

Both route through `python3 raptor.py zkpox <sub>` →
`raptor_zkpox.py`. `prove` is wrapped in the run lifecycle
(project-scoped outputs); `verify` is read-only.

**The dependency-free tiers have their own CLI** — the Tier 2/3
proving stack is not needed for them:

```
libexec/raptor-zkpox bundle <witness_store> <hash> --out <dir>   Tier 0/1: assemble a prover-ready bundle
libexec/raptor-zkpox reproduce <bundle_dir> [--n 3]              Tier 1.5: N× sandbox reproduction
```

The `prove` and `verify` subcommands gate the SP1 / RISC-V proving
toolchain through `packages.zkpox.require_proving_stack`; a host
without it gets an actionable `ProvingStackUnavailable` rather than a
vague binary-not-found. `--help` and the dependency-free tiers stay
usable without the toolchain.

## Tier ladder

A bundle dir grows progressively richer:

```
out/zkpox/<witness_hash>/
   manifest.json        # Tier 0/1 attestation      (after raptor-zkpox bundle)
   witness.bin          # the witness bytes
   manifest.json        # …+ reproduction.* tier="1.5"  (after raptor-zkpox reproduce)
   proof.bin            # SP1 STARK proof            (after /zkpox prove)
   prove-record.json    # bench + verifier metadata  (after /zkpox prove)
   bundle.cbor          # full disclosure bundle      (after /zkpox prove)
```

## Common flows

```bash
# 1. Assemble a Tier 0/1 bundle (dependency-free).
libexec/raptor-zkpox bundle out/run/witnesses <hash> --out out/disclosure-001/

# 2. Confirm it reproduces (Tier 1.5).
libexec/raptor-zkpox reproduce out/disclosure-001/zkpox/<hash>/ --n 5

# 3. Build the Rust prover + verifier.
cargo build --release --manifest-path core/zkpox/Cargo.toml

# 4. Produce the ZK proof (Tier 2/3 — heavy, ~17 min on CPU).
#    Phase 1.5 writes placeholder verifier_key_hash / harness.hash;
#    --allow-placeholder-hashes acknowledges they are NOT real-disclosure
#    grade until Phase 1.5.x. The bundle prints a loud warning on verify.
python3 raptor.py zkpox prove \
    --witness ./crashes/crash-001 \
    --target ./vulnerable-binary \
    --vendor-pubkey "$(cat vendor.age.pub)" \
    --gadget-id "memory-safety::oob-write@0.1.0" \
    --allow-placeholder-hashes \
    --out out/disclosure-001/

# 5. Verify the produced bundle.
python3 raptor.py zkpox verify out/disclosure-001/bundle.cbor
```

For the full `prove` / `verify` flag list:

```bash
python3 raptor.py zkpox prove --help
python3 raptor.py zkpox verify --help
```

## Standalone use without RAPTOR

The verifier binary is intentionally usable without the Python toolchain:

```bash
./core/zkpox/target/release/zkpox-verify path/to/bundle.cbor
```

Same exit-code semantics (0 = pass, 1 = structural fail, 2 = argument error).

## Status

**Beta — Phase 1.5.** `prove` produces a bundle whose
`verifier_key_hash` and `harness.hash` are PLACEHOLDERS (acknowledged
with `--allow-placeholder-hashes`); Phase 1.5.x wires the real SP1
verifying-key digest and harness hash. `verify` runs structural checks
today; SP1 STARK verification and Sigstore Rekor Merkle-inclusion are
deferred to 1.5.x. See `/prove-exploit` and `/verify-exploit-proof` for
the per-subcommand detail.

Background: `packages/zkpox/docs/raptor-zkpox-design.md`,
`packages/zkpox/docs/zkpox-phase-1.5.x.md`,
`packages/zkpox/docs/zkpox-scope.md`.
