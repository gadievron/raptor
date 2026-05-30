---
description: ZKPoX — zero-knowledge proof of exploit (beta). Subcommands: eligible / bundle / reproduce / prove / verify.
---

# /zkpox — Zero-Knowledge Proof of Exploit (beta)

Single dispatcher for every ZKPoX tier. Eligibility is FREE; bundle,
reproduction, prove, and verify are ON-REQUEST. **Read
`docs/zkpox-scope.md` first** — it states precisely what the MVP
proves and what it does NOT prove. Companion skill: `.claude/skills/zkpox/`.

## Subcommands

```
/zkpox eligible      Tier 0       free pre-flight signal (which witnesses qualify)
/zkpox bundle <w>    Tier 0/1     assemble prover-ready bundle (shipped)
/zkpox reproduce <b> Tier 1.5     N× sandbox reproduction      (shipped)
/zkpox prove <b>     Tier 2/3     the heavy SP1 STARK proof    (beta; #470)
/zkpox verify <p>    Tier 2/3     check a CBOR disclosure bundle (beta; #470)
```

Every subcommand routes through `python3 raptor.py zkpox <sub>`
which delegates to `libexec/raptor-zkpox`. `bundle`, `reproduce`, and
`prove` are wrapped in the run lifecycle (project-scoped outputs);
`eligible` and `verify` are read-only and bypass it.

## Tier ladder

A bundle dir grows progressively richer:

```
out/zkpox/<witness_hash>/
   manifest.json        # Tier 0/1 attestation (after /zkpox bundle)
   witness.bin          # the witness bytes
   manifest.json        # …updated with reproduction.* + tier="1.5"  (after /zkpox reproduce)
   proof.bin            # SP1 STARK proof                            (after /zkpox prove)
   prove-record.json    # bench + verifier-side metadata             (after /zkpox prove)
   bundle.cbor          # full Phase 1.5 disclosure bundle           (after /zkpox prove)
```

`reproduce` doesn't need the proving stack. `prove` does — the
underlying `cargo-prove` / SP1 toolchain is gated by
`packages.zkpox.require_proving_stack`; a bare box gets an actionable
`ProvingStackUnavailable` rather than a vague binary-not-found.

## Common flows

```bash
# 1. What's worth proving? (free; no flags needed)
python3 raptor.py zkpox eligible --run-dir out/run-2026-05-26/

# 2. Pick one and assemble its Tier 0/1 bundle.
python3 raptor.py zkpox bundle out/run-2026-05-26/witnesses <hash> \
    --out out/disclosure-001/

# 3. Confirm it reproduces (Tier 1.5).
python3 raptor.py zkpox reproduce out/disclosure-001/zkpox/<hash>/ --n 5

# 4. Produce the real ZK proof (Tier 2/3 — heavy, ~17 min on CPU).
#    prove takes the BUNDLE DIR — it reads witness.bin, the target
#    hash, the outcome, and the Tier 1.5 reproduction evidence straight
#    from manifest.json. proof.bin / bundle.cbor land in the bundle dir.
#    Bundle binds to the real SP1 vkey + guest ELF + gadget code hash
#    (no placeholders since Phase 1.5.1).
python3 raptor.py zkpox prove out/disclosure-001/zkpox/<hash>/ \
    --target ./vulnerable-binary \
    --vendor-pubkey "$(cat vendor.age.pub)" \
    --gadget-id "memory-safety::oob-write@0.1.0"

# 5. Verify the produced bundle. Strict by default since Phase 1.5.4 —
#    STARK verification (1.5.2) and structural checks must all pass.
#    Pass --no-strict to skip DEFERRED checks (currently: Rust offline
#    Rekor inclusion, pending the bundle schema extension in 1.5.3.x).
python3 raptor.py zkpox verify out/disclosure-001/zkpox/<hash>/bundle.cbor
```

`--target` is optional: when supplied, its sha256 is reconciled against
the manifest's recorded target hash (a mismatch is a hard error — the
proof can't silently bind to a different artifact than the one
triaged/reproduced). Omit it to trust the manifest's hash.

For the full `prove` / `verify` flag list, run:

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

**Beta — Phase 1.5.4.** The Phase 1.5.x credibility-gap work is
complete on the producer side and on the Python verify path:

- **Phase 1.5.1** — `proof.verifier_key_hash` binds to the real SP1
  vkey, `harness.hash` to the real guest ELF, and `gadget_code_hash`
  to the gadget's declared file manifest. No placeholders.
- **Phase 1.5.2** — the standalone Rust verifier (`full-verify`
  feature, default) re-derives the vkey from an embedded guest ELF,
  checks the bundle's hashes against it, and runs the SP1 STARK
  verification on the proof bytes.
- **Phase 1.5.3** — Python anchor verification does RFC 6962 Merkle
  inclusion + Rekor v1 SET (Signed Entry Timestamp) signature
  validation against an operator-pinned log pubkey.
- **Phase 1.5.4** — `--strict` is the default verifier behaviour;
  `--allow-placeholder-hashes` removed; "do NOT use for real
  disclosure" framing dropped.

Still labelled "experimental" because the broader ecosystem (SP1
zkVM, Rekor v2 witnessing model, Sigstore TUF) is still evolving and
because **Rust-side offline Rekor inclusion verification** is still
DEFERRED — pending a small bundle schema extension to carry the entry
body bytes (Phase 1.5.3.x). Operators verifying anchored bundles via
the standalone Rust verifier need `--no-strict` until that lands; the
Python verify path with `log_pubkey_pem` already does the full
inclusion + SET check.

Background: `docs/proposals/raptor-zkpox-design.md`,
`docs/proposals/zkpox-phase-1.5.x.md`, `docs/zkpox-scope.md`.
