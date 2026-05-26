---
name: zkpox
description: Zero-knowledge proof of exploit. Convert a working exploit witness into a publicly-verifiable disclosure bundle (SP1 STARK + Groth16 wrap + age vendor envelope + Drand time-lock + Sigstore Rekor anchor) — the witness stays private; the proof is public.
user-invocable: false
---

# ZKPoX — Zero-Knowledge Proof of Exploit

Companion skill to `/zkpox` (subcommands: `eligible`, `bundle`,
`reproduce`, `prove`, `verify`).

## When to use this skill

Trigger this skill whenever:

- The user has a working exploit / PoC / AFL crash and wants a publicly
  shareable demonstration that protects exploit details.
- The user is preparing a coordinated vulnerability disclosure and
  needs to prove severity to a vendor or the public without arming
  attackers.
- `/agentic --with-disclosure` is invoked and an exploit has succeeded
  (Phase 1.5+; not yet wired).
- The user mentions ZK proofs, zero-knowledge, witness encryption,
  responsible disclosure, CVD, Project Zero, ZDI, Immunefi, Cheesecloth,
  SIEVE, or similar terms.

## When NOT to use this skill

- The PoC is for a **side-channel or speculative-execution** bug.
  ZKPoX models software, not microarchitecture. Tell the user explicitly.
- The vulnerability requires **concurrency / weak memory models**.
  Out of MVP.
- The user wants **witness encryption** ("decryptable by anyone with a
  valid exploit"). Not deployable in 2026 for arbitrary NP relations;
  the Garg-Gentry-Sahai-Waters construction relies on multilinear maps
  that are broken. Redirect to the time-lock + vendor-key flow that
  ZKPoX already provides.
- The target is a **web exploit** whose violation predicate depends on
  browser/server behaviour. RAPTOR's `/web` is labelled stub/alpha;
  ZKPoX inherits that limitation.

## Workflow

The five subcommands form a tier ladder; bail out at the earliest
tier that answers the operator's question.

1. **Pre-flight (free).** `python3 raptor.py zkpox eligible
   --run-dir DIR` — classifies which witnesses qualify for a proof.
   Pure field-reading, no execution. If nothing's eligible, stop here.
2. **Verify the witness reproduces the violation locally.** Run the
   target on the witness, observe the crash / state transition. If
   it doesn't reproduce, the proof can't prove anything.
3. **Pick a violation gadget** from
   `.claude/skills/zkpox/violation-gadgets/`. If none fit cleanly,
   ask before falling back to `crash-only`.
4. **Assemble the Tier 0/1 bundle.** `python3 raptor.py zkpox bundle
   <witness_store> <witness_hash> --out DIR` — attestation-only,
   no crypto yet; the substrate every higher tier reads.
5. **Confirm reproduction (Tier 1.5).** `python3 raptor.py zkpox
   reproduce <bundle_dir> [--n N]` — re-runs the witness N× in the
   sandbox, folds the result into the bundle manifest.
6. **Build the harness if needed.** Current Phase 1 supports
   freestanding C compiled to SP1's RISC-V via the cross-compile in
   `core/zkpox/guest/build.rs`. EVM, embedded, and binary-only modes
   are future phases.
7. **Run the prover (Tier 2/3).** `python3 raptor.py zkpox prove
   --witness PATH --out DIR [...]`. Stream progress; the Groth16
   wrap can take 15+ minutes on CPU. Gated by
   `packages.zkpox.require_proving_stack` — fires
   `ProvingStackUnavailable` with an actionable message if the
   SP1 / RISC-V toolchain isn't installed.
8. **Vendor envelope (default).** Pass `--vendor-pubkey AGE_PUBKEY` to
   encrypt the witness to the vendor's age public key and to a Drand
   future round (default 90 d, the Project Zero norm).
9. **Anchor the bundle.** Default `--anchor` (on); set `--no-anchor`
   to skip Sigstore Rekor anchoring.
10. **Hand the bundle off.** `bundle.cbor` is the public artefact.
    Verifiers run `python3 raptor.py zkpox verify <bundle.cbor>` or
    the standalone `core/zkpox/target/release/zkpox-verify` binary.

## Files this skill writes

All under the user's chosen output directory:

- `bundle.cbor` — the disclosure bundle (proposal § 8 schema).
- `proof.bin` — the raw SDK-saved proof artefact (also embedded in
  the bundle's `proof.bytes` field).
- `prove-record.json` — bench metadata from the prover run.

## Where the implementation lives

```
core/zkpox/                     Rust workspace
├── guest/                      SP1 guest (runs inside the zkVM)
├── prover/                     native CLI: zkpox-prove
└── verifier/                   standalone CLI: zkpox-verify

packages/zkpox/                 Python orchestration
├── eligibility.py              Tier 0 — free witness classification
├── bundle.py                   Tier 0/1 — bundle assembly + persistence
├── reproduce.py                Tier 1.5 — N× sandbox reproduction
├── envelope.py                 AES + age + tle layered crypto
├── anchor.py                   Sigstore Rekor anchoring
├── prove.py                    Wrapper around zkpox-prove (Tier 2/3)
├── surfacing.py                Free end-of-run eligibility block
└── proving_deps.py             SP1 / RISC-V stack availability gate

libexec/raptor-zkpox            Operator CLI; the /zkpox dispatcher
raptor_zkpox.py                 Tier 2/3 driver (prove + verify)
```

## Trust model (proposal § 9, condensed)

- **Verifiers trust:** the zkVM verifier binary, hash functions and
  curves (SHA-256, BN254 for Groth16), the `target.hash` they care
  about, the Sigstore Rekor log (or an alternate log of their choice).
- **Verifiers do NOT trust:** the researcher, RAPTOR, the vendor.
  Verification works without any of them installed.
- **Researchers trust:** their own machine, the SP1 prover (audited
  by Veridise/Cantina/Zellic/KALOS for v6), the vendor's published
  encryption key.

## Phase status as of 1.5

Implemented: 1.1–1.4 + the command surface (1.5). The Rust verifier
is structural; full STARK + Rekor Merkle inclusion verification lands
in 1.5.x. The CBOR schema, envelope round-trip, and Rekor anchoring
all work end-to-end.

Bench numbers and the seven Phase-0 gotchas + the Phase-1 follow-ons
are documented in `docs/research/zkpox-phase0-findings.md`.
