---
name: zkpox
description: Zero-knowledge proof of exploit. Convert a working exploit witness into a publicly-verifiable disclosure bundle (SP1 STARK + Groth16 wrap + age vendor envelope + Drand time-lock + Sigstore Rekor anchor) — the witness stays private; the proof is public.
user-invocable: false
---

# ZKPoX — Zero-Knowledge Proof of Exploit

Companion skill to `/prove-exploit` and `/verify-exploit-proof`.

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

1. **Verify the witness reproduces the violation locally.** Run the
   target on the witness, observe the crash / state transition. If it
   doesn't reproduce, the proof can't prove anything.
2. **Pick a violation gadget** from `.claude/skills/zkpox/violation-gadgets/`.
   If none fit cleanly, ask before falling back to `crash-only`.
3. **Build the harness if needed.** Current Phase 1 supports
   freestanding C compiled to SP1's RISC-V via the cross-compile in
   `core/zkpox/guest/build.rs`. EVM, embedded, and binary-only modes
   are future phases.
4. **Run the prover.** `python3 raptor.py prove-exploit --witness PATH
   --out DIR [...]`. Stream progress; the Groth16 wrap can take 15+
   minutes on CPU.
5. **Vendor envelope (default).** Pass `--vendor-pubkey AGE_PUBKEY` to
   encrypt the witness to the vendor's age public key and to a Drand
   future round (default 90 d, the Project Zero norm).
6. **Anchor the bundle.** Default `--anchor` (on); set `--no-anchor` to
   skip Sigstore Rekor anchoring.
7. **Hand the bundle off.** `bundle.cbor` is the public artefact.
   Verifiers run `python3 raptor.py verify-exploit-proof` or the
   standalone `core/zkpox/target/release/zkpox-verify` binary.

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
├── envelope.py                 AES + age + tle layered crypto
├── bundle.py                   CBOR producer/parser + Timestamp
├── anchor.py                   Sigstore Rekor anchoring
└── prove.py                    Wrapper around zkpox-prove

raptor_zkpox.py                 Standalone driver (called by raptor.py)
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
