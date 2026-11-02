---
description: ZKPoX — witness eligibility, private bundles, reproduction and curated SP1 disclosure proofs (beta).
dispatch: python3 raptor.py zkpox
---

# /zkpox

Run `python3 raptor.py zkpox <subcommand> <arguments>`.
The dispatcher delegates to the canonical CLI in `packages/zkpox/cli.py`.
Read `packages/zkpox/docs/zkpox-scope.md` for the precise proof claim and
`packages/zkpox/README.md` for setup and complete workflows.

| Subcommand | Arguments | Behavior |
| --- | --- | --- |
| `eligible` | `--run-dir DIR [--project-root DIR]` | Read eligibility, with no execution or artifacts |
| `bundle` | `STORE WITNESS_HASH --out DIR` | Assemble a private Tier 0/1 witness bundle |
| `reproduce` | `BUNDLE_DIR [--binary FILE] [--n 3] [--timeout 5]` | Reproduce under RAPTOR's sandbox; update the private manifest |
| `prove` | `BUNDLE_DIR --target {01,02,03} [--gadget {crash_only,oob_write}] --out SEPARATE_DIR` | Produce a real Groth16 disclosure for an exact curated C source |
| `verify` | `BUNDLE_CBOR [--json]` | Require actual proof verification and a positive selected predicate |
| `inspect` | `BUNDLE_CBOR [--json]` | Read metadata without claiming verification |
| `open` | `BUNDLE_CBOR (--identity FILE OR --after-release) --out NEW_PRIVATE_FILE` | Verify, decrypt and check the committed witness |

`bundle` and `prove` create runs through the lifecycle. `reproduce` updates the
existing private bundle directly. Eligibility, verification, inspection and
opening bypass run creation. Opening creates only the requested private file.

`prove` supports three curated sources and requires their exact source hash in
the private manifest. It does not prove arbitrary native binaries; use
`reproduce` for native evidence. The public output contains `bundle.cbor` and
`verification.json`; the witness, salt and raw bench record remain private.

Optional proving flags:

- `--vendor-pubkey AGE_RECIPIENT --tlock-duration 90d`: encrypt delivery to the
  vendor and a Drand release round. Public delivery remains unchecked until
  the recipient opens it and verifies the commitment.
- `--anchor --rekor-url HTTPS_URL --rekor-key PINNED_LOG_KEY_PEM --rekor-origin ORIGIN`:
  explicitly publish a Rekor v2 inclusion entry. This proves inclusion, not a
  timestamp. No log publication occurs by default.
- `--timeout SECONDS`: bound proof execution (default 7200).

`verify --require-anchor --rekor-key PINNED_LOG_KEY_PEM --rekor-origin ORIGIN`
requires authenticated Rekor v2 inclusion in addition to the proof.
The standalone Rust verifier checks the proof independently; it labels optional
log evidence and encrypted delivery separately rather than authenticating them
implicitly. A structural-only Rust build succeeds only with `--inspect`.

Run `python3 raptor.py zkpox <subcommand> --help` for the current argument parser.
