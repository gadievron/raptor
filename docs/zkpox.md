# ZKPoX -- Proof of Exploit

ZKPoX consumes recorded witnesses and supports attestation, native reproduction
and optional zero-knowledge disclosures. The current SP1 guest proves canary
violations for three exact curated C sources; it does not prove arbitrary
native binaries. See the [precise scope](../packages/zkpox/docs/zkpox-scope.md)
and [setup and CLI guide](../packages/zkpox/README.md).

Generic witness storage lives in `core/witness`; all ZKPoX-specific orchestration,
Rust guest, prover and verifier live in `packages/zkpox`.

## Tiers

| Tier | Claim | Dependencies | Status |
|------|-------|--------------|--------|
| 0/1 | Recorded attestation and provenance | none | implemented |
| 1.5 | Native witness re-executed under the sandbox; observed outcome reproduced | sandbox | implemented |
| Execute | Deterministic execution of a curated C source in SP1 | built native executor | implemented |
| Disclosure | Positive selected canary predicate, exact curated source and hiding witness commitment, verified with SP1 6.5.0 Groth16 | built native prover/verifier and provisioned circuits | implemented |

Core proofs are an internal diagnostic format, not zero-knowledge disclosures.
Public verification separately labels encrypted delivery as unchecked until
opened, and optional log inclusion must be explicitly authenticated against a
pinned log key. Rekor v2 inclusion alone does not provide a timestamp.


## Free eligibility surfacing

Eligibility classification is free (pure field-reading, no execution). Runs
that record witnesses print it in their end-of-run summary without any flag:

```
ZKPoX-eligible witnesses: 2 / 7
   provable:             2
   outcome_not_provable: 4
   no_target:            1
```

Zero eligible witnesses means the heavier tiers are not worth setting up for
that run. Everything beyond this summary is on request.


## Bundle assembly (Tier 0/1)

```
libexec/raptor-zkpox bundle <witness_store> <witness_hash> --out <dir>
```

`<witness_store>` is a run's witness store root (typically
`<run_out_dir>/witnesses/`); `<witness_hash>` is the SHA-256 of the witness
bytes as recorded in the store's `manifests/`. The command assembles a
prover-ready bundle -- witness bytes plus a provenance manifest -- under
`<dir>/zkpox/<witness_hash>/`. The bundle shape is the stable hand-off every
higher tier consumes.


## Reproduction (Tier 1.5)

```
libexec/raptor-zkpox reproduce <bundle_dir> [--binary <path>] [--n N]
```

Re-runs the bundle's witness N times (default 3) in the sandbox and confirms
the recorded outcome reproduces. Reproduction is source-dispatched:

- **Exploit-source witnesses** (LLM-emitted PoCs): the witness bytes are
  source code -- each run recompiles and executes it. If the recorded outcome
  was a sanitizer report, the recompile uses the matching `-fsanitize` flag
  so the sanitizer can fire again.
- **Input-replay witnesses** (fuzzing crashes): the witness bytes are input
  to a target binary, fed via stdin. Pass the binary with `--binary`; its
  SHA-256 must match the bundle's recorded `target_binary_hash`, otherwise
  the run is refused.

The bundle is integrity-checked first: a `witness.bin` whose hash or length
disagrees with the manifest is refused rather than reproduced.

The verdict is judged over the runs that actually executed the target. A run
whose child never reached the target (a spawn failure such as a transient
`ETXTBSY`) is retried once and then excluded from the verdict instead of
being counted as a divergent outcome; the executed-vs-planned count is kept
in the result. `reproduced` requires every executed run to match the recorded
outcome, with at least one executed run. Each run's lane and outcome shape is
printed as a per-run diagnostic line, so a divergent run is diagnosable
straight from the report.

On success the reproduction record is folded into the bundle's
`manifest.json` and the bundle tier is bumped to 1.5.

Exit codes: `0` reproduced, `1` attempted but did not reproduce
(including when every planned run was excluded as a spawn failure —
the result then names `no run executed`), `2` could not attempt (bad
bundle, missing or mismatched binary).
