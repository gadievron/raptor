# ZKPoX -- Proof of Exploit

[Documentation index](README.md)

ZKPoX proves the statement "I possess an input that makes binary H exhibit
outcome O" -- ultimately without revealing the input itself. The verifier
learns that a working, reproducing exploit exists; they do not learn the
exploit bytes. Use cases: coordinated disclosure (prove capability before a
patch lands), bug-bounty triage, and escrowing exploit existence.

**That is the design goal.** The implemented tiers provide attestation and
sandboxed reproduction. Current bundles contain the witness bytes, so sharing
one can disclose the exploit or crashing input. Zero-knowledge proof generation
and witness-hiding verification are not implemented yet.

It is a downstream consumer of the witness substrate: any run that records
witnesses (`/fuzz`, `/agentic`, crash analysis) produces candidates.


Use the run summary to find eligible witnesses, assemble a bundle, then
reproduce it if you need an execution check. Run the helper commands below
in a terminal from the RAPTOR checkout. See [fuzzing](fuzzing.md) and
[validation](validation.md) for the upstream evidence workflows.

**Related documentation:**
[Fuzzing](fuzzing.md) |
[Validation](validation.md) |
[Security](security.md)

**On this page:**

- [Tiers](#tiers)
- [Free eligibility surfacing](#free-eligibility-surfacing)
- [Bundle assembly (Tier 0/1)](#bundle-assembly-tier-01)
- [Reproduction (Tier 1.5)](#reproduction-tier-15)

## Tiers

The design stages proving by dependency weight. The implemented tiers provide
attestation and reproduction; the planned tiers would add deterministic
execution evidence and zero-knowledge verification.

| Tier | Claim | Dependencies | Status |
|------|-------|--------------|--------|
| 0/1 | Attestation: "I assert witness W produced outcome O against H", carried by provenance hashes | none | implemented |
| 1.5 | Reproduction: W re-executed against H N times in the sandbox; O reproduces | sandbox only | implemented (on request) |
| 2 | Deterministic trace via RISC-V emulation | RISC-V toolchain | planned; not implemented |
| 3 | Full zero-knowledge STARK proof (SP1 zkVM); input stays hidden | heavy proving stack | planned; not implemented |

Attestation alone is not independent proof that the witness works. Tier 1.5
checks reproducibility; it does not hide the witness. Both operations run
when requested.


## Free eligibility surfacing

Eligibility classification is free (pure field-reading, no execution). Runs
that record witnesses print it in their end-of-run summary without any flag:

```
ZKPoX-eligible witnesses: 2 / 7
   provable:             2
   outcome_not_provable: 4
   no_target:            1
```

Zero eligible witnesses means no candidate qualifies for bundle assembly.
Bundle assembly and reproduction are on request.


## Bundle assembly (Tier 0/1)

```
libexec/raptor-zkpox bundle <witness_store> <witness_hash> --out <dir>
```

`<witness_store>` is a run's witness store root (typically
`<run_out_dir>/witnesses/`); `<witness_hash>` is the SHA-256 of the witness
bytes as recorded in the store's `manifests/`. The command assembles a
reproduction bundle -- witness bytes plus a provenance manifest -- under
`<dir>/zkpox/<witness_hash>/`. Reproduction consumes this bundle. The bundle is also the intended hand-off
for the planned higher tiers; their consumers are not implemented yet.


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
