---
name: binary-oracle
description: Binary-oracle reachability — flag surface, env build-on-demand, corpus evidence, hostile-binary defenses, audit trail, verification harnesses
user-invocable: false
---

# Binary-Oracle Reachability (reference)

The always-loaded contract (default-on behaviour, verdict enum, the
provenance-drop consent decision, and the non-interactive fallback) lives in
CLAUDE.md § BINARY-ORACLE REACHABILITY. This file is the full reference for
everything else.

## How the join works

When a debug binary is declared (or auto-detected), RAPTOR joins the source
inventory with it via DWARF + nm and annotates each native (C/C++/Rust/Go)
function with a per-binary verdict:

- `symbol_present` / `inlined` / `folded` — the function survived compilation in some form
- `absent` — the compiler / linker removed it from the analysed binary

`absent` is corpus-earned for suppression: **1952/1952 absent verdicts correct
across 6 iteratively-tuned corpora (consistency) + 187/187 absent verdicts
correct on the held-out zstd v1.5.6 corpus with NO classifier tuning
(generalization)** — rule-of-three 95% UB on miss rate ≤1.6% on
first-contact-with-unseen-data. The held-out is non-vacuous: 473/1431
functions exercised by the workload, zero `absent` verdicts on actually-live
functions. Conditional on full-DWARF evidence — a stripped binary in the
analysed set downgrades to `tier="symbol_only"` and the chokepoint refuses to
suppress.

The verdict flows through the existing reachability chokepoint: /codeql +
/agentic skip LLM analysis on absent-function findings (pre-LLM
hard-suppress); /validate's demoter clamps attack-path proximity; /understand
--map annotates entry-points and sinks with the per-binary verdict + tier.

## Operator usage

- (default, no flags) — auto-detect runs, filters to locally-built binaries
  (git-untracked) only, soft hint when nothing found. **Env build-on-demand:**
  when auto-detect AND the project binary store both find nothing and the
  project `build` trust marker authorises build execution, the oracle builds a
  debug binary itself (operator `build-command` slot first, detector synthesis
  second; network-isolated container; run-local artifact with a
  `/project binary add` persist hint). Suppression authority follows who chose
  the configuration: an operator-set build command earns `absent`-suppression
  like any declared binary; a detector-GUESSED command enriches
  (symbol_present/inlined, reachability promotion) but `earns_suppression`
  downgrades (`any_env_built_guessed` in the inventory summary) — a guessed
  container configuration can compile out features the real build includes.
  The `build` marker also defaults env build-on-demand where its flag pair
  exists (`--env-build`/`--no-env-build`).
- `--binary <path>` — pass an explicit debug binary. Repeatable for hybrid
  targets. Path validated at parse time. Bypasses the git-tracked filter
  (operator asserts trust). Suppresses default auto-detect.
- `--binary-auto` — same auto-detect + git-filter logic as the default-on
  path, but with a louder "nothing found" message. Honours `--target-kind`.
  Warns when the result cap (8) is reached. Auto-detected dirs: `build/`,
  `target/release/`, `cmake-build-*/`, `bazel-bin/`, `builddir/`, `Debug/`,
  `Release/`, `out/`, `dist/`, `bin/`, Rust `target/<triple>/release`
  cross-target globs, and the source root.
- `--no-binary-oracle` — disable binary-oracle filtering entirely for this
  run. Use for library-only targets with no main binary, runs where you want
  every finding unfiltered for review, or when a build mismatch is causing
  over-suppression. Overrides `--binary` / `--binary-auto` with a stderr
  warning if combined.
- `--binary-edges` — Inc 2b Tier 1/2: extract direct call edges + vtable
  resolution via r2 (single-invocation script-file mode; cached per-build-id
  with cross-target collision check). Slow (~10-30s per binary, then cached).
  Required for the `binary_call_edge` REACHABLE promote witness (rescues
  functions the source-graph thought were dead).
- For `--target-kind=hybrid` deployments (library + application both
  shipped), declare MULTIPLE binaries — a function is `absent` only when
  EVERY declared binary lacks it. Tier-weighted combine: when full-DWARF and
  symbol-only disagree, full-DWARF wins (`alive-in-any` rule only applies
  same-tier).

## Persistent per-project config

- `/project binary add <path>` — persist a binary path on the active project.
  Auto-loaded by every subsequent /agentic / /codeql / /validate run.
  `is_file()`-validated at add time.
- `/project binary list` / `remove` / `clear` — manage the persisted list.

## Audit trail

- `suppressions.jsonl` is written to the run's output directory whenever the
  chokepoint hard-suppresses a finding. One JSON record per suppression with
  `finding_id`, `rule_id`, `file_path`, `line`, `function`, `verdict`,
  `reason`, `dropped` (`false` marks records for findings that survived to
  the LLM; consumers must tolerate extra keys). Query with
  `jq -c . suppressions.jsonl`. /agentic, /codeql, and /audit (oracle-earned
  and vendored/generated triage decisions) write the same file shape.
- The classifier's per-finding analysis record also carries
  `analysis.reachability_suppression: true` +
  `analysis.reachability_verdict: <verdict>` for per-finding inspection.

## Defenses against hostile / wrong-binary scenarios

- Provenance gate on auto-detect: binaries tracked by git (committed to the
  source tree) are dropped — only locally-built artifacts (untracked files
  under build/, target/release/, etc.) feed the oracle. Defends against
  attacker-planted binaries and stale committed pre-builds that would
  silently steer `absent` verdicts toward suppressing real findings.
  Operator can bypass via explicit `--binary <path>` when they know a
  tracked binary is trustworthy.
- Source-coverage floor (≥5% of project source names matched, min 3 matched,
  kicks in at ≥8 project names) — a planted ELF unrelated to source gets
  dropped with a loud warning rather than driving every source function to
  `absent`.
- Sandbox isolation: r2 runs under `core.sandbox.run` (namespace + Landlock +
  network deny); the oracle's binutils invocations (readelf, nm, objdump,
  c++filt) run under the full sandbox as well.

## E2E + precision verification

- `core/analysis/scripts/binary-oracle-e2e` — single-invocation audit that
  builds a real C target and walks 14 consumer surfaces (~50 assertions). No
  LLM calls. Run with `CLAUDECODE=1 core/analysis/scripts/binary-oracle-e2e`.
  (Verification harnesses live in a `scripts/` subdirectory beside the code
  they audit — never on the `libexec/` LLM dispatch surface.)
- `core/analysis/scripts/binary-oracle-precision --corpus <name>` —
  re-measure absent-precision on any corpus driver
  (synthetic/zlib/libsodium/snappy/leveldb/regex-rust/zstd_holdout). Report
  includes per-corpus cross-tab (classifier × gcov live/dead), aggregate
  with rule-of-three UB, n-concentration dominator detection, and the
  toolchain block (cc/gcov/llvm-cov versions) so the precision number is
  reproducible.

## Code locations

`core/analysis/binary_oracle.py` (classifier),
`core/analysis/binary_oracle_autodetect.py` (auto-detect),
`core/analysis/binary_oracle_precision.py` (measurement harness — the
`core/analysis/scripts/binary-oracle-precision` shim runs it).
