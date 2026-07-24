# SAGE persistent memory usage

Loaded on demand by RAPTOR's root `CLAUDE.md` when the `sage_inception`
MCP tool is present (i.e. when the user has run `libexec/raptor-sage-setup`).
If this file is loaded, SAGE is available — use it.

## Boot sequence

1. Call `sage_inception` to initialize persistent memory.
2. Call `sage_turn` every turn with the current topic + observation.
3. Call `sage_reflect` after significant tasks with dos and don'ts.

## Domains

- `raptor-findings-{repo_key}` — CodeQL build reliability (repo-scoped)
- `raptor-fuzzing` — Fuzzing strategies and crash outcomes
- `raptor-sca-{repo_key}` — SCA findings and verdicts (repo-scoped)
- `raptor-methodology` — Analysis methodology and expert reasoning
- `raptor-fp-{repo_key}` — Finding verdicts for cross-run FP suppression (repo-scoped)
- `raptor-concepts` — Study concept recall (N1, planned)

## Domain rationale

- Use repo-scoped domains for target-specific outcomes that should not leak across projects.
- Keep `raptor-methodology` global because build/debug/analysis heuristics often generalise across repos and languages.
- Store fuzzing strategy outcomes in `raptor-fuzzing` to preserve semantic recall across similar binaries.

## Mechanical hooks (core/sage/hooks.py)

Every SAGE hook makes a hard decision — skip, suppress, reorder, set a
flag. No prompt injection (recalled text dropped into an LLM prompt).

| Hook | What it does | Domain |
|------|-------------|--------|
| `recall_context_for_sca` / `store_sca_outcomes` | Short-circuit: skip LLM for confirmed-malicious packages | `raptor-sca-{key}` |
| `recall_context_for_fuzzing_strategy` / `store_fuzzing_strategy_outcome` | Mechanical AFL flag inference from prior strategy rows | `raptor-fuzzing` |
| `infer_afl_fuzz_flags_from_sage_recall_row` | Derive `-L 0`, `-D`, `-p explore` from recall content | (utility) |
| `recall_context_for_codeql_build` / `store_codeql_build_reliability` / `infer_codeql_build_from_sage_recall_row` | Recall prior CodeQL build outcomes; mechanically infer build command from successful priors | `raptor-methodology` |
| `recall_prior_finding_verdict` / `store_finding_verdict` | Cross-run FP suppression: skip LLM for findings with a prior false_positive/not_exploitable verdict and unchanged source | `raptor-fp-{key}` |
| `compute_finding_source_hash` | Hash source lines around a finding line for staleness detection | (utility) |

## When to use

- **When scanning (SCA):** `recall_context_for_sca` fires pre-analysis; `store_sca_outcomes` fires post-analysis.
- **When fuzzing:** `recall_context_for_fuzzing_strategy` recalls prior strategies; `infer_afl_fuzz_flags_from_sage_recall_row` derives AFL flags mechanically.
- **Before destructive actions:** call `sage_recall` with `raptor-methodology` for known pitfalls.

## Mechanical AFL priors (fuzzing)

When `raptor_fuzzing.py` recalls high-confidence strategy rows (>= 0.85),
`infer_afl_fuzz_flags_from_sage_recall_row` in `core/sage/hooks.py` may append
conservative `afl-fuzz` flags (`-L 0`, `-D`, `-p explore|exploit|fast`) before
the `--` separator. Set **`RAPTOR_SAGE_AFL_PRIOR=0`** to disable. CMPLOG and
other companion-binary modes are not inferred here — keep those explicit in
operator workflows.

## Graceful degradation

If a SAGE call errors mid-session (server restart, transient failure),
fall back silently and continue — SAGE is purely additive. Log the error
at debug level (matching `core/sage/hooks.py`'s existing pattern) rather
than surfacing it to the user. Never let a SAGE failure block RAPTOR work.
