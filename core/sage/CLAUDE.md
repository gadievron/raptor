# SAGE persistent memory usage

Loaded on demand by RAPTOR's root `CLAUDE.md` when the `sage_inception`
MCP tool is present (i.e. when the user has run `libexec/raptor-sage-setup`).
If this file is loaded, SAGE is available — use it.

## Boot sequence

1. Call `sage_inception` to initialize persistent memory.
2. Call `sage_turn` every turn with the current topic + observation.
3. Call `sage_reflect` after significant tasks with dos and don'ts.

## Domains

- `raptor-findings-{repo_key}` — Vulnerability findings and analysis results (repo-scoped)
- `raptor-fuzzing` — Fuzzing strategies, crash patterns, exploit techniques
- `raptor-crashes-{repo_key}` — Crash analysis patterns and root causes (repo-scoped)
- `raptor-web-{repo_key}` — Web payload effectiveness and scan outcomes (repo-scoped)
- `raptor-forensics` — OSS forensics evidence and investigation patterns
- `raptor-exploits-{repo_key}` — Exploit development patterns and constraints (repo-scoped)
- `raptor-methodology` — Analysis methodology and expert reasoning
- `raptor-campaigns` — Campaign history and outcomes
- `raptor-reports` — Report structures and templates
- `raptor-agents` — Agent role definitions and capabilities
- `raptor-primitives` — Exploitation primitives and dependency graphs
- `raptor-prompts` — LLM system prompts and personas

## Domain rationale

- Use repo-scoped domains for target-specific outcomes that should not leak across projects (findings, exploits, crash and web behavior).
- Keep `raptor-methodology` global because build/debug/analysis heuristics often generalize across repos and languages.
- Store fuzzing strategy outcomes in `raptor-fuzzing` to preserve semantic recall across similar binaries while still allowing binary fingerprint hints in content.

## When to use

- **When scanning:** after analysis, store key findings via `sage_remember` in `raptor-findings`.
- **When fuzzing:** record strategy outcomes and crash patterns in `raptor-fuzzing`.
- **When developing exploits:** record technique success/failure in `raptor-exploits`.
- **Before destructive actions:** call `sage_recall` with `raptor-methodology` for known pitfalls.

## Graceful degradation

If a SAGE call errors mid-session (server restart, transient failure),
fall back silently and continue — SAGE is purely additive. Log the error
at debug level (matching `core/sage/hooks.py`'s existing pattern) rather
than surfacing it to the user. Never let a SAGE failure block RAPTOR work.

## Mechanical AFL priors (fuzzing)

When `raptor_fuzzing.py` recalls high-confidence strategy rows (≥ 0.85),
`infer_afl_fuzz_flags_from_sage_recall_row` in `core/sage/hooks.py` may append
conservative `afl-fuzz` flags (`-L 0`, `-D`, `-p explore|exploit|fast`) before
the `--` separator. Set **`RAPTOR_SAGE_AFL_PRIOR=0`** to disable. CMPLOG and
other companion-binary modes are not inferred here — keep those explicit in
operator workflows.
