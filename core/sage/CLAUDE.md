# SAGE persistent memory usage

Loaded on demand by RAPTOR's root `CLAUDE.md` when the `sage_inception`
MCP tool is present (i.e. when the user has run `libexec/raptor-sage-setup`).
If this file is loaded, SAGE is available — use it.

## Boot sequence

1. Call `sage_inception` to initialize persistent memory.
2. Call `sage_turn` every turn with the current topic + observation.
3. Call `sage_reflect` after significant tasks with dos and don'ts.

## Domains

- `raptor-findings` — Vulnerability findings and analysis results
- `raptor-fuzzing` — Fuzzing strategies, crash patterns, exploit techniques
- `raptor-crashes` — Crash analysis patterns and root causes
- `raptor-forensics` — OSS forensics evidence and investigation patterns
- `raptor-exploits` — Exploit development patterns and constraints
- `raptor-methodology` — Analysis methodology and expert reasoning
- `raptor-campaigns` — Campaign history and outcomes
- `raptor-reports` — Report structures and templates
- `raptor-agents` — Agent role definitions and capabilities
- `raptor-primitives` — Exploitation primitives and dependency graphs
- `raptor-prompts` — LLM system prompts and personas

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
