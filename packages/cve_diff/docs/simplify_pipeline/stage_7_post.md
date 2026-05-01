# Stage 7 — outcome: SKIPPED (idiomatic helpers, big surfaces excluded)

**Date:** 2026-05-01
**Outcome:** ⊘ Stage skipped (no code change applied)

## Pre-stage gates (P1-P4)

| Gate | Result |
|---|---|
| P1 — Inventory | 2 files (`cli/main.py` 497 LOC + `cli/bench.py` 738 LOC); helpers in scope, top-level command bodies EXCLUDED per plan |
| P2 — Coverage | both at 72%; gaps are mostly in error-handling branches of top-level commands (out-of-scope) |
| P3 — Tests | `test_main.py`, `test_bench.py` (covered indirectly by integration tests too). No fakes. |
| P4 — Test baseline | 598/598 pass |

## P6 dry-run findings

### `cli/main.py` helpers

| Function | Verdict |
|---|---|
| `_echo_flow_md` | clean defensive read — no simplification |
| `_flow_from_pipeline` | cc=20; builds stage_signals dict from PipelineResult. Touched in this session for the user-stated "all 5 stages must always render" invariant. **Skip** — recently stabilized. |
| `_budget_reason` + `_classify_discovery` | Both regex-extract a reason from error text, similar pattern. **Could merge** into a single helper but their return semantics differ (`_budget_reason` returns None for non-budget; `_classify_discovery` returns "DiscoveryError" default). Combining adds a `default=` kwarg or wrapping at callsites — **net wash for clarity, skip**. |
| `_write_failure_md` | trivial defensive write |
| `_version_callback` | trivial |
| `_root` callback | trivial |

### `cli/bench.py` helpers

| Function | Verdict |
|---|---|
| `_alarm_handler` | trivial |
| `_run_one` | per-CVE bench runner, **complex top-level surface — EXCLUDED per plan** |
| `_agent_attrs` | small helper |
| `_write_failure_md`, `_write_flow` | small helpers |
| `_outcome_buckets` | clean counter comprehensions |
| `_classify_error` | chain of `startswith` — could be a dict but current form is clear |
| `_echo_result` | trivial |
| `_render_bench_markdown` (cc=33) | **EXCLUDED per plan** — top-level renderer with user-facing report layout |
| `_render_html` | similar to above; renderer |
| `_persist_summary` | shipped earlier this session as A1; just stabilized |
| `_run_bench_retry_pass` | bench-layer retry orchestration — load-bearing |

## Stage 7 verdict

| Outcome | Why |
|---|---|
| **Total simplification candidates worth applying** | **0** |
| Total candidates considered | 1 (`_budget_reason`/`_classify_discovery` merge — net wash, skipped) |

**Recommendation: skip Stage 7.** CLI helpers are idiomatic; big surfaces are excluded by plan; the one possible merge has no value-positive payoff.

## Pipeline ahead

Stage 8 (analysis — 1 small file, 64 LOC, 100% covered) — closing stage.
