# Stage 6 — outcome: SKIPPED (one candidate over the risk bar)

**Date:** 2026-05-01
**Outcome:** ⊘ Stage skipped (no code change applied)

## Pre-stage gates (P1-P5)

| Gate | Result |
|---|---|
| P1 — Inventory | 1 file (`agent/tools.py`), 512 LOC, 18 tool implementations |
| P2 — Coverage | 70% — gappiest in `_fetch_distro_advisory_impl` (lines 386-410) and `_deterministic_hints_impl` (intentionally branchy, plan-EXCLUDED) |
| P3 — Tests | `test_tools.py` (47 tests, 81 asserts), `test_loop.py` (24 tests, 55 asserts). No fakes. |
| P4 — Test baseline | 598/598 pass |
| P5 — Smoke baseline | reused — tools.py is exercised by every CVE; Stage 5 baseline still applies |

## P6 dry-run: identified-but-skipped candidate

**Pattern:** `_gitlab_commit_impl`, `_cgit_fetch_impl`, and `_http_fetch_impl` share the SAME 5-line HTTP-fetch preamble:

```python
try:
    resp = requests.get(url, timeout=_TIMEOUT_S, headers={"User-Agent": _USER_AGENT})
except requests.RequestException as exc:
    return _err(f"network: {exc}")
if resp.status_code != 200:
    return _err(f"http {resp.status_code}")
```

A `_http_get_or_err(url, headers=None) -> tuple[Response | None, str | None]` helper would dedupe across these 3 tools (similar pattern to Stage 3's `_http_or_error` in `distro_cache.py`).

`_osv_raw_impl` and `_osv_expand_aliases_impl` have a similar shape but with special-cased 404 handling — less clean fit for the same helper.

**Net LOC:** ~3 saved (helper docstring offsets dedup).

## Why skipped

This is the **agent's tool surface**. Every CVE run goes through these tools dozens of times. The asymmetry is:

- **Cost of the change**: ~3 LOC saved, modest DRY win. Tests in `test_tools.py` cover these tools.
- **Cost of a regression**: every CVE potentially affected. A subtle bug in `_http_get_or_err` (e.g., wrong error string format, missing 404 special-case) propagates to all 3 forge paths.

The plan explicitly framed this as "**highest risk in the pipeline; do last**." Combined with the user-stated stakes ("my job relies on this"), the risk-adjusted ROI is negative for an incremental DRY win on a load-bearing module.

The same pattern was already validated in Stage 3 (`distro_cache._http_or_error`) — the architectural lesson is captured even without applying it here. If the team later wants this dedup in `agent/tools.py`, it's a focused 30-min PR with the existing tests as the guardrail.

## What WAS in Stage 6 scope but I deliberately did NOT touch

Per the plan's EXCLUDED list applied at sub-function level:
- `_deterministic_hints_impl` (cc=34, "intentionally branchy"). Skipped per plan.

## Stage 6 verdict

| Outcome | Why |
|---|---|
| **Total simplification candidates worth applying** | **0** |
| Total candidates considered | 1 (`_http_get_or_err` over the risk bar for an agent-surface module) |

**Recommendation: skip Stage 6.** The agent's tool surface is load-bearing; the candidate's value doesn't pass the risk bar.

## Pipeline ahead

Stage 7 (CLI — `cli/main.py` + `cli/bench.py`, ~1,200 LOC, helpers only — top-level command bodies are EXCLUDED) is next.
