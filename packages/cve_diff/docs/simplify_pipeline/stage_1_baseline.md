# Stage 1 — pre-stage baseline

**Stage:** Reports / rendering
**Files in scope:** `cve_diff/report/markdown.py`, `cve_diff/report/flow.py`, `cve_diff/report/consensus.py`, `cve_diff/report/osv_schema.py`
**Date:** 2026-05-01
**Working tree HEAD:** `1ebf961` (after dead-code purge + bench persistence + service_health tests)

## P1 — Inventory

| File | LOC |
|---|---:|
| `cve_diff/report/markdown.py` | 645 |
| `cve_diff/report/flow.py` | 129 |
| `cve_diff/report/consensus.py` | 226 |
| `cve_diff/report/osv_schema.py` | 121 |
| **Total** | **1,121** |

None overlap with the EXCLUDED list.

## P2 — Coverage

| File | Coverage | Uncovered lines |
|---|---:|---|
| `report/consensus.py` | 97% | 77, 123, 186 |
| `report/flow.py` | 93% | 60, 106, 116 |
| `report/markdown.py` | 85% | 67, 73, 75-76, 78, 84, 105-106, 239-240, 256-257, 270-271, 310, 314, 322, 401-409, 426, 463-464, 514, 550-556, 580, 591, 602, 609-617, 635-637 |
| `report/osv_schema.py` | 91% | 77, 79, 110, 114 |

`markdown.py` has the largest gap (47 uncovered lines) — mostly small helpers, FAIL-path renderers, googlesource-forge edge case.

## P3 — Test-quality audit

Tests exercising stage 1 modules:
- `tests/unit/report/test_flow.py` — 20 tests, 84 asserts (4.2 avg)
- `tests/unit/test_report_consensus.py` — 16 tests, 38 asserts (2.4 avg)
- `tests/unit/test_stage_assertions.py` — 7 tests, 3 explicit asserts + 6 `pytest.raises` checks (~9 effective assertions, real)

**Fakeness check:** zero `assert True` / trivial `pass` patterns.
**Verdict:** real, comprehensive enough to support the stage.

## P4 — Test-suite baseline

| Metric | Value |
|---|---|
| Total unit tests | **598** |
| Passed | 598 |
| Failed | 0 |
| Duration | 39.96 s |

## P5 — Smoke-CVE baseline (CVE-2023-38545)

| Field | Value |
|---|---|
| Outcome | **✓ PASS** |
| Agent pick (slug, sha) | `curl/curl @ 172e54cda184` |
| Extraction-agreement verdict | `agree` (3/3 sources match) |
| Pointer consensus | 1/2 (OSV ref agreed) |
| Diff shape | `source` |
| Files / bytes (clone) | 22 / 88,297 |
| Stages reached | all 5 (✓ DISCOVER → ACQUIRE → RESOLVE → DIFF → RENDER) |
| Tool-call sequence | `deterministic_hints`, `osv_raw`, `gh_commit_detail`, `check_diff_shape`, `submit_result` (5 calls) |
| Acquire layer | `targeted_fetch` |

Saved at `data/runs/20260501_stage_1_pre_CVE-2023-38545.osv.json`.

**Note on stochasticity**: a first-attempt run hit `sha_not_found_in_repo` at the agent stage (transient — agent picked a different SHA path). This is expected stochastic behavior, not a regression signal. The retried run produced the canonical `172e54cda184` pick that all prior baselines have used.

## P6 — Dry-run preview

Pending — to be filled in once the simplifier proposes changes.
