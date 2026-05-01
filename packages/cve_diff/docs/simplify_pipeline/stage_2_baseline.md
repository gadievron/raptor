# Stage 2 — pre-stage baseline

**Stage:** Diffing extractors
**Files in scope:** `cve_diff/diffing/{extract_via_api, extract_via_gitlab_api, extract_via_patch_url, extraction_agreement, extractor, commit_resolver, shape, shape_dynamic}.py`
**Date:** 2026-05-01
**Working tree HEAD:** `1ebf961`

## P1 — Inventory

| File | LOC | Note |
|---|---:|---|
| `extract_via_api.py` | 175 | GitHub Commits API extractor |
| `extract_via_gitlab_api.py` | 244 | GitLab v4 API extractor + forge dispatcher |
| `extract_via_patch_url.py` | 181 | `.patch` URL extractor (3rd source) |
| `extraction_agreement.py` | 214 | N-source pairwise comparison |
| `extractor.py` | 211 | git-CLI clone-based extractor |
| `commit_resolver.py` | 120 | SHA expansion + parent_of |
| `shape.py` | 94 | Offline shape classifier |
| `shape_dynamic.py` | 117 | Dynamic shape classifier (consults `/languages`) |
| **Total** | **1,356** | |

No overlap with EXCLUDED list.

## P2 — Coverage

| File | Coverage | Note |
|---|---:|---|
| `shape.py` | 100% | |
| `shape_dynamic.py` | 100% | |
| `extract_via_patch_url.py` | 96% | 3 lines uncovered — defensive returns |
| `extractor.py` | 95% | 3 lines uncovered — defensive returns |
| `extract_via_api.py` | 94% | 3 lines uncovered — defensive returns |
| `extraction_agreement.py` | 93% | 5 lines uncovered — defensive returns |
| `commit_resolver.py` | 82% | 11 lines — all `raise ValueError` and `subprocess.TimeoutExpired` handlers |
| `extract_via_gitlab_api.py` | 78% | 22 lines — all `raise AnalysisError(...)` and `except: pass` swallow blocks |

**All gaps are defensive error handlers, not core branching logic.** Test-uplift not required for Stage 2.

## P3 — Test quality

Tests directly covering this stage:
| File | Tests | Asserts | Raises |
|---|---:|---:|---:|
| `tests/unit/diffing/test_extract_via_api.py` | 11 | 15 | 8 |
| `tests/unit/diffing/test_extract_via_gitlab_api.py` | 11 | 23 | 3 |
| `tests/unit/diffing/test_extract_via_patch_url.py` | 9 | 18 | 0 |
| `tests/unit/diffing/test_extraction_agreement.py` | 11 | 27 | 0 |

Plus 5 indirect-coverage test files (`tests/unit/test_commit_resolver.py`, `test_diff_extractor.py`, `test_diff_shape*.py`, `test_extractor_tier1.py`, `test_pipeline.py`).

Fakeness sweep: zero `assert True` / trivial `pass` patterns. The single `pass` (`test_extract_via_patch_url.py:187`) is a `class _RE(Exception): pass` — Python idiom for a marker exception.

## P4 — Test-suite baseline

Same as Stage 1 baseline: **598 / 598 pass / 39.96s.**

## P5 — Smoke-CVE baseline (CVE-2023-38545)

Same baseline as Stage 1 (saved at `data/runs/20260501_stage_1_pre_CVE-2023-38545.osv.json`):
- ✓ PASS, agent pick `curl/curl @ 172e54cda184`, 3/3 extractor agreement, 5 tool calls, source shape, 22 files / 88,297 bytes (clone).
