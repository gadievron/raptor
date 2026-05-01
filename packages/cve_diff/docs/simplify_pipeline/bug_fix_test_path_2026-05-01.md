# Bug fix: harmonize divergent `_TEST_PATH_RE`

**Date:** 2026-05-01
**Outcome:** ✓ Applied
**Pipeline-plan reference:** Stage 2 dry-run surfaced this; deferred per user; fixed in this commit.

## What was broken

`cve_diff/diffing/` had **3 separate `_TEST_PATH_RE` definitions** with **two divergent patterns**, causing the same file to be classified differently depending on which extractor handled the CVE.

| File | Pattern |
|---|---|
| `extractor.py` (clone path) | A — required `\.[a-z]+$` extension; included `testing/`; excluded `fixtures/` and `*.test.*` |
| `extract_via_api.py` (API path) | B — permissive extension; included `fixtures/` and `*.test.*`; excluded `testing/` |
| `extract_via_patch_url.py` (patch URL path) | identical copy of B |
| `extract_via_gitlab_api.py` | imported B from `extract_via_api` |

Empirical confirmation: **3 of 9 sample paths classified differently** between A and B.

## Fix applied

Created `cve_diff/core/test_path.py` with a single canonical `is_test_path(path)` and the regex pattern that's the **strict union** of A and B:

```python
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|testing|fixtures?)(?:/|$)"
    r"|(?:^|/)test_[^/]+(?:\.[^/]+)?$"
    r"|(?:^|/)[^/]+_test\.[^/]+$"
    r"|(?:^|/)[^/]+\.(?:test|spec)\.[^/]+$",
    re.IGNORECASE,
)
```

All 4 callers now import `is_test_path` from this module:

```python
from cve_diff.core.test_path import is_test_path as _is_test_path
```

(Imported with the historical alias `_is_test_path` so the call sites in each extractor are zero-touch.)

## Verification

| Gate | Result |
|---|---|
| All imports resolve to the same canonical function | ✓ verified via `id()` comparison |
| 14 representative test paths classify per the canonical pattern | ✓ all 14 match expected |
| Full unit suite | ✓ **598/598 pass** (no regressions) |
| ruff F401 | ✓ unused `re` import in `extractor.py` cleaned up |
| Smoke CVE (CVE-2023-38545) test split | ✓ identical pre/post for files this CVE touches |
| 4-CVE smoke bench | ✓ **4/4 PASS** (best run of this session) — prior runs hit 3/4 with stochastic CVE-2024-7006 flips |

## Per-CVE test classification (post-fix, 4-CVE bench)

| CVE | total files | test files | examples |
|---|---:|---:|---|
| CVE-2022-21676 | 2 | 1 | `test/server.js` |
| CVE-2023-38545 | 3 | 2 | `tests/data/Makefile.inc`, `tests/data/test728` |
| CVE-2024-3094 | 12 | 9 | `tests/files/README`, `tests/files/bad-*` |
| CVE-2024-7006 | 1 | 0 | (only source files) |

All classifications consistent with the canonical pattern. No file was misclassified.

## Diff stat

| File | Insertions | Deletions |
|---|---:|---:|
| `cve_diff/core/test_path.py` (new) | 49 | 0 |
| `cve_diff/diffing/extractor.py` | 1 | 18 |
| `cve_diff/diffing/extract_via_api.py` | 1 | 9 |
| `cve_diff/diffing/extract_via_patch_url.py` | 1 | 9 |
| `cve_diff/diffing/extract_via_gitlab_api.py` | 1 | 4 |
| **Net** | **53** | **40** |

Net +13 LOC for the new module's docstring + canonical regex; -40 LOC removed across the 4 extractors. Architectural quality much higher: 1 source of truth instead of 3 divergent ones.

## Pipeline framing

This is a **bug fix**, not a simplifier action — it intentionally changes behavior (harmonizes two divergent classifications). The simplifier-pipeline plan explicitly carved this out as separate work:

> The simplifier's contract is "preserve behavior"; harmonizing two divergent regexes inherently changes behavior for some files. **Surfaced for separate handling outside this pipeline.**

The fix is documented here under `docs/simplify_pipeline/` for proximity to the dry-run finding that surfaced it, but the commit message explicitly frames it as `fix:` not `simplify:`.

## next_tasks update

Item #5 (`Harmonize divergent _TEST_PATH_RE across diffing extractors`) — **DONE 2026-05-01**.
