# Stage 2 — outcome: SKIPPED (no simplifier candidates) + 1 bug surfaced

**Date:** 2026-05-01
**Outcome:** ⊘ Stage skipped (no code change applied as a simplifier action)

## Why skipped

The P6 dry-run preview surfaced 0 pure simplifications worth applying:
- 4 files (`extract_via_api`, `extract_via_patch_url`, `extraction_agreement`, `extractor`) — clean, idiomatic
- 1 file (`extract_via_gitlab_api`) — has a repeated try/except pattern that could be extracted to a helper, but tests pin error message texts; risk-vs-value doesn't pass the bar
- 1 file (`commit_resolver`) — same shape as gitlab; same skip rationale
- 2 files (`shape`, `shape_dynamic`) — 100% covered, idiomatic, no candidates

## BUG SURFACED — DEFERRED FOR USER DECISION

The dry-run revealed that `_TEST_PATH_RE` is **triple-defined** across `cve_diff/diffing/` files with **two different patterns**, causing the test/source split shown in `<cve>.md` to differ depending on which extractor was primary for the CVE.

| File | Pattern | Treats `fixtures/` |
|---|---|---|
| `extractor.py` | A (clone path) | not a test |
| `extract_via_api.py` | B (API path) | **is a test** |
| `extract_via_patch_url.py` | B (API path, identical) | **is a test** |
| `extract_via_gitlab_api.py` | imports B from extract_via_api | **is a test** |

Confirmed divergence on 3 of 9 sample paths (`fixtures/data.json`, `src/foo.test.js`, `testing/regression.go`).

**This is NOT a simplification** (the simplifier's contract is "preserve behavior"). It's a real classification bug that requires an opinionated harmonization. **Surfaced for separate handling outside this pipeline.** See `stage_2_preview.md` for the full analysis.

## What this means for the pipeline

- No commit, no diff to review, no V1-V6 verification needed (nothing changed)
- The `_TEST_PATH_RE` divergence stays open — recommend a separate bug-fix workstream the user explicitly opens
- Total cost of Stage 2: ~$0.10 in tokens (read 6 of 8 files; shape.py + shape_dynamic.py were skipped after their 100% coverage was confirmed)

## Pipeline ahead

Stage 3 (discovery — 3 files, ~480 LOC, 87-91% covered) is next.
