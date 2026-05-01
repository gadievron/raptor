# Simplifier pipeline — execution log

This directory documents the staged execution of Anthropic's
`code-simplifier` plugin against the cve-diff codebase. Each stage
ran a verified, atomic pipeline:

1. **Pre-stage gates** (P1-P6): inventory, coverage check, test-quality
   audit, baseline test run, smoke-CVE baseline, dry-run preview
2. **Stage execution** (X1-X2): run simplifier, manual diff review
3. **Post-stage verification** (V1-V6): module tests, full unit tests,
   coverage no-regression, smoke-CVE rerun match, full smoke set,
   side-by-side comparison
4. **Commit** (C1-C3): atomic commit, mirror to raptor, document

Failure of any check at any stage reverted that stage and stopped the
pipeline. Plan: `~/.claude/plans/learn-the-project-really-quirky-micali.md`.

## Files explicitly EXCLUDED (load-bearing / intentional concentration)

- `cve_diff/agent/loop.py` (run cc=66, intentional state machine)
- `cve_diff/pipeline.py` (top-level orchestrator)
- `cve_diff/core/{models,url_re,exceptions}.py` (typed invariants)
- `cve_diff/agent/{invariants,source_classes,types,prompt}.py`
- `cve_diff/security/*` (just trimmed)
- All `__init__.py`

## Bug fix (separate from simplifier pipeline)

| Date | Item | Status | Commit | Notes |
|---|---|---|---|---|
| 2026-05-01 | `_TEST_PATH_RE` triple-divergence harmonization | ✓ applied | `a5cd792` (raptor `c21f229`) | Created `cve_diff/core/test_path.py` with canonical pattern (union of A+B). All 4 extractors import from there. 598/598 tests + 4/4 smoke. See `bug_fix_test_path_2026-05-01.md`. |

## Stage status

| # | Stage | Files | Status | Pre $ | Post $ | Commit | Notes |
|---|---|---|---|---|---|---|---|
| 1 | reports / rendering | `report/{markdown,flow,consensus,osv_schema}.py` | ⊘ skipped | $0.20 | $0 | none | No simplifiable surface — files already idiomatic. See `stage_1_post.md`. |
| 2 | diffing extractors | `diffing/extract_via_*` + `extraction_agreement` + `extractor` + `commit_resolver` + `shape*` | ⊘ skipped + ⚠ bug surfaced | $0.10 | $0 | none | No simplifier candidates. **`_TEST_PATH_RE` triple-duplicated across 3 files with 2 divergent patterns** — real classification bug, surfaced separately. See `stage_2_post.md`. |
| 3 | discovery | `discovery/{osv,nvd,distro_cache}.py` | ✓ applied | $0.30 | $1.50 | `5296cc6` (raptor `444cf1d`) | Extracted `_http_or_error` helper from 3 per-distro fetchers in `distro_cache.py`. 598/598 unit tests pass; CVE-2024-3094 smoke byte-identical pre/post; 1/4 stochastic flip on V5 4-CVE bench unrelated to change. See `stage_3_post.md`. |
| 4 | infra | `infra/{github_client,api_status,rate_limit,disk_budget,service_health}.py` | ⊘ skipped | $0.10 | $0 | none | One candidate (`github_client _get/commit_exists` retry dedup) over the risk bar — load-bearing retry path handled the 2026-04-23 NVD 429 storm. See `stage_4_post.md`. |
| 5 | acquisition | `acquisition/layers.py` | ✓ applied | $0.30 | $1.50 | `d2d4e84` (raptor `e6d4fae`) | Extracted `_clean_dest` helper from 3 rm-rf callsites. 598/598 tests pass; 3/4 bench (same stochastic CVE flip as Stage 3 V5). See `stage_5_post.md`. |
| 6 | agent tools | `agent/tools.py` | ⊘ skipped | $0.10 | $0 | none | One candidate (`_http_get_or_err` helper for 3 forge tools) over the risk bar — agent's load-bearing tool surface. Same pattern was already validated in Stage 3's `distro_cache`. See `stage_6_post.md`. |
| 7 | CLI | `cli/{main,bench}.py` (helpers only) | ⊘ skipped | $0.05 | $0 | none | Helpers idiomatic; big surfaces (`_run_one`, `_render_bench_markdown`) EXCLUDED. One marginal merge candidate skipped (net wash). See `stage_7_post.md`. |
| 8 | analysis | `analysis/analyzer.py` | ⊘ skipped | $0.02 | $0 | none | Already trimmed from predecessor's 746 LOC to 133 LOC; 100% covered; no candidates. See `stage_8_post.md`. |
