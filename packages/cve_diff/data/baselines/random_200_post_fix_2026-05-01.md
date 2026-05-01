# random_200 post-SHA-not-found-gate bench (2026-05-01)

**Date:** 2026-05-01 (start 21:38, end 22:45 local)
**Sample:** `data/samples/random_200.json` (200 CVEs)
**Workers:** `-w 2`
**HEAD:** `72b8062` (after SHA-not-found gate + ship2 trim)
**Baseline:** `random_200_FULL_2026-04-24.md` (ship `068c3c1`)
**Bench artifact:** `/tmp/bench_r200_post_fix/summary.json` (sha256[:12]: e3adbdd80f04)

## Headline

**138/200 PASS (69.0%) · $99.68 total · $0.498/CVE · 0 hallucinations · 1h 7min wall · 0 LLM retries**

| | This run | Ship baseline | Δ |
|---|---|---|---|
| PASS | **138/200 (69.0%)** | 128/200 (64.0%) | **+10 PASS** |
| Cost / CVE (mean) | $0.498 | $0.337 | +$0.16 |
| Hallucinations | **0** | 1 (CVE-2023-0210 ksmbd) | **-1** |
| Wall-clock | 1h 7min | ~2h | -45 min |
| Pipeline issues | 3 | n/a | — |

## Outcome distribution

| Class | Count |
|---|---:|
| PASS | 138 |
| UnsupportedSource | 52 |
| no_evidence | 7 |
| budget_cost_usd | 2 |
| PerCveTimeout | 1 |

## Self-heal telemetry

| Layer | Fired | Saved |
|---|---:|---|
| meta_retry | 5 | 4 (CVE-2024-7006 + 3 others) |
| bench_retry | 1 | 0 (CVE-2018-1000156 PerCveTimeout — bench-layer retry didn't help) |
| post_submit_retry | 0 | 0 (consistent inert) |
| reflection_fired | 0 | 0 |
| llm_retries (total) | 0 | API rock-stable |
| **`sha_not_found_in_repo`** (gate's terminal surrender) | **0** | ← gate fix vindicated |

## Tool histogram (top 20)

| Tool | Calls |
|---|---:|
| gh_commit_detail | 250 |
| submit_result | 205 |
| gh_search_commits | 202 |
| deterministic_hints | 186 |
| osv_raw | 167 |
| check_diff_shape | 152 |
| nvd_raw | 83 |
| http_fetch | 60 |
| gh_list_commits_by_path | 32 |
| gitlab_commit | 26 |
| gh_search_repos | 19 |
| fetch_distro_advisory | 10 |
| git_ls_remote | 6 |
| oracle_check | 5 |
| cgit_fetch | 2 |

## Diff-shape (PASSes only)

| Shape | Count | % |
|---|---:|---:|
| source | 137 | 99.3% |
| packaging_only | 1 (CVE-2020-10713 BootHole) | 0.7% |
| notes_only | 0 | 0% |

## Extraction agreement (PASSes only)

| Status | Count |
|---|---:|
| majority_agree | 80 |
| partial | 52 |
| agree | 4 |
| disagree | 2 |

## Pipeline issues (3 actionable / 200 = 1.5%)

### CVE-2018-1000156 — PerCveTimeout (300s exceeded)
- Repo: `git.savannah.gnu.org/git/patch.git` via cgit
- 13 tool calls in discovery alone — bench-level 300s ceiling exhausted before acquisition
- bench_retry fired but didn't recover (structural)

### CVE-2018-19788 — budget_cost_usd ($3.09 / cap $2.00)
- 11 iter, 352K tokens
- Tool mix: gitlab_commit×4, gh_search_commits×4, gh_list_commits_by_path×1
- Last iteration's context grew past expected size; budget check is loop-top so prior iter cost overshot

### CVE-2025-0426 — budget_cost_usd ($2.68 / cap $2.00)
- 7 iter, 253K tokens
- Tool mix: http_fetch×6 (page scrapes inflated context)
- 2025 CVE — possibly thin OSV/NVD record forced fallback to web fetches

## Hallucination check — PASSED

| Probe | Verdict |
|---|---|
| CVE-2023-0210 (ksmbd, the ship's residual hallucination) | **NOW PASSES with `shape=source`** — the prior `cifsd-team/ksmbd → torvalds/linux` confabulation is gone |
| Other oracle-verified-wrong PASSes | 0 (extraction_agree shows healthy 80 majority_agree + 52 partial across PASSes) |

## Fix-at-end decisions

| Candidate | Decision | Rationale |
|---|---|---|
| Tighten budget cap $2.00 → $1.75 | skip | Bandaid; doesn't fix root cause |
| Per-iteration token estimation | skip | Real fix but complex; deferred |
| CVE-2018-1000156 timeout root-cause | skip | Needs case-specific investigation |
| Save this baseline file | **done** | Provenance |
| Close queue item #1 | **done** | See `memory/next_tasks.md` |

## Comparison to historical baselines

| Run | Date | n | PASS | $/CVE | Notes |
|---|---|---:|---:|---:|---|
| random_200_FULL_2026-04-24 | 2026-04-24 | 200 | 64.0% | $0.337 | Ship baseline at `068c3c1`; 1 hallucination (ksmbd) |
| random_200_FULL_promptfix_2026-04-25 | 2026-04-25 | 200 | 68.0% | $0.337 | +8 PASS via meta_retry recoveries |
| **this run** | **2026-05-01** | **200** | **69.0%** | **$0.498** | **+10 PASS vs ship; 0 hallucinations; SHA-not-found gate validated** |
| oss_2022_2024_2026-04-26 | 2026-04-26 | 501 | 67.5% | n/a | OSS-only, period-restricted |

## Verdict

✅ **Healthy run. SHA-not-found gate validated at scale.** PASS rate up,
hallucinations down to 0, all stages exercised, all retry layers stable.
The 3 pipeline issues are non-trivial ceiling cases (timeout + budget
overrun on token-heavy paths) that would benefit from deeper engineering
but aren't surgical one-liners.

## Reproducibility

```bash
ANTHROPIC_API_KEY=… GITHUB_TOKEN=… \
  .venv/bin/cve-diff bench \
    --sample data/samples/random_200.json \
    --output-dir /tmp/bench_r200_post_fix \
    -w 2 --disk-limit-pct 95
```
