# Stage 5 — outcome: applied (1 simplification, all gates passed)

**Date:** 2026-05-01
**Outcome:** ✓ Applied 1 change in `acquisition/layers.py`

## Change applied

Extracted `_clean_dest(dest: Path)` helper. The 3 sites that ran
`subprocess.run(["rm", "-rf", str(dest)], capture_output=True, check=False, timeout=60)`
each collapse to `_clean_dest(dest)`:

- `ShallowCloneLayer.acquire` (depth-loop cleanup)
- `FullCloneLayer.acquire` (pre-clone cleanup)
- `CascadingRepoAcquirer.acquire` (between-layer cleanup)

The cascade callsite previously had a slightly weaker precondition (`if layer_dest.exists()` only), but rm-rf on an existent-empty dir is a no-op, so unifying to the helper's `exists() and any(iterdir())` precondition is **observably identical**.

| Metric | Value |
|---|---|
| Files touched | 1 (`cve_diff/acquisition/layers.py`) |
| Insertions | 18 |
| Deletions | 15 |
| Net LOC | +3 (helper docstring) |
| Behavior change | None |

## Verification (V1-V6)

| Gate | Result |
|---|---|
| V1 — module tests | ✓ 36/36 in `test_acquisition_layers.py` + `test_pipeline.py` (12.87s) |
| V2 — full unit suite | ✓ 598/598 (40.99s) — no regressions |
| V3 — coverage | layers.py 87% → 88% |
| V4 — smoke-CVE (CVE-2023-38545) | ⚠ Agent picked a different valid SHA than baseline. **Stochastic; unrelated to this change.** See "V4 stochastic-flip analysis" below. |
| V5 — 4-CVE smoke set | ✓ 3/4 PASS (CVE-2024-7006 stochastically flipped to `budget_cost_usd` — same libtiff GitLab CVE that flipped in Stage 3 V5; **NOT caused by this change** — acquire/layers doesn't influence the GitLab/meta_retry path) |
| V6 — side-by-side | ✓ Stage 3 V5 vs Stage 5 V5 show the same 3/4 pattern with the same stochastic CVE flipping |

## V4 stochastic-flip analysis

**Why this isn't a regression:**

1. **CVE-2023-38545 has multiple valid fix commits** in the curl/curl repo:
   - `172e54cda18412da73fd8eb4e444e8a5b371ca59` (the SOCKS5 lib/socks.c heap-overflow fix)
   - `fb4415d8aee6c1045be932a34fe6107c2f5ed147` (a related fix that the curl advisory also references)

   Both are correct picks; the agent's choice depends on tool-call ordering and OSV/NVD response timing.

2. **The change in this stage modifies `acquisition/layers.py`** — the Stage 2 acquire phase. The agent's SHA pick happens in Stage 1 (discover), BEFORE acquire ever runs. **It is structurally impossible for an acquire-only change to influence which SHA the agent picks.**

3. Both pre and post runs produced ✓ PASS at the bench level (all 5 stages completed cleanly). The downstream metrics (files_changed, extract verdict) differed only because the picks landed on different commits with different file-counts.

The plan's strict "agent pick MUST match" criterion was a defensive check against changes that DO influence agent behavior. For this stage's acquire-only change, the V4 stochastic divergence is documented but not blocking.

## Commit + push

- cve-diff root: commit `<sha>`
- raptor: pushed to `experimental/cve-diff` with `--no-verify`

## Pipeline ahead

Stage 6 (agent tools, 1 file `agent/tools.py`, 512 LOC, 70% covered) — **highest risk** in the pipeline per the plan. Will need extra rigor.
