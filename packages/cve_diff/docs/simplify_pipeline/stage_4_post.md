# Stage 4 — outcome: SKIPPED (one candidate over the risk bar)

**Date:** 2026-05-01
**Outcome:** ⊘ Stage skipped (no code change applied)

## Pre-stage gates (P1-P5)

| Gate | Result |
|---|---|
| P1 — Inventory | 5 files, 869 LOC. None overlap with EXCLUDED list. |
| P2 — Coverage | github_client 79%, rate_limit 97%, service_health 100%, disk_budget 100%, api_status 100% |
| P3 — Test quality | 3 test files (`test_github_client`, `test_rate_limit`, `test_service_health`, `test_api_status`). All real, zero fake patterns. (`test_github_client` and `test_rate_limit` use unittest.TestCase classes, so the `^def test_` grep returned 0; assertion counts confirm they're real.) |
| P4 — Test baseline | 598/598 unit tests pass |
| P5 — Smoke baseline | reused — Stage 3 baseline (CVE-2024-3094) covers the infra path |

## P6 dry-run findings

| File | Verdict |
|---|---|
| `service_health.py` (247 LOC) | 100% covered as of this session's `1ebf961` commit. Just stabilized — touching it now would muddy the audit trail. **Skip.** |
| `disk_budget.py` (46 LOC) | Tiny, 100% covered, single function. **Skip.** |
| `api_status.py` (175 LOC) | Pure data + record/format functions, 100% covered. **Skip.** |
| `rate_limit.py` (108 LOC) | TokenBucket with explicit lock + injectable time source. Already idiomatic. **Skip.** |
| `github_client.py` (293 LOC, 79%) | **One real candidate identified, but over the risk bar — see below.** |

## github_client.py: identified-but-skipped candidate

`_get()` (lines 109-139) and `commit_exists()` (lines 158-194) share a near-identical retry+rate-limit+timeout structure:

```python
for attempt in (1, 2):
    try:
        resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT_S)
    except (requests.Timeout, requests.ConnectionError):
        if attempt == 1:
            continue
        return None
    status = resp.status_code
    # ... handler-specific 200 path ...
    if status in (401, 403, 429):
        _warn_rate_limited(status)
        return None
    if status >= 500 and attempt == 1:
        continue
    return None
```

The shared structure could be extracted into a `_request_with_retry(url, on_200)` helper that takes a callback for the status-200 handling (`_get` returns parsed JSON; `commit_exists` returns True). Saves ~10-15 LOC.

**Why skipped:** This retry block handled the **2026-04-23 NVD 429 storm** in production. The exact behavior of "retry on 5xx OR connection error / single attempt for 4xx" is load-bearing — a subtle refactor that miscounts attempts or drops a status-code branch could re-introduce the rate-limit cascade failures.

The 79% coverage gap on this file is precisely in these retry paths (lines 121-124, 130-131, 179-194 — defensive branches the unit tests don't all exercise). Refactoring code that's both load-bearing AND under-covered is over the user-stated bar ("critical functionality isn't hurt").

## Stage 4 verdict

| Outcome | Why |
|---|---|
| **Total simplification candidates worth applying** | **0** |
| Total candidates considered | 1 (over risk bar) |
| Files skipped trivially | 4 |

**Recommendation: skip Stage 4.** The infra layer is in good shape; the only real candidate is in production-load-bearing code that's better left alone for now.

If we want the github_client cleanup later, it should be a separate effort with: (1) test uplift on lines 121-194 first to cover the retry branches, (2) targeted regression test using a mock-server harness, (3) separate commit framed as a refactor (not a simplifier action).

## Pipeline ahead

Stage 5 (acquisition — single file `acquisition/layers.py`, 220 LOC) is next.
