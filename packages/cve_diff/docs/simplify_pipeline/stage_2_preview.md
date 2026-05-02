# Stage 2 — dry-run preview

## Per-file findings

### `extract_via_api.py` (175 LOC) — clean except for the duplicate

The main flow is clean: validate SHA → get slug → fetch commit → check parents → build diff_chunks → return DiffBundle. No unnecessary nesting. Branching is data-shape-driven (per-entry filters in the file iteration). **No pure simplifications.**

But — defines its own `_TEST_PATH_RE` (lines 167-171) **inconsistent with the one in `extractor.py`**. See "BUG FOUND" below.

### `extract_via_gitlab_api.py` (244 LOC) — repetitive but clear

`extract_via_gitlab_api` (lines 62-187) has a repeated 4-step pattern:
```
try:
    resp = requests.get(url, timeout=...)
except RequestException as exc:
    raise AnalysisError(...)
if resp.status_code != 200:
    raise AnalysisError(...)
try:
    data = resp.json()
except ValueError as exc:
    raise AnalysisError(...)
```

Repeats 2x (meta_resp lines 88-104, diff_resp lines 114-129). **Could extract** `_get_json_or_raise(url, error_label)` to ~6 lines × 2 + 8-line helper = 20 LOC saved.

Risk: medium. The error messages contain CVE-id + slug + sha context that tests assert on (`test_extract_via_gitlab_api.py` covers the network-error and 404 paths).

Value: low — saves ~20 LOC, reduces parallel structure but doesn't change reading flow much.

**Recommendation: skip.** Marginal value for non-trivial risk to error-message text in tests.

### `extract_via_patch_url.py` (181 LOC) — clean except for the duplicate

Defines its own `_TEST_PATH_RE` (lines 173-177), **identical to the one in `extract_via_api.py`** but **different from `extractor.py`**. See "BUG FOUND" below.

The forge-routing in `_patch_url_for` (lines 38-72) is a clear if/else chain across 3 forge types. Could be expressed via a tuple of `(matcher, builder)` but the current form is more readable for 3 cases.

### `extraction_agreement.py` (214 LOC) — clean

`_compare` and `_compare_pair` overlap (both compute paths overlap + byte percent + verdict label). Could collapse but it's intentional — `_compare_pair` runs in a nested loop in `_summarize_n` for N≥3 sources, and skipping the dict-build per call is a real micro-saving. Don't simplify.

### `extractor.py` (211 LOC) — clean

The git-CLI extractor. Defines `_TEST_PATH_RE` (lines 35-41), **different from the one in `extract_via_api.py` / `extract_via_patch_url.py`.** See "BUG FOUND".

`_count_hunks_per_file`, `_show_blob`, `_build_file_changes`, `_list_files` are all small focused helpers. **No simplifications.**

### `commit_resolver.py` (120 LOC) — clean

`expand` and `parent_of` share subprocess-wrapping structure. Could extract `_run_git_or_raise(repo, args, timeout, error_label)` to dedupe the 5-line try/except + returncode check pattern. Saves ~10 LOC.

Risk: medium. Tests pin specific error messages. Pulling subprocess into a helper would parameterize the messages — same texts at the callsite, but indirection.

Value: low.

**Recommendation: skip.**

### `shape.py` (94 LOC) — already 100% covered, not read in detail. Skip.

### `shape_dynamic.py` (117 LOC) — already 100% covered, not read in detail. Skip.

---

## BUG FOUND — `_is_test_path` is divergent across extractors

This isn't a simplification target — it's a **real classification bug** the dry-run surfaced.

### The duplication

3 separate `_TEST_PATH_RE` definitions exist in `cve_diff/diffing/`:

| File | Pattern shape | Treats `fixtures/` | Treats `*.test.*` | Treats `testing/` |
|---|---|---|---|---|
| `extractor.py:35` | `(?:^|/)(?:tests?|__tests__|specs?|testing)(?:/|$)` + `_test.[a-z]+$` etc. | not a test | not a test | **is a test** |
| `extract_via_api.py:167` | `(^|/)(tests?|spec|specs?|__tests__|fixtures?)/` + `_test.[^/]+$` etc. | **is a test** | **is a test** | not a test |
| `extract_via_patch_url.py:173` | identical to extract_via_api | **is a test** | **is a test** | not a test |

`extract_via_gitlab_api.py:29` correctly imports `_is_test_path` from `extract_via_api.py` (so it shares pattern with API + patch_url).

### The bug

The same file gets classified differently depending on which extractor handled the CVE:

| Path | extractor (clone) | API / patch_url |
|---|---|---|
| `fixtures/data.json` | not a test | **is a test** |
| `src/foo.test.js` | not a test | **is a test** |
| `testing/regression.go` | **is a test** | not a test |

### The impact

- The `<cve>.md` report shows `## Files (N production / M test)` based on the primary extractor's classification.
- The OSV JSON's `database_specific.files[].is_test` reflects the same classification.
- **Same file, different classification depending on whether clone or API was the primary source for that CVE.**
- In practice: most CVEs use clone (extractor.py path), so the visible behavior is consistent for the common case. The bug surfaces on CVEs where clone failed and the API became primary.

### Fixing it

Pure simplification (no behavior change) is **impossible** here — you must pick one regex. The two patterns disagree on real classification cases.

**Option A — Harmonize on extractor.py's pattern.** Clone is the primary source (most CVEs). API + patch_url already see the same file lists from the API, just classify them differently. Promoting extractor.py's regex to the canonical one minimizes visible change for the common case. Behavior changes for: `fixtures/data.json` flips API-path classification from test → not-test (matches clone).

**Option B — Harmonize on extract_via_api.py's pattern.** Slightly more inclusive (catches `fixtures/`). Some CVEs would see one more file labeled "test" in the report.

**Option C — Move to a shared `cve_diff/core/test_path.py` with a canonical pattern.** Same risk as A or B, just with cleaner architecture.

### Recommendation

**Surface this as a SEPARATE bug-fix follow-up, not a simplifier-pipeline change.**

Reasons:
1. The simplifier's contract is "preserve behavior." This change doesn't preserve behavior; it harmonizes two divergent behaviors. That's a bug fix.
2. Stage 2 has no pure simplifications worth applying. Mixing a bug fix into a "simplifier" stage muddles the audit trail.
3. The fix needs its own evidence: pick a regex, check if any CVE in the smoke set has files that would flip, document.
4. Per the careful pipeline's "atomic, evidence-bearing" principle, separate concerns belong in separate stages.

The user should decide:
- Defer the fix entirely (acknowledge the inconsistency, address later)
- Open a separate plan/commit specifically for the harmonization (not part of this pipeline)
- Apply it now as a special non-simplifier commit in this pipeline (with explicit "behavior change" warning in commit message)

---

## Stage 2 verdict

| Outcome | Why |
|---|---|
| **Total simplification candidates worth applying** | **0** |
| **Bugs surfaced** | **1** (the `_TEST_PATH_RE` divergence — to handle separately) |

**Recommendation: skip Stage 2 as a simplifier stage.** No pure simplifications. Surface the bug for separate decision.

Move directly to Stage 3 (discovery — 3 files, 480 LOC, 87-91% coverage).
