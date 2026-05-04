# Security Engineering Audit Report
## Bugs BUG-A, BUG-R-016, BUG-NEW — Integration Bug Post-Fix Review

**Date:** 2026-05-05  
**Auditor:** Security Engineer (automated, via code analysis)  
**Scope:** `raptor_agentic.py`, `packages/exploitability_validation/agentic.py`, `packages/openant/scanner.py`, related tests and variant hunt across the full codebase.

---

## Table of Contents

1. [BUG-A — Dedup Arithmetic Inflation](#bug-a)
2. [BUG-R-016 — Merge Format Mismatch (dict vs list)](#bug-r-016)
3. [BUG-NEW — CWD Isolation](#bug-new)
4. [Variant Hunt — Similar Bugs Elsewhere](#variant-hunt)
5. [Test Coverage Assessment](#test-coverage)
6. [Summary Verdict Table](#summary-verdict-table)

---

## BUG-A — Dedup Arithmetic Inflation {#bug-a}

### Data Flow

```
Phase 1 (Semgrep/CodeQL):
  semgrep_metrics['total_findings'] + codeql_metrics['total_findings']
         │
         ▼
  total_findings  ─────────────────────────────────────────────┐
         │                                                      │
         │  Phase 1b (OpenAnt):                                 │
         │  openant_extra_findings = [...]                      │
         │  ← NOTE: NOT added to total_findings                 │
         │  (comment at raptor_agentic.py:707-711 explains why) │
         │                                                      │
         ▼                                                      ▼
  run_validation_phase(total_findings=total_findings)    final_report
         │                                              "original_findings"
         │   agentic.py:161:
         │   unique_count = len(converted_findings['findings'])
         │   duplicates_removed = total_findings - unique_count
         │          ← SARIF-only count: correct baseline
         ▼
  validated_findings = unique_count
```

### Fix Analysis

**File:** `raptor_agentic.py`, lines 662–716 (Phase 1b block)  
**Key lines:** 707–711 (comment), 728 (`total_findings=total_findings`)

The fix is **correctly applied**. `openant_extra_findings` is never added to `total_findings` before `run_validation_phase()`. The comment at line 707 accurately explains the invariant:

> NOTE: do NOT add to total_findings here. total_findings feeds run_validation_phase which uses it to compute duplicates_removed = total_findings - unique_sarif_count. Adding OpenAnt findings before that call inflates the baseline and makes the dedup report show OpenAnt findings as "duplicates" (they're not SARIF findings).

**Arithmetic trace (post-fix, correct):**
- `total_findings` = semgrep findings + codeql findings (SARIF only)
- `run_validation_phase(total_findings=N)` computes `unique_count = len(sarif_deduplicated)`
- `duplicates_removed = N - unique_count` (SARIF→SARIF duplicate count: correct)
- `validated_findings` is then incremented by `len(openant_extra_findings)` **after** dedup at lines 774 and 789

### Remaining Risk: `validated_findings` double-increment potential

**Severity:** Low  
**File:** `raptor_agentic.py`, lines 774, 789, 802

`validated_findings` is incremented in three branches of the merge block. Each branch is mutually exclusive (`elif`/`else`), so there is no double-increment possible within the merge block. However, `validated_findings` is also initialized to `total_findings` inside `run_validation_phase()` (agentic.py:131) and then overwritten to `unique_count` (agentic.py:165). This is correct. No inflation remains.

### Are there other places that add non-SARIF findings to `total_findings` before `run_validation_phase()`?

Searched all `+= ` assignments to `total_findings` in `raptor_agentic.py`. Only these lines appear:
- Line 624: `total_findings = codeql_metrics.get('total_findings', 0)` (CodeQL report read)
- Line 641: `total_findings = semgrep_metrics.get('total_findings', 0) + codeql_metrics.get('total_findings', 0)` (final combined count)

No other path adds to `total_findings` before line 728. **Fix complete.**

### Test Coverage Assessment (BUG-A)

**Test file:** `packages/openant/tests/test_phase1b_integration.py`

**Gap found — CRITICAL:** The tests in `TestBugR011OpenantFindingsMerge` and `TestBugR016DictFormatMerge` exercise the **merge logic** (is the file updated correctly?) but **do NOT test the dedup arithmetic path** at all. Specifically:

- There is no test that calls `run_validation_phase()` and then verifies that `duplicates_removed` equals `(sarif_count - unique_sarif_count)` and NOT `(sarif_count + openant_count - unique_sarif_count)`.
- There is no test that asserts `validated_findings` at the end of the full merge block equals `unique_sarif_count + len(openant_extra_findings)` (not inflated).
- The static check `test_merge_block_present` verifies the comment text exists but not the arithmetic behavior.

**Missing tests:**
1. `test_total_findings_not_inflated_by_openant`: mock `run_validation_phase` returning `(result, N)` and verify the final `validated_findings` equals `N + len(openant_extra_findings)`, not `N + 2*len(openant_extra_findings)`.
2. `test_dedup_arithmetic_openant_not_counted_as_duplicates`: verify `duplicates_removed` in `validation_result` reflects only SARIF deduplication.

**Verdict:** BUG-A fix is **CORRECT** but **under-tested at the arithmetic level.**

---

## BUG-R-016 — Merge Format Mismatch (dict vs list) {#bug-r-016}

### Data Flow

```
Phase 2: run_validation_phase()
         └─► convert_sarif_to_findings(sarif_files, repo_path)
               └─► convert_sarif_data()  [orchestrator.py:419-462]
                     └─► returns {
                             "stage": "A",
                             "timestamp": "...",
                             "target_path": "...",
                             "source": "sarif",
                             "findings": [...]
                         }
                         ↑ ALWAYS a wrapped dict, never a plain list
                     └─► save_json(validation_out/"findings.json", converted_findings)
         │
         ▼
Phase 1b merge block (raptor_agentic.py:750-806):
         │
         ├─ if validation_findings_path.exists():
         │       existing = load_json(..., strict=True) or []
         │       ┌── isinstance(existing, dict) and "findings" in existing
         │       │        ← Raptor's actual format: this branch now taken ✓
         │       │        findings_list = existing.get("findings", [])
         │       │        findings_list.extend(openant_extra_findings)
         │       │        existing["findings"] = findings_list
         │       │        save_json(...)
         │       │
         │       ├── isinstance(existing, list)
         │       │        ← backward compat (pre-fix code, or JSON null→[] via `or []`)
         │       │        existing.extend(openant_extra_findings)
         │       │        save_json(...)
         │       │
         │       └── else: unrecognized format → logger.error, skip merge
         │
         └─ else (no prior file):
                  save_json(validation_findings_path, openant_extra_findings)
                              ↑ WRITES PLAIN LIST (see BUG-R-016-VARIANT below)
```

### Fix Analysis

**File:** `raptor_agentic.py`, lines 750–806  
**Pre-fix:** `isinstance(existing, list)` always rejected the dict format, silently dropping OpenAnt findings.  
**Post-fix:** Dict branch added at lines 762–778, list branch retained at lines 779–793.

The fix correctly handles the Raptor-native wrapped dict format. The dict branch extracts `existing.get("findings", [])`, extends it, re-wraps it into `existing["findings"]`, and writes the whole dict back — preserving `stage`, `timestamp`, `target_path`, and `source` metadata.

### Issue 1: `load_json(strict=True) or []` TOCTOU + Null-JSON Silent Data Loss

**Severity:** Medium  
**File:** `raptor_agentic.py`, line 754

```python
existing = load_json(validation_findings_path, strict=True) or []
```

`load_json` in `core/json/utils.py:16-33` checks `p.exists()` first and returns `None` for a missing file **before** reaching the `strict` branch. This means:

1. **TOCTOU race:** If `findings.json` is deleted between line 752 (`exists()`) and line 754 (`load_json`), `load_json` returns `None`. `None or []` gives `[]`. The code hits the `isinstance(list)` branch and writes only OpenAnt findings — the SARIF findings that were in the deleted file are lost from the output (though SARIF data remains in the original `.sarif` files).

2. **JSON null edge case:** If `findings.json` somehow contains the JSON literal `null`, `json.loads('null')` returns Python `None`. `strict=True` does not prevent this — it only controls exception propagation for parse errors. `None or []` silently gives `[]`, losing SARIF data.

**Operational mitigation stated in tests (TestCleanupB1ToctouRaceWindow):** Per-run output directory isolation means no concurrent writers to the same `findings.json`. The race is theoretical in single-process runs. However, the test pins the wrong contract: it asserts `load_json` returns `None` after deletion (correct) but does NOT assert that SARIF findings survive the TOCTOU scenario.

**Better fix:** Instead of `or []`, test for `None` explicitly:

```python
if existing is None and not validation_findings_path.exists():
    # File was deleted between exists() check and load (TOCTOU)
    logger.warning("validation/findings.json disappeared; creating fresh file")
    # Fall through to the else branch (create from scratch)
elif existing is None:
    # JSON null in file
    logger.error("validation/findings.json contains JSON null; skipping merge")
    existing = None  # block merge
```

### Issue 2: `or []` Masks Corrupted-File `None` from strict=True

**Severity:** Low  
**File:** `raptor_agentic.py`, line 754

When `strict=True` is passed and the file contains valid-but-null JSON, `load_json` returns `None` (not an exception). The `except Exception` block at line 755 catches actual parse errors correctly. But the `or []` at line 754 collapses the null-JSON case into the non-strict no-file case — bypassing the explicit `None` guard at line 761. This is a conceptual inconsistency: the `strict=True` signal suggests "I want to know about problems" but `or []` hides one class of problems.

### Issue 3: --openant-only Mode Writes Plain List That Breaks Phase 3

**Severity:** HIGH — Active Bug  
**File:** `raptor_agentic.py`, line 801

When `--openant-only` is used:
- No SARIF files are generated, so `validation_findings_path` does not exist
- `run_validation_phase()` returns early (line 138-141 of `agentic.py`) because `total_findings == 0`
- The merge block's `else` branch (line 799-806) runs and executes:

```python
save_json(validation_findings_path, openant_extra_findings)
```

`openant_extra_findings` is a **plain Python list**. This writes the file as a plain JSON array.

Phase 3 (line 831-838 of `raptor_agentic.py`) then detects `validation_findings_path.exists()` is True and passes `--findings str(validated_findings_path)` to `packages/llm_analysis/agent.py`.

`agent.py` calls `_load_validated_findings` → `convert_validated_to_agent_format(data)` (line 297-339), which does:

```python
for raw in data.get("findings", []):  # line 311
```

If `data` is a plain list, `data.get()` raises `AttributeError: 'list' object has no attribute 'get'`. **Phase 3 crashes in `--openant-only` mode.**

**Fix needed:** At line 801, wrap the list before saving:

```python
save_json(validation_findings_path, {
    "stage": "A",
    "timestamp": datetime.now().isoformat(),
    "source": "openant",
    "findings": openant_extra_findings,
})
```

### Is the dict format the ONLY format Raptor writes?

**`convert_sarif_to_findings()` / `convert_sarif_data()`:** Always returns a dict with `stage`, `timestamp`, `target_path`, `source`, `findings`. (orchestrator.py:456-462)

**`run_validation_phase()`:** Calls `save_json(findings_file_path, converted_findings)` where `converted_findings` is the dict from above. Always dict format.

**Exception:** The `else` branch in the merge block (line 801) writes a plain list. This is a bug, not an intentional format variation.

**Other places that write findings.json as dict:** `core/project/merge.py:178`, `core/project/report.py:321`, `core/coverage/summary.py:495`. All use `{"findings": merged}` or `{"stage": "A", ...}` wrapper.

### Are there other places that READ `validation/findings.json`?

1. **`raptor_agentic.py:831-838` (Phase 3):** Passes to `agent.py --findings`. Handled above.
2. **`packages/llm_analysis/agent.py:856` (`_load_validated_findings`):** Calls `convert_validated_to_agent_format(data)` which uses `data.get("findings", [])`. Does NOT handle plain list. Bug if file is plain list.
3. **`packages/exploitability_validation/report.py:25,158`:** Uses `findings_data.get("findings", [])`. Does NOT handle plain list. Only called from `/validate` pipeline which always writes dict format — not a practical risk, but a latent bug.
4. **`packages/exploitation/bootstrap.py:240,253,265`:** Uses `data.get()` methods. Does NOT handle plain list. Only reads validation pipeline output dirs — not a practical risk.
5. **`raptor_agentic.py:1020`:** Only reads the path, does not parse — safe.

### Test Coverage Assessment (BUG-R-016)

**Tests in `TestBugR016DictFormatMerge`:** Cover the merge write phase only. Do NOT cover:

**Missing tests:**
1. `test_phase3_reads_merged_dict_format`: Verify `convert_validated_to_agent_format` successfully processes a dict-format findings.json that was written by the merge block (dict with nested `findings` list).
2. `test_openant_only_mode_writes_dict_format`: Verify the `else` branch (no prior file) writes a wrapped dict, not a plain list, so Phase 3 can read it.
3. `test_phase3_crashes_on_plain_list`: Document that if findings.json is plain list, Phase 3 raises `AttributeError` (and that the fix prevents this).
4. `test_null_json_findings_handled_defensively`: Verify that `null` JSON content in findings.json is handled without silent data loss.

**Verdict:** BUG-R-016 fix is **PARTIAL**. The merge write is fixed but the `--openant-only` path still writes a plain list that will crash Phase 3 with `AttributeError`.

---

## BUG-NEW — CWD Isolation {#bug-new}

### Root Cause and Fix

**File:** `packages/openant/scanner.py`, `_run_subprocess()` function, line 80

**Root cause:** Python's `-m module` invocation automatically inserts `''` (the current working directory) as the first entry in `sys.path`. Raptor's repo root contains a `core/` package (`core/__init__.py` exists, confirmed by test `test_would_fail_without_fix`). OpenAnt also has a `core/` package. Without `cwd=`, the CWD is Raptor's repo root, so `''` resolves to Raptor's `core/` — which shadows OpenAnt's `core/`, causing `ModuleNotFoundError: No module named 'core.scanner'`.

**Fix:** `cwd=str(config.core_path)` added at line 80.

### Verification

```python
# packages/openant/scanner.py:74-81
proc = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=config.timeout_seconds,
    env=env,
    cwd=str(config.core_path),   # ← FIX IS PRESENT
)
```

Confirmed: `cwd=str(config.core_path)` is present.

### Data Flow

```
raptor_agentic.py:681
  run_openant_scan(repo_path, oa_out, oa_config)
         │
         ▼
packages/openant/scanner.py:_run_subprocess()
         │
         ├─ env = _build_subprocess_env(config)
         │    └─► resolved = config.core_path.resolve(strict=True)
         │         # resolves symlinks, validates existence, validates marker
         │        PYTHONPATH = str(resolved) + ... # RESOLVED path
         │
         ├─ cmd = [sys.executable, "-m", "openant", ...]
         │
         └─ subprocess.run(cmd, ..., cwd=str(config.core_path))
                                          # config.core_path: UNRESOLVED path
                                          # ↑ SEE MISMATCH BELOW
```

### Mismatch: `cwd` uses unresolved path, PYTHONPATH uses resolved path

**Severity:** Low  
**File:** `packages/openant/scanner.py`

`_build_subprocess_env()` (line 152-175) uses `config.core_path.resolve(strict=True)` and assigns the **resolved** path to `PYTHONPATH`.

`_run_subprocess()` (line 80) passes `cwd=str(config.core_path)` using the **original, unresolved** path.

If `config.core_path` is a symlink (e.g., `~/.openant-core -> /opt/openant/core`), then:
- `PYTHONPATH = "/opt/openant/core"` (resolved)
- `cwd = "/home/user/.openant-core"` (symlink)

When Python's `-m openant` starts with `cwd=/home/user/.openant-core`, it puts `''` (which resolves to `/home/user/.openant-core` == `/opt/openant/core` via the symlink) first in `sys.path`. Since `''` and `PYTHONPATH` point to the same inode, the package is loaded once. **No practical problem.**

However, if the symlink is broken or changes between `_build_subprocess_env` execution and the `subprocess.run` call, `cwd` could fail (the process would fail to start) while `PYTHONPATH` would still be valid. This is a theoretical race.

**Risk assessment:** The validation at `_build_subprocess_env` calls `config.core_path.resolve(strict=True)` which raises `RuntimeError` if the path doesn't exist. This check happens before `subprocess.run`, so if the symlink is broken at check time, we fail early with a clear error. If the symlink is broken between the check and `subprocess.run`, the OS would fail to change to the `cwd`, causing the subprocess to fail to start. This would appear as a launch error, caught at line 86-87.

**Recommendation:** For consistency and defense-in-depth, change line 80 to use the resolved path:

```python
# In _run_subprocess, after calling _build_subprocess_env:
resolved_core = config.core_path.resolve()
proc = subprocess.run(cmd, ..., cwd=str(resolved_core))
```

But since `_build_subprocess_env` already validates the resolved path, passing the resolved path as cwd is straightforward and eliminates the mismatch.

### Is `core_path` always resolved (absolute) by the time it reaches `_run_subprocess`?

**No** — `config.core_path` is whatever was passed into `OpenAntConfig(core_path=...)`. It may be a relative path, a symlink, or contain `..` components. The resolution only happens inside `_build_subprocess_env`. The `cwd` parameter to `subprocess.run` receives the unresolved path.

The OS kernel resolves the `cwd` symlink when `chdir(2)` is called during subprocess startup, so operationally this works. But the code has an asymmetry that should be documented or fixed.

### Test Coverage Assessment (BUG-NEW)

**Tests in `TestBugNewCwdIsolation`:** Three tests.

1. `test_cwd_set_in_subprocess_run` — Static check: `"cwd="` appears in scanner.py source. **PASS but weak** — this only checks the string appears, not that it's wired to the correct variable.
2. `test_cwd_resolves_to_core_path` — Static check: `"core_path"` appears within 60 chars after `"cwd="` in source. **PASS but fragile** — a whitespace change or comment between `cwd=` and `core_path` would break this.
3. `test_would_fail_without_fix` — Structural: verifies Raptor has `core/__init__.py` and lacks `core/scanner.py`. **PASS — good motivating test.**

**Missing tests:**
1. `test_cwd_symlink_does_not_cause_shadow`: Create a symlink to a fake openant-core, configure it as `core_path`, verify `_run_subprocess` correctly resolves and uses it without import shadowing.
2. `test_cwd_resolved_path_equals_pythonpath_prefix`: Verify that `cwd` (after symlink resolution) equals the first entry in `PYTHONPATH` built by `_build_subprocess_env`.
3. `test_subprocess_run_called_with_cwd_kwarg` (integration): Patch `subprocess.run`, call `_run_subprocess`, assert the mock was called with `cwd=` argument set to a path under the fake `core_path`.

**Verdict:** BUG-NEW fix is **CORRECT** and **functional**, with a minor path-asymmetry that is low-risk. Tests are present but use static string matching (brittle) rather than behavioral assertions.

---

## Variant Hunt — Similar Bugs Elsewhere {#variant-hunt}

### Variant 1: `subprocess.run`/`Popen` with `-m` module and no `cwd`

**Only one production instance of `-m module` subprocess invocation:**

| File | Line | Call | Has cwd? |
|------|------|------|----------|
| `packages/openant/scanner.py` | 136 | `sys.executable, "-m", "openant"` | YES (fixed) |
| `core/sandbox/_spawn.py` | 1001 | `sys.executable, "-m", "core.sandbox.tracer"` | Via `os.execvpe` (not subprocess.run) — no cwd needed since it's an exec in a child after fork |

The Semgrep (`raptor_agentic.py:523`) and CodeQL (`raptor_agentic.py:548`) `subprocess.Popen` calls use **script path** invocation (`python3 path/to/script.py`), not `-m`, so the `''` shadowing risk does not apply — Python's `-m` special-casing of `sys.path[0]` only activates for `-m` invocations.

**Result:** No additional variants of the `-m` shadow bug.

### Variant 2: JSON files read assuming only one format (dict or list)

| File | Lines | Format Assumed | Actual Risk |
|------|-------|---------------|-------------|
| `packages/llm_analysis/agent.py` | 311 | dict only (`data.get("findings")`) | **ACTIVE BUG** in `--openant-only` mode (plain list written at raptor_agentic.py:801) |
| `packages/exploitability_validation/report.py` | 29, 162, 189 | dict only (`findings_data.get("findings")`) | Latent — only called from `/validate` pipeline which always writes dict |
| `packages/exploitation/bootstrap.py` | 148, 247, 253, 265 | dict only (`data.get(...)`) | Latent — only reads `/validate` pipeline output dirs |
| `core/coverage/summary.py` | 145-150, 476-481 | Both handled | None — correct |
| `core/project/findings_utils.py` | 65-68 | Both handled | None — correct |
| `packages/diagram/renderer.py` | 39-40 | dict only (`fdata.get("findings")`) | Low — renderer has null check before the `.get()` call |

**Notable:** `core/coverage/summary.py` and `core/project/findings_utils.py` correctly handle both formats. The three packages that don't are all downstream of the `/validate` pipeline which guarantees dict format — making this a latent (not currently triggerable) bug, **except** for the `--openant-only` path.

### Variant 3: `total_findings` or `unique_count` arithmetic that could be inflated

| File | Lines | Counter | Fed to Dedup? | Risk |
|------|-------|---------|---------------|------|
| `raptor_agentic.py` | 641 | `total_findings = semgrep + codeql` | YES (line 728) | None — OpenAnt excluded (fix applied) |
| `raptor_agentic.py` | 774, 789, 802 | `validated_findings +=` | Only for display/report | None — incremented AFTER dedup |
| `packages/exploitability_validation/agentic.py` | 131, 161, 165 | `validated_findings`, `unique_count` | Internal only | None — no OpenAnt mixed in |
| `core/project/merge.py` | 164 | `total_findings += len(findings)` | Only for merge verification | None — independent counter for project merge, not fed to run_validation_phase |
| `packages/codeql/agent.py` | 344 | `total_findings += result.findings_count` | Into `codeql_report.json` | None — CodeQL-internal, feeds `codeql_metrics` which raptor_agentic.py reads correctly |

**Result:** No additional arithmetic inflation variants found. The fix correctly isolated the OpenAnt count from the SARIF dedup baseline.

---

## Test Coverage Assessment {#test-coverage}

### Tests Present

| Test Class | File | What It Tests | Quality |
|-----------|------|---------------|---------|
| `TestBugR011OpenantFindingsMerge` | test_phase1b_integration.py | Merge write (plain list format) | Good functional coverage |
| `TestBugR016DictFormatMerge` | test_phase1b_integration.py | Merge write (dict format) | Good functional coverage |
| `TestBugR011FragilityCorruptedFindingsFile` | test_phase1b_integration.py | Corrupted JSON, non-dict elements | Good defensive coverage |
| `TestCleanupB1ToctouRaceWindow` | test_phase1b_integration.py | TOCTOU: file deleted between exists/load | Weak — pins wrong contract (SARIF loss undetected) |
| `TestBugR011RaptorAgenticMergeBlock` | test_phase1b_integration.py | Static source text checks | Brittle — checks for string presence only |
| `TestBugNewCwdIsolation` | test_scanner.py | cwd= parameter presence | Weak — static string match |
| `TestBugR013PythonpathValidation` | test_scanner.py | PYTHONPATH validation logic | Good behavioral coverage |
| `TestBugR015StderrPersistence` | test_scanner.py | Stderr persistence | Static check |

### Missing Tests (Prioritized)

**Priority 1 — Blocking active bugs:**

1. **`test_openant_only_mode_writes_dict_not_list`** (test_phase1b_integration.py)
   - Arrange: `openant_extra_findings = [{"id": "X"}]`, no prior `validation/findings.json`
   - Act: run the `else` branch (no prior file)
   - Assert: written file is a dict with `"findings"` key, NOT a plain list
   - Rationale: Currently Line 801 writes a plain list → Phase 3 AttributeError

2. **`test_phase3_reads_merged_dict_format`** (test_phase1b_integration.py or test_load_findings.py)
   - Arrange: write merged findings.json as dict (post-BUG-R-016-fix format)
   - Act: call `convert_validated_to_agent_format(data)` where data is the dict
   - Assert: OpenAnt findings appear in output
   - Rationale: Confirms Phase 3 can actually consume what Phase 1b merger writes

**Priority 2 — Arithmetic coverage:**

3. **`test_dedup_arithmetic_openant_not_included`** (test_phase1b_integration.py)
   - Mock `run_validation_phase` to return `({"duplicates_removed": 2}, 8)`
   - Set `openant_extra_findings = [{"id": "oa-1"}, {"id": "oa-2"}]`
   - After merge, assert `validated_findings == 8 + 2 = 10` (not 12 or 8)
   - Assert `duplicates_removed == 2` (OpenAnt count not included)

**Priority 3 — Defensive:**

4. **`test_null_json_findings_file_handled`**: Verify that a `findings.json` containing JSON `null` does not silently drop SARIF data.
5. **`test_cwd_equals_resolved_pythonpath_prefix`** (test_scanner.py): Behavioral test that `cwd` passed to subprocess matches the resolved PYTHONPATH prefix.
6. **`test_subprocess_run_called_with_cwd`** (test_scanner.py): Patch `subprocess.run`, call `_run_subprocess`, assert `cwd=` kwarg was passed.

---

## Summary Verdict Table {#summary-verdict-table}

| Bug | Fix Applied? | Fix Correct? | Remaining Risk | Severity | Tests Adequate? | Pass/Fail |
|-----|-------------|-------------|----------------|----------|-----------------|-----------|
| BUG-A (dedup inflation) | YES | YES | None on dedup arithmetic | None | No — arithmetic path untested | **PASS with warning** |
| BUG-R-016 (merge format) | YES (dict branch) | PARTIAL | `--openant-only` writes plain list → Phase 3 crashes | HIGH | No — Phase 3 read path untested; `--openant-only` path untested | **FAIL** |
| BUG-NEW (cwd isolation) | YES | YES | Minor: `cwd` uses unresolved path vs PYTHONPATH uses resolved | Low | No — static string checks only, no behavioral tests | **PASS with warning** |

### FAIL Item Detail: BUG-R-016

The BUG-R-016 fix correctly handles the **merge write** for the common case (Semgrep/CodeQL + OpenAnt). However, the `--openant-only` mode triggers an **unfixed code path**:

- `raptor_agentic.py:801`: `save_json(validation_findings_path, openant_extra_findings)` — writes plain list
- `packages/llm_analysis/agent.py:311`: `data.get("findings", [])` — crashes on plain list with `AttributeError`

This means `raptor.py agentic --openant-only` will crash during Phase 3 analysis whenever there are findings. This is a **regression in the `--openant-only` path** that the current tests do not catch.

---

## Appendix: Key File Locations

| Item | Path | Relevant Lines |
|------|------|----------------|
| Phase 1b OpenAnt block | `raptor_agentic.py` | 662–716 |
| `total_findings` baseline | `raptor_agentic.py` | 641 |
| Dedup arithmetic | `raptor_agentic.py` | 728; `agentic.py` 161–165 |
| Merge block (BUG-R-016 fix) | `raptor_agentic.py` | 750–806 |
| Plain list write (`--openant-only`) | `raptor_agentic.py` | 801 |
| Phase 3 findings read | `raptor_agentic.py` | 831–838 |
| `convert_validated_to_agent_format` | `packages/llm_analysis/agent.py` | 297–339 |
| `_load_validated_findings` | `packages/llm_analysis/agent.py` | 850–864 |
| `run_validation_phase` | `packages/exploitability_validation/agentic.py` | 97–174 |
| `convert_sarif_data` | `packages/exploitability_validation/orchestrator.py` | 419–462 |
| `_run_subprocess` + cwd fix | `packages/openant/scanner.py` | 55–87 |
| `_build_subprocess_env` (resolved path) | `packages/openant/scanner.py` | 152–175 |
| `load_json` (strict behavior) | `core/json/utils.py` | 16–33 |
| Phase 1b regression tests | `packages/openant/tests/test_phase1b_integration.py` | all |
| CWD isolation tests | `packages/openant/tests/test_scanner.py` | 170–215 |
| Phase 3 findings format tests | `packages/llm_analysis/tests/test_load_findings.py` | all |
