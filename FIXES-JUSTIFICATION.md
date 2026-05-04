# OpenAnt Integration — Fixes Justification

This document provides the complete from-scratch justification for every bug fix
and architectural decision in the `feat/openant-integration` branch. It is
written so that a future engineer (or a Claude session with no context) can:

1. Understand WHY each fix was needed (root cause, not just symptom)
2. Independently VERIFY the old code was broken (minimal reproducer)
3. Re-APPLY the fix from scratch if commits are ever reverted
4. Locate the TEST that guards against regression

Fixes are ordered by commit chronology. Each entry is self-contained.

---

## Architecture: Why subprocess isolation?

**Decision**: OpenAnt is invoked via `subprocess.run`, with `PYTHONPATH` set
to `config.core_path` — never via `sys.path.insert` in the Raptor process.

**Why**: Both Raptor and OpenAnt have a top-level `core/` package. If
`core_path` is added to `sys.path` in the Raptor process, Python's module
cache is shared and the first `import core.scanner` either finds Raptor's
`core/` (no `scanner.py`) or OpenAnt's `core/` — whichever is first. This
is a non-deterministic shadowing bug that manifests as `ModuleNotFoundError`
or the wrong `core` being imported.

Subprocess isolation guarantees clean separation: each process has its own
import resolution, no cross-contamination.

**Alternative considered**: Namespace packages (`core.openant.*`). Rejected
because it would require modifying OpenAnt's internal package structure, adding
coupling. Subprocess is zero-coupling by construction.

---

## BUG-NEW — `cwd` not set in subprocess.run

**Commit**: `3cd98c8`
**File**: `packages/openant/scanner.py:85`

### Root Cause

Python adds `''` (empty string, meaning "current working directory") as the
first entry in `sys.path` for any `-m` invocation. When Raptor launches
`python -m openant scan ...`, the `cwd` of the subprocess defaulted to
whatever directory Raptor's launcher was in — typically the Raptor repo root,
which contains `core/__init__.py`. Python then found Raptor's `core/` before
OpenAnt's, giving `ModuleNotFoundError: No module named 'core.scanner'`.

### The Fix

```python
# Before (buggy):
proc = subprocess.run(cmd, capture_output=True, text=True, env=env)

# After:
proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                      cwd=str(config.core_path))
```

Setting `cwd=config.core_path` makes Python's `''` resolve to
`openant-core/`, not the Raptor root, so `core.scanner` resolves correctly.

### Verification

```bash
# Without fix: launch from Raptor root, PYTHONPATH unset
cd /path/to/raptor-integration
python -m openant scan ...  # ModuleNotFoundError: No module named 'core.scanner'

# With fix: same command but subprocess cwd=openant-core
# Works because '' in sys.path → openant-core, not raptor root
```

### Test

`test_scanner.py::TestBugNewCwdIsolation`:
- Checks `"cwd="` is present in `scanner.py` source
- Checks `"core_path"` appears immediately after `cwd=`
- Verifies Raptor's `core/__init__.py` exists (proving shadow would occur without fix)

---

## BUG-R-013 — PYTHONPATH set without validation

**Commit**: `c78ff8b`
**File**: `packages/openant/scanner.py:180-203`

### Root Cause

`_build_subprocess_env()` wrote `config.core_path` directly into `PYTHONPATH`
without checking (a) that the path exists, or (b) that it actually IS an
`openant-core` directory. An attacker controlling `OPENANT_CORE` env var could
redirect Python's import resolution to a malicious directory.

### The Fix

```python
# After:
try:
    resolved = config.core_path.resolve(strict=True)  # raises FileNotFoundError if absent
except FileNotFoundError as e:
    raise RuntimeError(f"OpenAnt core path does not exist: {config.core_path}") from e
if not (resolved / "core" / "scanner.py").exists():
    raise RuntimeError(f"PYTHONPATH target {resolved} is not an openant-core directory")
```

`resolve(strict=True)` also collapses `../` components, preventing path
traversal. The `core/scanner.py` sentinel check verifies the directory is
actually OpenAnt.

### Verification

```python
# Minimal reproducer — without fix, this silently writes malicious path:
config = OpenAntConfig(core_path=Path("/tmp/evil"))
env = _build_subprocess_env(config)
# env["PYTHONPATH"] == "/tmp/evil" — attacker controls imports

# With fix:
# RuntimeError: PYTHONPATH target /tmp/evil is not an openant-core directory
```

### Test

`test_scanner.py::TestBugR013PythonpathValidation`:
- Valid path → accepted, PYTHONPATH set correctly
- `../` components → resolved and collapsed (no `..` in output)
- Nonexistent path → RuntimeError
- Wrong directory (no `core/scanner.py`) → RuntimeError with "openant-core" in message

---

## CLEANUP-C1 — FileNotFoundError vs RuntimeError at the boundary

**Commit**: `af4faaa`
**File**: `packages/openant/scanner.py:188-194`

### Root Cause

`raptor_openant.py` catches only `RuntimeError` around the config build.
`Path.resolve(strict=True)` raises `FileNotFoundError` for nonexistent paths.
Before C1, a nonexistent `OPENANT_CORE` would propagate as uncaught
`FileNotFoundError` — a "Fatal error" in Raptor's logs instead of a graceful
"OpenAnt unavailable" message.

### The Fix

Wrap `resolve(strict=True)` and re-raise as `RuntimeError`:

```python
try:
    resolved = config.core_path.resolve(strict=True)
except FileNotFoundError as e:
    raise RuntimeError(
        f"OpenAnt core path does not exist: {config.core_path} "
        f"(set OPENANT_CORE to a valid libs/openant-core directory)"
    ) from e
```

### Test

`test_scanner.py::TestCleanupC1FileNotFoundHandling.test_nonexistent_core_path_raises_runtime_error_not_filenotfound`:
Passes `Path("/nonexistent/xyz")`, asserts `RuntimeError` is raised (not
`FileNotFoundError`), and checks message contains "openant" or "not found".

---

## BUG-R-015 — stderr truncated to 600 chars

**Commits**: `7ec2c34`, `ff64933`, `6b08172`
**File**: `packages/openant/scanner.py:99-116`

### Root Cause

The original code only showed the first 600 characters of stderr in the error
message. If OpenAnt produced a multi-line traceback (typical for any Python
exception), the actual error was truncated away — only import noise or the
beginning of the stack trace remained.

Secondary fragility: no cap on stderr size. A misbehaving OpenAnt that spammed
stderr in a tight loop could fill the disk.

### The Fix

```python
STDERR_MAX_BYTES = 1_000_000  # 1 MiB cap

if proc.stderr:
    stderr_to_write = proc.stderr[:STDERR_MAX_BYTES]
    if len(proc.stderr) > STDERR_MAX_BYTES:
        stderr_to_write += f"\n\n[truncated — original was {len(proc.stderr)} bytes]\n"
    (out_dir / "openant.stderr.log").write_text(stderr_to_write)

# Error message points to the log file:
snippet = (proc.stderr or "")[:600].strip()
return _empty_result(
    f"OpenAnt exited {proc.returncode}: {snippet} "
    f"(full stderr in {out_dir}/openant.stderr.log)"
)
```

Full stderr is persisted to disk; the 600-char snippet is kept for inline
display only. The 1 MiB cap prevents disk abuse.

### Test

`test_scanner.py::TestBugR015StderrPersistence`:
- Error message must reference `openant.stderr.log`
- `scanner.py` source must contain `write_text` in the stderr block
- `STDERR_MAX_BYTES` constant (or `[:1_000_000]` slice) must be present

---

## BUG-R-016 — Merge block rejected dict format silently

**Commit**: `3cd98c8`
**File**: `raptor_agentic.py:763-799`

### Root Cause

Raptor's `convert_sarif_to_findings()` writes `validation/findings.json` as:

```json
{"stage": "A", "timestamp": "...", "target_path": "...", "source": "sarif", "findings": [...]}
```

The original Phase 1b merge code did:

```python
existing = load_json(validation_findings_path)
if isinstance(existing, list):
    existing.extend(openant_extra_findings)
    save_json(...)
else:
    logger.error("unrecognized format; skipping merge")  # ← always hit
```

Since `existing` is always a `dict` (Raptor's format), the `isinstance(list)`
check always failed, the `else` branch always fired, and OpenAnt findings were
silently dropped. Phase 3 never received them.

### The Fix

Add a dict branch before the list branch:

```python
if isinstance(existing, dict) and "findings" in existing:
    # Raptor's wrapped dict format from convert_sarif_to_findings()
    findings_list = existing.get("findings", [])
    if not all(isinstance(f, dict) for f in findings_list):
        logger.error("non-dict elements; skipping merge")
    else:
        findings_list.extend(openant_extra_findings)
        existing["findings"] = findings_list
        save_json(validation_findings_path, existing)
        validated_findings += len(openant_extra_findings)
elif isinstance(existing, list):
    # Plain list (backward compat for any legacy paths)
    ...
else:
    logger.error(f"unrecognized format (got {type(existing).__name__}); skipping merge")
```

### Verification

```python
# Minimal reproducer:
findings_json = {"stage": "A", "timestamp": "...", "findings": [{"id": "sarif-1"}]}
openant_extra = [{"id": "oa-1"}]

# Old code: isinstance(findings_json, list) → False → skipped
# New code: isinstance(findings_json, dict) and "findings" in findings_json → merged
```

### Test

`test_phase1b_integration.py::TestBugR016DictFormatMerge`:
- Dict with existing findings → OpenAnt findings appended, dict structure preserved
- Dict with empty findings → OpenAnt findings are the only entries
- Dict without "findings" key → error logged, merge skipped (defensive)
- Plain list → still merged (backward compat)
- Unrecognized type (int) → error logged, merge skipped

---

## BUG-R-016-VARIANT — `--openant-only` writes plain list → Phase 3 crash

**Commit**: `8f073e9`
**File**: `raptor_agentic.py:800-817`

### Root Cause

When running `--openant-only`, no SARIF scan runs, so `validation/findings.json`
doesn't exist before Phase 1b. The `else` branch (file doesn't exist) wrote:

```python
save_json(validation_findings_path, openant_extra_findings)  # plain list!
```

Phase 3 (`packages/llm_analysis/agent.py:_load_validated_findings`) reads
this file and calls:

```python
data = load_json(findings_path)
findings = data.get("findings", [])  # AttributeError: list has no .get()
```

This crashed with `AttributeError` on every `--openant-only` run.

### The Fix

```python
# Before (buggy):
save_json(validation_findings_path, openant_extra_findings)

# After:
(out_dir / "validation").mkdir(exist_ok=True)
save_json(validation_findings_path, {
    "stage": "A",
    "timestamp": datetime.now().isoformat(),
    "source": "openant",
    "findings": openant_extra_findings,
})
```

Matches Raptor's standard `{"stage":...,"findings":[...]}` format. Phase 3
can now call `.get("findings", [])` without crashing.

**Also required**: `from datetime import datetime` at module level (line 23).

### Verification

```python
# Without fix:
data = [{"id": "oa-1"}]           # what was written
data.get("findings", [])           # AttributeError: 'list' object has no attribute 'get'

# With fix:
data = {"stage": "A", ..., "findings": [{"id": "oa-1"}]}
data.get("findings", [])           # [{"id": "oa-1"}] ✓
```

### Test

`test_phase1b_integration.py::TestBugR016VariantOpeantonlyPath`:
- `test_no_prior_file_writes_dict_not_plain_list` — result is a dict, not list
- `test_no_prior_file_dict_has_required_stage_key` — "stage" key present
- `test_no_prior_file_source_is_openant` — "source" == "openant"
- `test_phase3_format_compatible_get_call_does_not_crash` — `.get("findings")`
  succeeds without AttributeError
- `test_static_check_else_branch_writes_dict` — grep `raptor_agentic.py` source

---

## BUG-R-017 — `sys.executable` lacks tree-sitter bindings

**Commit**: `2fb1e85`
**File**: `packages/openant/scanner.py:135-150, 158`

### Root Cause

The original `_build_command()` used `sys.executable` (Raptor's Python 3.14)
as the Python interpreter for OpenAnt. OpenAnt's parsers for C, Ruby, PHP, and
JavaScript require language-specific tree-sitter packages
(`tree_sitter_c`, `tree_sitter_ruby`, `tree_sitter_php`,
`tree_sitter_javascript`). These are only installed in OpenAnt's own venv at
`openant-core/.venv/bin/python3`.

Scans using Raptor's Python silently failed with:
`ModuleNotFoundError: No module named 'tree_sitter_c'`

Python and Go scans worked because Python uses the `ast` stdlib module and Go
uses a compiled binary (`go_parser/go_parser`).

### The Fix

```python
def _find_venv_python(core_path: Path) -> str:
    for candidate in ("python3", "python3.11", "python3.12", "python3.13", "python"):
        venv_python = core_path / ".venv" / "bin" / candidate
        if os.access(venv_python, os.X_OK):  # X_OK: actually executable, not just present
            return str(venv_python)
    return sys.executable  # fallback only

def _build_command(repo_path, out_dir, config):
    python_exe = _find_venv_python(config.core_path)  # was: sys.executable
    ...
```

`os.access(path, os.X_OK)` checks actual executability (mode bits), not just
file existence — avoids returning a zero-byte placeholder that would fail at
subprocess launch with a cryptic `PermissionError`.

### Test

`test_scanner.py::TestBugR017VenvPythonSelection`:
- Venv python present → venv python returned
- No venv → `sys.executable` returned
- `_build_command` uses venv python as `cmd[0]`
- `sys.executable` does not appear in `_build_command` body (static check)

---

## os.access fix — `.exists()` insufficient for executability

**Commit**: `4be5050`
**File**: `packages/openant/scanner.py:148`

### Root Cause (judge finding)

The original BUG-R-017 fix used `venv_python.exists()` to check for the venv
Python. `.exists()` only checks whether the file is present in the filesystem —
it returns `True` for a zero-byte placeholder, a dangling symlink target, or a
file with mode `000`. Any of these would be returned as the chosen Python
interpreter and then fail at `subprocess.run` with a cryptic `PermissionError`
or `OSError`.

### The Fix

```python
# Before:
if venv_python.exists():

# After:
if os.access(venv_python, os.X_OK):
```

`os.access(path, os.X_OK)` checks actual executability using the real process
UID/GID. Returns `False` for zero-byte files, wrong mode bits, or symlinks to
nonexistent targets.

Note: the other `.exists()` call in `scanner.py` (line 195, checking for the
`core/scanner.py` marker file) remains correct — that IS a pure existence check.

---

## BUG-R-018 — `--language zig` not a valid CLI choice

**Commit**: `2fb1e85`
**File**: `packages/openant/scanner.py:31, 162`

### Root Cause

OpenAnt's `--language` CLI argument accepts only:
`{auto, python, javascript, go, c, ruby, php}`

Languages like Zig are auto-detected by file extension but are NOT in the
argparse enum. Passing `--language zig` produced:

```
error: argument --language: invalid choice: 'zig'
       (choose from auto, python, javascript, go, c, ruby, php)
```

OpenAnt exited immediately with a non-zero code, producing no output.

### The Fix

```python
_OPENANT_CLI_LANGUAGES = {"auto", "python", "javascript", "go", "c", "ruby", "php"}

def _build_command(repo_path, out_dir, config):
    lang = config.language if config.language in _OPENANT_CLI_LANGUAGES else "auto"
    cmd = [..., "--language", lang, ...]
```

Unrecognized languages fall back to `"auto"`, which uses file extension
detection — the correct behavior for Zig and any future languages.

### Test

`test_scanner.py::TestBugR018ZigLanguageFallback`:
- `language="zig"` → `--language auto` in command
- All known languages pass through unchanged
- `language="cobol"` → `--language auto`
- `_OPENANT_CLI_LANGUAGES` constant pinned to exact expected set

---

## BUG-OA-001 — `build_pipeline_output()` return type mismatch

**Location**: `libs/openant-core/core/reporter.py:192`,
             `libs/openant-core/core/scanner.py:386`,
             `libs/openant-core/openant/cli.py:384,523`

### Root Cause

`build_pipeline_output()` was annotated `-> str` but returned `(path, count)`,
a tuple. The `core/scanner.py` caller at line 386 didn't capture the return
value at all (discarded silently). The `cli.py` callers also had inconsistent
handling.

Any future caller writing `path = build_pipeline_output(...)` would get a
tuple where a string was expected, causing subtle downstream errors.

### The Fix

```python
# reporter.py:192 — before:
) -> str:

# After:
) -> tuple[str, int]:
```

```python
# scanner.py:386 — before:
build_pipeline_output(results_path=..., output_path=..., ...)

# After:
_, findings_count = build_pipeline_output(results_path=..., output_path=..., ...)
```

All three call sites now unpack the tuple explicitly. The annotation matches
reality.

### Verification

```bash
grep -n "build_pipeline_output" libs/openant-core/openant/cli.py
# line 384: path, findings_count = ...     ✓
# line 523: _, _ = ...                     ✓

grep -n "build_pipeline_output" libs/openant-core/core/scanner.py
# line 386: _, findings_count = ...        ✓

grep -n "-> tuple" libs/openant-core/core/reporter.py
# line 192: ) -> tuple[str, int]:          ✓
```

---

## BUG-R-011 — OpenAnt findings orphaned before Phase 3

**File**: `raptor_agentic.py` Phase 1b block (~line 662-818)

### Root Cause

Phase 3 (`AutonomousSecurityAgentV2`) reads `validation/findings.json` to
obtain the list of findings to analyze. The original Phase 1b code computed
translated OpenAnt findings but never wrote them into `validation/findings.json`
— it wrote only to `openant_findings.json` (a separate output artifact).

Phase 3 therefore never saw OpenAnt findings, rendering the `--openant` flag
useful only for the standalone `openant_findings.json` report, not for the
full agentic pipeline.

### The Fix

After translating OpenAnt findings, merge them into `validation/findings.json`
(creating the file if it doesn't exist). See BUG-R-016 and BUG-R-016-VARIANT
above for the exact merge logic required.

---

## BUG-A — `total_findings` inflated before SARIF dedup

**Commit**: `3cd98c8`
**File**: `raptor_agentic.py` Phase 1b (~line 700-730)

### Root Cause

An earlier version of Phase 1b added `total_findings += len(openant_extra_findings)`
before the SARIF deduplication step. `total_findings` is used as the baseline
for SARIF dedup — inflating it with OpenAnt findings shifted the dedup
threshold and could cause SARIF findings to be incorrectly dropped.

### The Fix

Remove `total_findings += len(openant_extra_findings)` from before
`run_validation_phase`. The OpenAnt count is added to `validated_findings`
inside the merge block (after dedup), which is the correct place.

### Verification

```bash
grep -n "total_findings.*openant\|openant.*total_findings" raptor_agentic.py
# (no matches) ✓
```

---

## Summary table

| Fix | File(s) | Guard test |
|-----|---------|-----------|
| BUG-NEW cwd isolation | `scanner.py:85` | `test_scanner.py::TestBugNewCwdIsolation` |
| BUG-R-013 PYTHONPATH validation | `scanner.py:186-203` | `test_scanner.py::TestBugR013PythonpathValidation` |
| CLEANUP-C1 FileNotFoundError unification | `scanner.py:188-194` | `test_scanner.py::TestCleanupC1FileNotFoundHandling` |
| BUG-R-015 stderr persistence | `scanner.py:99-116` | `test_scanner.py::TestBugR015StderrPersistence` |
| BUG-R-016 dict format merge | `raptor_agentic.py:763-799` | `test_phase1b_integration.py::TestBugR016DictFormatMerge` |
| BUG-R-016-VARIANT plain list crash | `raptor_agentic.py:800-817` | `test_phase1b_integration.py::TestBugR016VariantOpeantonlyPath` |
| BUG-R-017 venv Python | `scanner.py:135-150,158` | `test_scanner.py::TestBugR017VenvPythonSelection` |
| os.access fix | `scanner.py:148` | covered by BUG-R-017 tests |
| BUG-R-018 zig language | `scanner.py:31,162` | `test_scanner.py::TestBugR018ZigLanguageFallback` |
| BUG-OA-001 tuple return type | `reporter.py:192`, `scanner.py:386`, `cli.py:384,523` | OpenAnt test suite (447 pass) |
| BUG-R-011 orphaned findings | `raptor_agentic.py:662-818` | `test_phase1b_integration.py::TestBugR011RaptorAgenticMergeBlock` |
| BUG-A dedup baseline | `raptor_agentic.py:~700` | `test_phase1b_integration.py` |

All 86 Raptor integration tests pass. All 447 OpenAnt core tests pass.

```bash
# Verify from scratch:
cd raptor-integration
python3 -m pytest packages/openant/tests/ -q
# Expected: 86 passed, 5 subtests passed

cd libs/openant-core
.venv/bin/python3 -m pytest tests/ --ignore=tests/smoke -q
# Expected: 447 passed, 5 skipped
```
