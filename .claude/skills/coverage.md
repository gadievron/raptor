---
name: coverage
description: Coverage tracking and reporting — what tools examined what code
user-invocable: false
---

# Coverage System

Tracks what each tool examined during analysis. Answers: "what code has been checked, by whom, and what's missing?"

## Architecture

Three layers:

1. **Collection** — the coverage plugin hook (`plugins/coverage/`) appends file paths to `.reads-manifest` on every Read tool call. Per-tool records (`coverage-<tool>.json`) are written by scanners and the run lifecycle.
2. **Store** — `CoverageStore` (`core/coverage/store.py`) persists a unified `coverage.json` keyed by (file, line-interval, tool). Survives across runs. Updated at run completion via importers.
3. **Reporting** — `render_coverage()` and `coverage_view()` join store state with per-run execution detail.

## Coverage Records

Each tool writes a `coverage-<tool>.json` in the run output directory:

| File | Written by | Contents |
|------|-----------|----------|
| `coverage-semgrep.json` | Scanner (`/scan`) | files examined, policy groups, errors |
| `coverage-codeql.json` | Scanner (`/scan`, `/codeql`) | files examined, packs, rules, extraction failures |
| `coverage-read.json` | Lifecycle end (any status) | files the LLM read (from `.reads-manifest`) |
| `coverage-llm.json` | `/validate` stage 1; operator/agent `--mark` | items analysed (from findings + marks) |
| `coverage-journal.json` | `/agentic` | functions reviewed (from review-journal entries) |
| `coverage-fuzz.json` | `/fuzz` (gcov-instrumented targets) | per-function runtime reach (never counts as review) |

Records are written automatically — no manual action needed. The summary
ends with a `Read tracking:` health line (did the LLM-read capture leg
ever engage?) and, in project mode, a `Progress:` trend line from
`coverage-progress.jsonl` (one row appended per completed run).

## Coverage Store

`CoverageStore` (`core/coverage/store.py`) is the persistent coverage sink. Key APIs:

```python
from core.coverage.store import CoverageStore

store = CoverageStore(project_dir / "coverage.json")   # loads if present

# Mark lines as examined by a tool
store.mark("src/auth.c", 10, 50, "audit")

# Query who examined a line or a function's span
tools = store.who_checked("src/auth.c", 25)
tools = store.who_checked_function("src/auth.c", 10, 50)
```

Line-range tracking uses inclusive `[lo, hi]` intervals, kept sorted and coalesced per tool.

### Tool Registry

Tool labels are classified by category and depth (`core/coverage/registry.py`):

| Category | Depth | Tools |
|----------|-------|-------|
| static | scanned | semgrep, coccinelle, codeql |
| llm | scanned | read, understand |
| llm | analysed | claude, llm, audit, validate, agentic, journal, mark, annotations |
| runtime | runtime-tested | gcov, lcov, llvm-cov, afl, fuzz, bincov, drcov, frida, sancov, coverage.py, pytest |

The registry source is authoritative for the full label set.

A file the LLM merely read (`read`) is `scanned`, not `analysed` — it does not count as "reviewed". Review requires depth >= `analysed`.

### Store Importers

At run completion, `_snapshot_run_coverage` in `core/run/metadata.py` imports data into the store:

```python
from core.coverage.importer import (
    import_run_dir,        # import all coverage-*.json records
    import_run_findings,   # import findings as function-level coverage
    import_journal,        # import review journal entries
    import_annotations,    # import human-authored annotations
)
```

## CLI

`raptor-coverage-summary` accepts any of: no argument (active project), project name, target path, project output dir, or run dir. It resolves automatically.

**Summary and detail:**
```bash
libexec/raptor-coverage-summary                          # active project
libexec/raptor-coverage-summary --detailed               # per-file table
libexec/raptor-coverage-summary /tmp/vulns               # resolves to project
libexec/raptor-coverage-summary out/projects/vulns/validate-20260411/  # specific run
```

**Find gaps** (unreviewed functions):
```bash
libexec/raptor-coverage-summary --gaps
```
Output: `09_stack_overread.c:record`

**Mark as reviewed** — two options:

Inline (few functions):
```bash
libexec/raptor-coverage-summary <run_dir> --mark src/auth.c:check_pw src/db.c:query
```

From file (many functions — preferred for `/understand` and `/validate`):
```bash
libexec/raptor-coverage-summary <run_dir> --mark-file "$OUTPUT_DIR/reviewed-items.json"
```

The JSON file is a flat array of `{file, item}` objects. The `item` key matches any inventory item (function, global, struct, macro). `function` is accepted as a backwards-compatible alias. An optional `status` (`clean` / `suspicious` / `finding` / `dormant`) sets the journaled verdict; default `clean`.
```json
[
    {"file": "src/auth.c", "item": "check_pw"},
    {"file": "src/auth.c", "item": "credentials", "status": "suspicious"},
    {"file": "src/db.c", "item": "query"}
]
```

Write this file using the Write tool, then pass it to `--mark-file`.

**Durability:** in a project context (run dir under a project with a checklist), every mark is ALSO journaled into the project's `review-journal-index.json` as a review assertion (`producer=mark`, `model=operator`) with a source hash. Journaled marks survive run deletion, suppress `/audit` gaps cross-run through the hash-verified fold, and resurface automatically when the function's source drifts. On a standalone run dir the mark stays record-only (same-run suppression only).

**Remove from reviewed** (undo incorrect mark):
```bash
libexec/raptor-coverage-summary <run_dir> --unmark src/auth.c:check_pw
```
Unmark also withdraws any journaled mark (an error-verdict entry replaces it in the index), so the function returns to the gap list.

**Import external runtime coverage:**
```bash
libexec/raptor-coverage-summary <run_dir> --import coverage.info --format lcov --tool gcov
```

**Via project command** (summary and detail only):
```bash
libexec/raptor-project-manager coverage
libexec/raptor-project-manager coverage --detailed
```

## Python API

Coverage reporting is store-backed and unified: one `render_coverage()` shows
coverage **state** (from the persistent store) plus per-run tool **execution**
detail (from the records).

```python
from pathlib import Path
from core.coverage.store_summary import (
    render_coverage,        # unified report string (state + execution detail)
    render_run_coverage,    # single-run convenience wrapper
    coverage_view,          # the store-backed view dict (for --fail-under etc.)
    store_coverage_threshold_met,  # threshold check
)

# Single run (resolves checklist/coverage.json/annotations under the dir):
print(render_run_coverage(Path("out/projects/vulns/validate-20260411/")))

# Explicit inputs (a run dir, or a project's output dir + its run dirs):
report = render_coverage(run_dirs, checklist, store_path, annotations_base)
print(report)

# Programmatic view (e.g. to apply a threshold):
view = coverage_view(run_dirs, checklist, store_path, annotations_base)
if not store_coverage_threshold_met(view, fail_under=80.0):
    print("Coverage below threshold")
```

### View dict structure

```python
{
    "target": "...", "content_id": "content:...",
    "total_functions": 11,                 # all items, any kind
    "items_by_kind": {"function": 8, "global": 2, "interstitial": 1},
    "functions_covered": 10,               # examined by any tool (verdict-based)
    "functions_by_category": {"static": 10, "llm": 7, "runtime": 0},
    "llm_reviewable": 8,                    # function + top_level items only
    "gap_no_tool": 1, "gap_no_llm": 1,     # gap_no_llm counts reviewable kinds
    "llm_gap_functions": [{"file": ..., "function": ..., "line": ...}],
    "verdicts": {"clean": 9, "open": 1, "found_then_lost": 0, "unexamined": 1},
    "review_gap": [...],
    "provenance": {...},
}
```

### Execution detail (per-run tool diagnostics)

```python
from core.coverage.summary import execution_detail, format_execution_detail
detail = execution_detail(run_dirs, checklist)
# {"tools": {"semgrep": {"files_examined": 10, "files_total": 10,
#                        "rules_applied": ["crypto"], "packs": [],
#                        "files_failed": [], "version": "1.55"}, ...},
#  "missing_groups": ["injection", "auth", ...]}
print(format_execution_detail(detail))
```

### Reading/writing records directly

```python
from core.coverage.record import (
    load_records,          # load all coverage-*.json from a dir
    write_record,          # write coverage-<tool>.json
    build_from_semgrep,    # from Semgrep JSON output (paths.scanned)
    build_from_codeql,     # from CodeQL SARIF (artifacts, packs, rules)
    build_from_findings,   # from findings.json + reads manifest
    build_from_manifest,   # from reads manifest only
)

# Load all records from a run
records = load_records(Path("out/validate-20260411/"))
for r in records:
    print(f"{r['tool']}: {len(r['files_examined'])} files")

# Write a custom coverage record
write_record(run_dir, {
    "tool": "manual_review",
    "files_examined": ["src/auth.c"],
    "functions_analysed": [{"file": "src/auth.c", "function": "check_password"}],
}, tool_name="manual")
```

## Coverage Record Schema

```json
{
    "tool": "semgrep|codeql|llm|<custom>",
    "timestamp": "2026-04-11T00:00:00+00:00",
    "files_examined": ["path/to/file.c", ...],
    "functions_analysed": [{"file": "...", "function": "..."}, ...],
    "rules_applied": ["rule_or_group_name", ...],
    "packs": ["pack/name@version", ...],
    "version": "1.79.0",
    "files_failed": [{"path": "...", "reason": "..."}, ...]
}
```

Only `tool` and `files_examined` are required. All other fields are optional.

## What Each Tool Records

**Semgrep:** Files from `paths.scanned` in JSON output (produced by `--json-output` flag). Policy groups from scanner config. File-level only — Semgrep scans entire files.

**CodeQL:** Files from SARIF `artifacts` array. Query packs from `tool.extensions`. Rules from `tool.driver.rules`. Extraction failures from `invocations.toolExecutionNotifications`.

**LLM (read):** Files from the reads manifest (`.reads-manifest`, populated by coverage plugin hook on every Read tool call). Depth: scanned only.

**LLM (analysed):** Functions from `findings.json` — any function with a finding or ruling counts as analysed. Also from the review journal (`review-journal.jsonl`), which is the primary source for function-level coverage in `/audit`.

## Inventory (denominator)

Coverage percentages use `checklist.json` as the denominator:
- **Files:** total files in checklist
- **Items:** total functions/globals/macros per file (`items` key, fallback `functions`)
- **SLOC:** source lines of code per file

The checklist is built by `/validate` Stage 0 or `/understand` MAP-0.

## Missing Groups

Semgrep policy groups are compared against `RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK` to identify which vulnerability classes weren't scanned. Missing groups appear in the "Action needed" section.

## Gap Computation in /audit

`core/audit/gaps.py:compute_gaps` determines which functions still need review. Coverage sources, in priority order:

1. **Review journal** — `review-journal.jsonl` (per-run) and `review-journal-index.json` (project-level). This is the primary mid-run and cross-run source.
2. **Coverage records** — per-tool `coverage-*.json` in the run dir: review-grade `functions_analysed` entries (an operator `--mark`, `coverage-llm.json`, `coverage-journal.json`) suppress gaps; scanned-depth labels (`read`, `understand`), whole-file `files_examined`, and runtime records (`coverage-fuzz.json` is reachability evidence, not review) never do. Legacy `coverage-record.json` still loads for pre-per-tool-split runs.

A function is a gap when it has no entry in either source. The durable
`coverage.json` store is a query-time projection (summaries, `--gaps`),
not a `compute_gaps` input.
