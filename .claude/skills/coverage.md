---
name: coverage
description: Coverage tracking and reporting — what tools examined what code
user-invocable: false
---

# Coverage System

Tracks what each tool examined during analysis. Answers: "what code has been checked, by whom, and what's missing?"

## Coverage Records

Each tool writes a `coverage-<tool>.json` in the run output directory:

| File | Written by | Contents |
|------|-----------|----------|
| `coverage-semgrep.json` | Scanner (`/scan`) | files examined, policy groups, errors |
| `coverage-codeql.json` | Scanner (`/scan`, `/codeql`) | files examined, packs, rules, extraction failures |
| `coverage-llm.json` | Lifecycle complete (`/validate`, `/understand`) | files examined (from reads manifest), items analysed — functions, globals, structs (from findings + mark) |

Records are written automatically — no manual action needed.

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

The JSON file is a flat array of `{file, item}` objects. The `item` key matches any inventory item (function, global, struct, macro). `function` is accepted as a backwards-compatible alias.
```json
[
    {"file": "src/auth.c", "item": "check_pw"},
    {"file": "src/auth.c", "item": "credentials"},
    {"file": "src/db.c", "item": "query"}
]
```

Write this file using the Write tool, then pass it to `--mark-file`.

**Remove from reviewed** (undo incorrect mark):
```bash
libexec/raptor-coverage-summary <run_dir> --unmark src/auth.c:check_pw
```

**Via project command** (summary and detail only):
```bash
libexec/raptor-project-manager coverage
libexec/raptor-project-manager coverage --detailed
```

## Python API

```python
from core.coverage.summary import compute_summary, compute_project_summary
from core.coverage.summary import format_summary, format_detailed

# Single run
summary = compute_summary(Path("out/projects/vulns/validate-20260411/"))
print(format_summary(summary))

# Project-wide (aggregated)
from core.project.project import Project, ProjectManager
p = ProjectManager().load("vulns")
summary = compute_project_summary(p)
print(format_detailed(summary))
```

### Summary dict structure

```python
{
    "inventory": {"files": 10, "sloc": 103, "items": 11},
    "tools": {
        "semgrep": {
            "files_examined": 10, "files_total": 10,
            "rules_applied": ["crypto"], "files_failed": [],
        },
        "codeql": {
            "files_examined": 10, "files_total": 10,
            "packs": ["codeql/cpp-queries"], "rules_applied": [...],
        },
        "llm": {
            "files_examined": 10, "files_total": 10,
            "functions_analysed": 10, "functions_total": 11,
            "sloc_analysed": 95,
        },
    },
    "unreviewed_functions": 1,
    "unreviewed_sloc": 8,
    "missing_groups": ["injection", "auth", ...],
    "per_file": [
        {
            "path": "09_stack_overread.c",
            "sloc": 12,
            "reviewed": 1,
            "total": 2,
            "pct": 50.0,
            "findings": 1,
            "unreviewed_functions": ["record"],
            "scanned_semgrep": True,
            "scanned_codeql": True,
            "scanned_llm": True,
        },
        ...
    ],
}
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

**LLM:** Files from the reads manifest (`.reads-manifest`, populated by coverage plugin hook on every Read tool call). Functions from `findings.json` — any function with a finding or ruling counts as analysed.

## Inventory (denominator)

Coverage percentages use `checklist.json` as the denominator:
- **Files:** total files in checklist
- **Items:** total functions/globals/macros per file (`items` key, fallback `functions`)
- **SLOC:** source lines of code per file

The checklist is built by `/validate` Stage 0 or `/understand` MAP-0.

## Missing Groups

Semgrep policy groups are compared against `RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK` to identify which vulnerability classes weren't scanned. Missing groups appear in the "Action needed" section.

## Future (Phase 3+)

The current system computes coverage on-the-fly from records. Phase 3 adds:
- `CoverageStore` class with persistent `coverage.json`
- `store.mark()` / `store.gaps()` / `store.who_checked()` query API
- Line-range tracking (intervals, bitmap fallback for dense data)
- Tool registry with categories (static/llm/runtime)

See `/home/raptor/design/coverage-layer.md` for the full design.
