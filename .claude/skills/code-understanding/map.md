---
name: code-understanding-map
description: Builds a ground-truth model of a codebase's entry points, trust boundaries, and dangerous sinks from an attacker's perspective, producing context-map.json for pipeline integration.
user-invocable: false
---

# [MAP] Application Context Mapping

Build a ground-truth model of the target codebase before attacking it. The goal is to understand the application's trust model, where input enters, where decisions get made, and where dangerous operations occur.

## Input

A target directory or repository.

## Purpose

A context map answers: *"If I were the attacker, what would I care about here?"*

This is not documentation generation. It is adversarial reconnaissance at the source level.

## Task

**[MAP-0] Source Inventory**

Before any manual enumeration, run the inventory builder to get a reliable file and function list:

```
python3 build_inventory.py --repo <target> --out $WORKDIR
```

Read the resulting `checklist.json`. It provides every source file with language, line count, SHA-256 checksum, and every function with name, line number, and signature. Excluded files are recorded with reasons.

If tree-sitter is installed, functions also include a `metadata` field with:
- `attributes` — decorators (Python) and annotations (Java) that identify entry points and auth gates
- `visibility` — public/private/static/exported/extern
- `class_name` — enclosing class or receiver type
- `return_type` and `parameters` — typed signatures for data flow analysis

Check the metadata BEFORE reading code — it may already answer questions about entry points, trust boundaries, and attack surface without needing to open files.

Use this as your ground truth for what exists in the codebase. Do NOT manually enumerate files.

**[MAP-1] Entry Point Enumeration**

Find all locations where external input enters the application:
- HTTP routes (GET/POST handlers, REST endpoints, GraphQL resolvers)
- CLI argument parsers
- File/socket readers
- Message queue consumers
- Deserialization entry points (JSON parsers, pickle loads, XML parsers)
- IPC handlers

For each: record file path, line number, and what data it accepts.

**[MAP-2] Trust Boundary Identification**

Identify where the code makes (or should make) trust decisions:
- Authentication checks (where credentials are verified)
- Authorization checks (where permissions are enforced)
- Input validation (where sanitization occurs)
- Privilege transitions (setuid, sudo, elevated operations)

Flag any entry point that reaches a sensitive operation *without* passing through a trust boundary.

**[MAP-3] Sink Catalog**

Find all dangerous operations:
- Database queries (especially raw/string-concatenated)
- Shell execution (`subprocess`, `exec`, `system`, `popen`)
- File system writes and reads (especially with user-controlled paths)
- Deserialization (`pickle.loads`, `eval`, `yaml.load` without SafeLoader)
- Network requests with user-controlled URLs (SSRF candidates)
- Template rendering with user data
- Cryptographic operations (especially key material handling)

For each: record file path, line number, and what data reaches it.

**[MAP-4] Architecture Summary**

Produce a brief summary covering:
- Application type (web app, CLI, daemon, library, etc.)
- Primary language(s) and frameworks
- Authentication model (session-based, token-based, API key, none)
- Database(s) and ORM (if any)
- External service dependencies
- Notable security controls present (WAF hints in code, CSP headers, rate limiting)

## Output Format

`context-map.json` is a superset of `attack-surface.json`. The top-level `sources`, `sinks`, and `trust_boundaries` keys use the same required fields as Stage B's `attack-surface.json` — so `cp context-map.json attack-surface.json` works. Context-map-specific fields (`meta`, `entry_points`, `unchecked_flows`) sit alongside as extra keys.

```json
{
  "sources": [
    {
      "type": "http_route",
      "entry": "POST /api/v2/query @ src/routes/query.py:34"
    }
  ],
  "sinks": [
    {
      "type": "db_query",
      "location": "src/db/query.py:89"
    }
  ],
  "trust_boundaries": [
    {
      "boundary": "JWT auth middleware",
      "check": "src/middleware/auth.py:12"
    }
  ],
  "meta": {
    "target": "path/to/target",
    "timestamp": "ISO timestamp",
    "app_type": "web_app|cli|daemon|library",
    "language": ["python", "go"],
    "frameworks": ["flask", "sqlalchemy"],
    "auth_model": "session|token|api_key|none|mixed"
  },
  "entry_points": [
    {
      "id": "EP-001",
      "type": "http_route|cli_arg|file_read|socket|queue|ipc|deserialize",
      "method": "POST",
      "path": "/api/v2/query",
      "file": "src/routes/query.py",
      "line": 34,
      "accepts": "JSON body: {query: string, params: object}",
      "auth_required": true,
      "notes": "Auth check at line 38, but only validates token format, not permissions"
    }
  ],
  "sink_details": [
    {
      "id": "SINK-001",
      "type": "db_query|shell_exec|file_write|file_read|deserialize|network|template|crypto",
      "operation": "cursor.execute(raw_sql)",
      "file": "src/db/query.py",
      "line": 89,
      "reaches_from": ["EP-001"],
      "trust_boundaries_crossed": ["TB-001"],
      "parameterized": false,
      "notes": "Query string built via f-string at line 87"
    }
  ],
  "boundary_details": [
    {
      "id": "TB-001",
      "type": "auth_check|authz_check|input_validation|privilege_drop",
      "file": "src/middleware/auth.py",
      "line": 12,
      "covers": ["EP-001", "EP-002"],
      "gaps": "EP-003 bypasses this middleware via direct import at src/admin/bulk.py:67"
    }
  ],
  "unchecked_flows": [
    {
      "entry_point": "EP-003",
      "sink": "SINK-002",
      "missing_boundary": "No auth check on admin bulk endpoint"
    }
  ]
}
```

## Gates

GATES APPLY: U1 [READ-FIRST], U2 [ATTACKER-LENS], U5 [EVIDENCE-ONLY]

Do not populate `sources`, `sinks`, or `entry_points` from file names or common patterns alone — read the code and verify.

**[MAP-5] Record Coverage**

After writing `context-map.json`, update the inventory with which functions you examined.
Build a list of every function you read and analysed (entry points, sinks, trust boundary
checks), then write a small Python script to record them:

```python
# Save as /tmp/record_coverage.py and run: python3 /tmp/record_coverage.py
import json, sys, os
sys.path.insert(0, os.getcwd())  # script is in /tmp but cwd is the raptor repo root
from core.inventory.coverage import update_coverage

workdir = sys.argv[1]
inv = json.load(open(f"{workdir}/checklist.json"))
checked = [
    # Add one entry per function you examined:
    {"file": "src/routes/query.py", "function": "handle_query"},
    {"file": "src/db/query.py", "function": "run_query"},
    # ... etc
]
update_coverage(inv, checked, "understand:map")
json.dump(inv, open(f"{workdir}/checklist.json", "w"), indent=2)
print(f"Recorded {len(checked)} functions as checked by understand:map")
```

Run via Bash tool: `python3 /tmp/record_coverage.py <workdir_path>`

This ensures coverage tracking is cumulative across `/understand` and `/validate` runs.

## Output

OUTPUT: `$WORKDIR/context-map.json`

Display a summary to the user after writing:
- N entry points found (N require auth, N are public)
- N trust boundaries found (N gaps identified)
- N sinks found (N have unchecked flows)
- Recommended next step: `--trace <entry-point-id>` for highest-risk unchecked flow
