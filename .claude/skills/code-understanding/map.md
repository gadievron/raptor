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

Before any manual enumeration, build the source inventory (the understand command's Step 1 already did this — `$WORKDIR/checklist.json` should exist).

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

**[MAP-5] Normalise context-map**

Right after writing `context-map.json`, run the normaliser. It uses the
checklist in the same dir as ground truth to:
- backfill missing `name` fields on entry_points / sink_details from line ranges
- normalise file paths (strip leading `./`, convert absolute paths under
  the target into relative ones)
- warn (non-fatal) on hallucinated files / out-of-range line numbers /
  cross-reference typos in `unchecked_flows`

```bash
libexec/raptor-normalize-context-map "$WORKDIR"
```

Idempotent — safe to re-run. Skip this step only if `$WORKDIR/checklist.json`
doesn't exist (e.g. you skipped MAP-0 inventory build).

When you can, include the function `name` directly on each entry_point and
sink_detail you emit — it helps the normaliser skip backfill and is
clearer for human reviewers.

**[MAP-5b] Enrich entry points with forward-reachable closures**

After normalisation, run the call-graph enricher. Uses the inventory to
attach a `forward_reachable` field to each entry point, listing the
internal functions and external dep calls transitively reachable from
the entry's host function.

```bash
libexec/raptor-enrich-context-map-callgraph "$WORKDIR"
```

The enriched context-map.json carries machine-derived "this entry
reaches N internal + M external" data alongside the LLM's narrative —
useful for `/diagram` rendering and downstream consumers (audit
prioritisation, validate Stage F). Idempotent. Skip if
`$WORKDIR/checklist.json` doesn't exist or doesn't carry `target_path`.

**[MAP-6] Record Coverage**

After writing `context-map.json`, update the inventory with which functions you examined.
Write a JSON array of every function you read and analysed (entry points, sinks, trust boundary
checks) to `$WORKDIR/reviewed-items.json`, then run the coverage recorder:

Record coverage using the understand command's Step 3:
```bash
libexec/raptor-coverage-summary "$WORKDIR" --mark src/routes/query.py:handle_query src/db/query.py:run_query
```

This updates the coverage record so `/project coverage` reflects what was examined.

**[MAP-7] Runtime Probe (optional)**

When the target ships an executable binary alongside the source —
e.g. a CLI tool, a built service, or a packaged scanner — you can
corroborate the static map with a runtime observation. The probe
runs the binary under `sandbox(observe=True)` and records every
path it reads/writes/stat's plus every connect target it attempts;
the resulting profile is merged into `context-map.json` under a
`runtime_observation` key with correlations against your entry
points and sinks.

This is **opt-in** because:
- many /understand targets don't have a runnable binary;
- probing executes the binary, which the operator must consent to;
- the observation is one execution path — entry points the binary
  didn't reach in this run aren't refuted, just unconfirmed.

Run the probe via the CLI shim and merge the JSON output:

```bash
raptor-sandbox-observe --json --out "$WORKDIR/probe" -- \
    /path/to/binary [args...] > "$WORKDIR/probe.json"

python3 -c "
import json
from pathlib import Path
from core.sandbox.observe_profile import (
    ConnectTarget, ObserveProfile,
)
from core.sandbox.observe_context_merge import (
    merge_observation_into_context_map,
)

w = Path('$WORKDIR')
ctx = json.loads((w / 'context-map.json').read_text())
probe = json.loads((w / 'probe.json').read_text())
profile = ObserveProfile(
    paths_read=probe['paths_read'],
    paths_written=probe['paths_written'],
    paths_stat=probe['paths_stat'],
    connect_targets=[
        ConnectTarget(**t) for t in probe['connect_targets']
    ],
)
merged = merge_observation_into_context_map(
    ctx, profile,
    binary='/path/to/binary',
    command=['/path/to/binary'] + ['<args>'],
)
(w / 'context-map.json').write_text(json.dumps(merged, indent=2))
"
```

After merge, `context-map.json` has a new `runtime_observation`
section with:
- the full path/connect record;
- `correlations.entry_points_runtime_confirmed`: IDs of entry
  points whose source file the binary actually opened;
- `correlations.sinks_runtime_confirmed`: IDs of sinks whose
  source file the binary opened for write;
- `correlations.external_reach`: list of ip:port the binary
  attempted (often complements egress proxy log).

When you display the MAP summary to the user, surface a runtime
section if `runtime_observation` is present:

> Runtime probe: N paths read, N writes, N connects.
> Confirmed entry points: EP-001, EP-007.
> Confirmed sink writes: SINK-002.

## Output

OUTPUT: `$WORKDIR/context-map.json`

Display a summary to the user after writing:
- N entry points found (N require auth, N are public)
- N trust boundaries found (N gaps identified)
- N sinks found (N have unchecked flows)
- Recommended next step: `--trace <entry-point-id>` for highest-risk unchecked flow
