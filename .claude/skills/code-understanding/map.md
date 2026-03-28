# [MAP] Application Context Mapping

Build a ground-truth model of the target codebase before attacking it. The goal is to understand the application's trust model, where input enters, where decisions get made, and where dangerous operations occur.

## Input

A target directory or repository.

## Purpose

A context map answers: *"If I were the attacker, what would I care about here?"*

This is not documentation generation. It is adversarial reconnaissance at the source level.

## Task

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

## Output

OUTPUT: `$WORKDIR/context-map.json`

Display a summary to the user after writing:
- N entry points found (N require auth, N are public)
- N trust boundaries found (N gaps identified)
- N sinks found (N have unchecked flows)
- Recommended next step: `--trace <entry-point-id>` for highest-risk unchecked flow
