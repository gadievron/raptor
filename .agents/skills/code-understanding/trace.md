---
name: code-understanding-trace
description: Follows a single data flow from untrusted input through every function call to a dangerous sink, with full branch coverage and attacker control assessment, producing a structured trace for validation pipeline integration.
user-invocable: false
---

# [TRACE] Data Flow Tracing

Follow a single data flow from untrusted input to a dangerous operation. Show every step: the call site, the function definition, and any transformations along the way. This is verbose, in your face and super helpful. 

## Input

- An entry point: HTTP route path, function name, or `EP-xxx` ID from context-map.json
- Optionally: a target sink type (`--to db|shell|file|deserialize|network`)

**Disambiguation:** `EP-xxx` → look up by ID in context-map.json. String starting with an HTTP method (e.g. `"POST /api/v2/query"`) → match against route entry points. Anything else → treat as a function name and search the codebase.

## Purpose

Answer: *"Can I control what reaches this sink, and is anything stopping me?"*

The goal is a complete, step-by-step walkthrough of the supplied code, not a summary, but an actual trace showing the function call and its definition at each hop. This is what distinguishes understanding from guessing.

## Task

**[TRACE-1] Anchor**

Locate the entry point in code. Read it. Record:
- Exactly what data the entry point accepts (parameter names, types, where it comes from)
- Any immediate validation at the entry (before it's passed anywhere)
- The first downstream call

**[TRACE-2] Walk the Chain**

For each function call in the chain:
1. Show the call site (file:line — the line calling the function)
2. Show the function definition (file:line — where the function is defined)
3. Show what happens to the input data inside that function
4. Identify the next call that carries tainted data forward

Continue until one of:
- Data reaches a sink (database, shell, filesystem, deserializer, network)
- Data is definitively sanitized (record what sanitization occurs and assess its completeness)
- Data reaches a dead end (hardcoded, discarded, never used)

**[TRACE-3] Branch Coverage**

Identify all branches in the flow — not just the happy path:
- Error handlers (do they short-circuit safely, or do they pass data through anyway?)
- Conditional branches (does the input take different paths under different conditions?)
- Async/deferred execution (is the data passed to a queue, goroutine, callback?)

Trace each significant branch separately.

**[TRACE-3b] Path Conditions (for SMT consumption)**

Separately from `branches[]` (which describes *alternative* paths), record the **conjunction of guards on the dangerous path** — every condition that must hold for execution to actually reach the sink along the trace you've followed. These are downstream-consumed by the SMT path-feasibility helper (`raptor-smt-validate-path`), so emit them as simple bitvector predicates over named variables:

  - Numeric comparisons: `"size > 0"`, `"offset + length <= buffer_size"`, `"count * 16 < max_alloc"`
  - Null checks: `"ptr != NULL"`, `"ptr == NULL"`
  - Bitmask: `"flags & 0x80000000 == 0"`
  - Negated form (the guard was *bypassed* on the dangerous path): `{"text": "validate(input)", "negated": true}` — but most negations come out clearer as the inverted predicate (`ptr == NULL` instead of `!ptr != NULL`).

For each condition, also record the `step_index` it gates so consumers can correlate back to `steps[]`.

**Avoid:** function calls (`strlen(input)`), type casts (`(uint32_t)x`), struct/array access (`obj.field`, `arr[0]`), pointer deref (`*p`) — the SMT parser can't encode these. Either simplify into a bitvector predicate or omit; "missing" is far better than "wrong shape".

Also pick a `path_profile` describing the dominant C type along the path — `"uint32"` for `int`/`unsigned int` arithmetic, `"uint64"` for `size_t`/`uint64_t`/pointers (default), `"int32"` for signed-overflow UB reasoning. Pre-made profiles: `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `uint64`, `int64`. Pick one that matches the dominant arithmetic type on the path.

**[TRACE-4] Sink Analysis**

At each sink, record:
- Exactly what reaches it (the variable name and what it contains)
- Whether it's parameterized or interpolated
- What an attacker could inject and what the effect would be
- What would need to be true for exploitation (prerequisites)

**[TRACE-5] Control Assessment**

Summarize what the attacker controls:
- Input they provide directly (high control)
- Input filtered by previous checks (partial control — assess bypass potential)
- Input not under attacker control (discard from threat model)

## Output Format

```json
{
  "id": "TRACE-001",
  "name": "POST /api/v2/query → db_query",
  "finding": "FIND-001",
  "meta": {
    "entry_point": "POST /api/v2/query",
    "entry_file": "src/routes/query.py:34",
    "target_sink": "db_query",
    "timestamp": "ISO timestamp"
  },
  "steps": [
    {
      "step": 1,
      "type": "entry",
      "call_site": null,
      "definition": "src/routes/query.py:34",
      "description": "POST handler receives JSON body. `query` field extracted at line 41.",
      "tainted_var": "request.json['query']",
      "transform": "none",
      "confidence": "high"
    },
    {
      "step": 2,
      "type": "call",
      "call_site": "src/routes/query.py:48",
      "definition": "src/services/query_service.py:12",
      "description": "Passes `query` directly to QueryService.run() without validation.",
      "tainted_var": "query_str",
      "transform": "none",
      "confidence": "high"
    },
    {
      "step": 3,
      "type": "sink",
      "call_site": "src/services/query_service.py:31",
      "definition": "psycopg2.cursor.execute()",
      "description": "Raw SQL built via f-string: f'SELECT * FROM {table} WHERE query = {query_str}'",
      "tainted_var": "query_str",
      "transform": "none",
      "confidence": "high",
      "sink_type": "db_query",
      "parameterized": false,
      "injectable": true
    }
  ],
  "proximity": 9,
  "blockers": [],
  "branches": [
    {
      "branch_point": "src/routes/query.py:44",
      "condition": "if request.json.get('admin')",
      "outcome": "Bypasses auth middleware entirely — tainted data reaches same sink via shorter path"
    }
  ],
  "path_conditions": [
    {"text": "len(query) > 0", "step_index": 1, "negated": false},
    {"text": "table != NULL", "step_index": 3, "negated": false}
  ],
  "path_profile": "uint64",
  "attacker_control": {
    "level": "full|partial|none",
    "what": "Full control over `query` field via POST body",
    "bypasses_needed": [],
    "notes": ""
  },
  "summary": {
    "flow_confirmed": true,
    "sink_reachable": true,
    "sanitizers": [],
    "verdict": "Untrusted POST body reaches raw SQL execution with no parameterization. Direct SQLi.",
    "confidence": "high",
    "feeds_validation": true
  }
}
```

**Schema note:** `steps[]`, `proximity` (0–10 score: 10 = at the sink, 0 = no viable path), and `blockers[]` are shared with `attack-paths.json` from the validation pipeline. What this means is that a flow-trace can be consumed directly by Stage B. `branches`, `attacker_control`, and `summary` are trace-specific extensions.

`path_conditions` and `path_profile` are forwarded by `core/orchestration/understand_bridge.py` into `attack-paths.json` so /validate's Stage E can feed them straight to the SMT path-feasibility helper without re-extracting from source. Both fields are optional — omit if the trace doesn't lend itself to bitvector predicates (e.g., string/format findings) and Stage E will fall back to its own reasoning.

## Teach Mode Integration

If you encounter an unfamiliar framework, library, or pattern while tracing, say so explicitly. Switch to [TEACH] mode to understand the mechanism, then return to the trace.

Example: *"Step 4 uses SQLAlchemy's `text()` construct, so loading teach mode to understand whether this is parameterised."*

This prevents false confidence from tracing through code you don't fully understand.

## Output

OUTPUT: `$WORKDIR/flow-trace-<entry-id>.json` (one file per traced flow)

Display the flow to the user as a narrative walkthrough after writing, not just the JSON. Show each step as: `[step N] file:line — what happens — what attacker controls`.

## Gates

GATES APPLY: U1 [READ-FIRST], U2 [ATTACKER-LENS], U3 [FULL-FLOW], U5 [EVIDENCE-ONLY]

**Full flow means full flow.** If a function calls another function, read the callee. Do not assume what a function does from its name. Read it.
