---
name: code-understanding-hunt
description: Systematically finds all instances of a vulnerability pattern across the codebase, classifying each match by taint status and grouping by root cause to determine fix scope.
user-invocable: false
---

# [HUNT] Variant Analysis

Once a vulnerability pattern is identified, I need you to systematically find every other location in the codebase where the same pattern could apply. A single finding is rarely isolated. Don't be scared, be curious

## Input

One of:
- A vulnerability finding (from `/validate` output or SARIF)
- A code pattern description (`--hunt "raw SQL via f-string"`)
- A sink type (`--hunt sink:shell_exec`)
- A file/function from a completed trace (`--hunt EP-001`)

**Disambiguation:** `FIND-*` or `EP-*` → ID lookup in findings.json / context-map.json. `sink:` prefix → filter by sink type. Everything else → treat as a freeform pattern description.

## Purpose

Answer: *"Is this the only place this happens, or did the same mistake get made everywhere?"*

Variant hunting operates at three levels:
1. **Structural variants** — same code pattern (same API call, same string operation, same missing check)
2. **Semantic variants** — different code, same vulnerability class (all SQL injection regardless of how it's built)
3. **Root-cause variants** — if a shared utility function is vulnerable, find every caller

## Task

**[HUNT-1] Pattern Extraction**

From the input finding or description, extract:
- The dangerous operation (what API or construct is used)
- The taint source (where user input entered)
- The missing control (what was absent: validation, parameterization, escaping)

Express this as a searchable pattern before starting.

Example: *"Pattern: `cursor.execute()` called with a string that contains an f-string or `%` or `+` operator, where the string variable is not a fixed constant."*

**[HUNT-2] Structural Search**

Search the codebase for the structural pattern:
- Use Grep for API calls, function names, and syntax patterns
- Cast wide first, then narrow — start with the sink, then filter for taint

Record every match with file path, line number, and the matched code.

**[HUNT-3] Taint Qualification**

For each structural match, quickly assess whether attacker-controlled input can reach it:
- Is there an obvious untrusted source in the same function?
- Is the variable populated from a request, file, or external source?
- Does the call sit behind a public entry point?

Classify each match:
- `confirmed_tainted`: direct evidence of user input reaching the sink
- `likely_tainted`: plausible path from external input, needs trace to confirm
- `unlikely_tainted`: value appears to come from internal/trusted sources
- `false_positive`: value is a constant or clearly safe

Do not discard `likely_tainted` matches — they become candidates for `--trace`.

**[HUNT-4] Root-Cause Grouping**

Group findings by root cause:
- Same shared utility function → one fix fixes all
- Same copy-paste pattern → independent findings, need separate fixes
- Same framework misuse → systemic issue across the codebase

This determines whether one patch addresses the whole class or whether each instance needs separate attention.

**[HUNT-5] Priority Ranking**

Rank variants by exploitability:
1. `confirmed_tainted` with public entry point — highest priority
2. `confirmed_tainted` with authenticated entry point
3. `likely_tainted` with public entry point
4. `likely_tainted` with authenticated entry point
5. `unlikely_tainted` — document, low priority
6. `false_positive` — retained in `variants.json` for audit trail (with notes explaining why), but excluded from `recommended_traces` and `validation_scope`

## Output Format

```json
{
  "meta": {
    "seed": "FIND-001 | pattern description",
    "pattern": "cursor.execute() with non-parameterized string",
    "timestamp": "ISO timestamp",
    "total_matches": 8,
    "confirmed_tainted": 3,
    "likely_tainted": 2,
    "unlikely_tainted": 2,
    "false_positive": 1
  },
  "variants": [
    {
      "id": "VAR-001",
      "file": "src/services/query_service.py",
      "function": "run_query",
      "line": 31,
      "vuln_type": "sqli",
      "status": "not_disproven",
      "confidence": "high",
      "proof": {
        "vulnerable_code": "cursor.execute(f'SELECT * FROM {table} WHERE id = {user_id}')",
        "source": "request.json['user_id'] at src/routes/user.py:22",
        "sink": "psycopg2.cursor.execute() at src/services/query_service.py:31"
      },
      "matched_code": "cursor.execute(f'SELECT * FROM {table} WHERE id = {user_id}')",
      "taint_status": "confirmed_tainted",
      "taint_source": "request.json['user_id'] at src/routes/user.py:22",
      "root_cause_group": "direct-fstring-interpolation",
      "entry_points": ["POST /api/v2/users"],
      "auth_required": false,
      "priority": 1,
      "notes": "Same pattern as seed finding. Public endpoint."
    }
  ],
  "root_cause_groups": [
    {
      "id": "RCG-001",
      "name": "direct-fstring-interpolation",
      "description": "SQL built via f-string without parameterization",
      "count": 5,
      "fix_strategy": "Replace with parameterized queries — one fix pattern applies to all instances"
    }
  ],
  "recommended_traces": ["VAR-002", "VAR-004"],
  "validation_scope": {
    "add_to_checklist": ["VAR-001", "VAR-002", "VAR-003"],
    "note": "Pass variants.json to /validate --findings to expand validation scope"
  }
}
```

## Output

OUTPUT: `$WORKDIR/variants.json`

Display a summary to the user:
- N total matches
- N confirmed tainted (ready for `/validate`)
- N likely tainted (recommend `--trace` on each)
- N grouped by root cause

If `confirmed_tainted` variants exist, prompt: *"Found N confirmed variants. Run `/validate` with `--findings variants.json` to validate exploitability."*

## Gates

GATES APPLY: U1 [READ-FIRST], U2 [ATTACKER-LENS], U4 [VARIANT-COMPLETE], U5 [EVIDENCE-ONLY]

**GATE-U4 reminder:** Search the full codebase. If the grep returns many results, process all of them — do not sample. Document any files excluded from the hunt (e.g., test harnesses, generated code) and why.
