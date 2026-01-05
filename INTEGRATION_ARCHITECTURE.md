# RAPTOR Complete Integration Architecture

## How The Pieces Work Together

### Data Flow: Binary Analysis Example

```
USER REQUEST: "Find all vulnerabilities in ./myapp binary"
                         │
                         ▼
              ┌──────────────────────┐
              │  Meta-Orchestrator   │
              │    (The Brain)       │
              └──────────┬───────────┘
                         │
                    LLM decides:
                    "Need comprehensive
                     binary analysis"
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌────────┐    ┌──────────┐    ┌──────────┐
    │Semgrep │    │  Frida   │    │CodeQL    │
    │        │    │ Binary   │    │          │
    │Simple  │    │ Context  │    │Deep      │
    │Patterns│    │ Analyzer │    │Analysis  │
    └────┬───┘    └─────┬────┘    └────┬─────┘
         │              │               │
         │              ▼               │
         │      ┌──────────────┐        │
         │      │ Dependencies │        │
         │      │ - libc.so    │        │
         │      │ - libssl.so  │        │
         │      │ Symlinks:    │        │
         │      │ - /tmp/...   │        │
         │      │ SUID: YES    │        │
         │      │ LD_PRELOAD:  │        │
         │      │ - malloc()   │        │
         │      │ - system()   │        │
         │      └──────┬───────┘        │
         │             │                │
         │    Feed dependency source    │
         │    code to static analyzers  │
         │             │                │
         └─────────────┼────────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │Finding Normalizer│
              │                  │
              │ Converts all to: │
              │ Unified JSON     │
              └─────────┬────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │ Unified Finding Format        │
        │ {                             │
        │   "id": "merged-libc-001",    │
        │   "severity": "critical",     │
        │   "title": "Buffer Overflow", │
        │   "evidence": {               │
        │     "static": {               │
        │       "semgrep": "...",       │
        │       "codeql": "dataflow"    │
        │     },                        │
        │     "dynamic": {              │
        │       "frida": "confirmed",   │
        │       "libraries": ["libc"]   │
        │     }                         │
        │   },                          │
        │   "context": {                │
        │     "suid": true,             │
        │     "dependencies": [...],    │
        │     "ld_preload_vuln": true   │
        │   },                          │
        │   "exploitability": "high"    │
        │ }                             │
        └───────────┬───────────────────┘
                    │
                    ▼
           ┌────────────────┐
           │  LLM Analysis  │
           │  (Claude)      │
           │                │
           │ Understands:   │
           │ - All findings │
           │ - Dependencies │
           │ - Context      │
           │ - Synergies    │
           └────────┬───────┘
                    │
                    ▼
           ┌─────────────────┐
           │  LLM Reasoning: │
           │                 │
           │ "Critical:      │
           │  Buffer overflow│
           │  in SUID binary │
           │  confirmed by   │
           │  Frida.         │
           │                 │
           │  Impact:        │
           │  Root privilege │
           │  escalation     │
           │                 │
           │  Exploitation:  │
           │  LD_PRELOAD can │
           │  inject code    │
           │  via malloc()   │
           │                 │
           │  Dependencies:  │
           │  libc vuln too  │
           │  → Scan libc!"  │
           └─────────┬───────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
Next iteration  Generate PoC   Suggest fix
  with libc     (exploit pkg)  (patch pkg)
```

## Tool Output Format Conversion

### Before Normalization

**Semgrep (SARIF):**
```json
{
  "runs": [{
    "results": [{
      "ruleId": "sql-injection",
      "level": "error",
      "message": {"text": "SQL injection"},
      "locations": [...]
    }]
  }]
}
```

**CodeQL (SARIF):**
```json
{
  "runs": [{
    "results": [{
      "ruleId": "cpp/path-injection",
      "codeFlows": [...],
      "message": {"text": "Path injection"}
    }]
  }]
}
```

**Frida (Custom JSON):**
```json
{
  "findings": [{
    "type": "finding",
    "level": "warning",
    "title": "TOCTOU Vulnerability",
    "details": {
      "file": "/tmp/test",
      "time_window_ms": 250
    }
  }],
  "libraries": [...],
  "dependency_tree": {...}
}
```

**AFL++ (Crash files):**
```
crashes/
  id:000000,sig:11,src:000000
  id:000001,sig:06,src:000015
```

### After Normalization

**All tools → Unified format:**
```json
{
  "id": "merged-auth-001",
  "tool": "semgrep+frida",
  "severity": "critical",
  "title": "Authentication Bypass",
  "description": "SQL injection in auth function",
  "location": {
    "file": "auth.c",
    "line": 123,
    "function": "authenticate"
  },
  "category": "injection",
  "cwe": "CWE-89",
  "evidence": {
    "static": {
      "semgrep": {
        "rule_id": "sql-injection",
        "snippet": "..."
      },
      "codeql": {
        "query": "sql-injection-taint",
        "dataflow": [...]
      }
    },
    "dynamic": {
      "frida": {
        "runtime_observation": "SQL query executed",
        "libraries": ["libsqlite3.so"],
        "env_vars": {"DATABASE_URL": "..."}
      }
    }
  },
  "confidence": 0.98,
  "exploitability": "high",
  "context": {
    "suid": false,
    "dependencies": ["libsqlite3.so"],
    "symlinks": [],
    "ld_preload_opportunities": ["system()"],
    "loaded_libraries": [...]
  }
}
```

## Meta-Orchestrator Decision Making

### Example: Finding RCE Vulnerability

**Iteration 1:**
```
LLM Input:
  Goal: "Find RCE vulnerabilities"
  Target: "./webapp"
  Tools Available: [semgrep, codeql, frida, afl, web]
  Previous Findings: None

LLM Decision:
  {
    "next_tools": ["semgrep"],
    "reasoning": "Start with fast pattern matching to find suspicious code",
    "continue_after": true,
    "estimated_progress": "20%"
  }

Output:
  - 15 potential issues found
  - 3 command execution patterns
  - 2 path injection patterns
```

**Iteration 2:**
```
LLM Input:
  Previous: Semgrep found command execution in process_file()
  Normalized Finding:
    {
      "title": "Possible Command Injection",
      "location": {"file": "process.py", "line": 45},
      "evidence": {"static": {"semgrep": "..."}},
      "confidence": 0.75
    }

LLM Decision:
  {
    "next_tools": ["frida"],
    "reasoning": "Verify at runtime if command execution is exploitable",
    "target_function": "process_file",
    "continue_after": true,
    "estimated_progress": "50%"
  }

Frida Hooks:
  - system()
  - exec*()
  - popen()

Output:
  - process_file() calls system(user_input)
  - CONFIRMED: Command injection
  - Confidence: 0.75 → 0.95
```

**Iteration 3:**
```
LLM Input:
  Confirmed command injection
  Context from Frida:
    - Binary uses LD_LIBRARY_PATH
    - SUID bit: NO
    - Dependencies: libc, libssl

LLM Decision:
  {
    "next_tools": ["codeql"],
    "reasoning": "Track full dataflow from input to system() call",
    "continue_after": true,
    "estimated_progress": "75%"
  }

CodeQL Query:
  "Find all paths from user input to process_file()"

Output:
  - 3 code paths lead to vulnerable call
  - All paths lack sanitization
  - Dataflow confirmed
```

**Iteration 4:**
```
LLM Input:
  - Semgrep: Found pattern
  - Frida: Confirmed at runtime
  - CodeQL: Traced full dataflow
  - Confidence: 0.98

LLM Decision:
  {
    "next_tools": [],
    "reasoning": "Goal achieved - RCE confirmed with high confidence",
    "continue_after": false,
    "estimated_progress": "100%"
  }

Final Report:
  Severity: CRITICAL
  Title: Remote Code Execution via Command Injection
  Evidence:
    - Static analysis (Semgrep): Pattern match
    - Dynamic verification (Frida): Runtime confirmation
    - Dataflow analysis (CodeQL): Complete path
  Exploitability: HIGH
  Recommendation: Use subprocess with shell=False
```

## Binary Environment → Static Analysis Loop

### How Frida Feeds Dependencies to Semgrep/CodeQL

```
Frida discovers:
  ./myapp uses:
    - /lib/x86_64-linux-gnu/libc.so.6
    - /usr/lib/libssl.so.1.1
    - /usr/lib/libcrypto.so.1.1

Meta-Orchestrator:
  "Found dependencies, should analyze their source code"

LLM decides:
  "Check libc for vulnerabilities that myapp might trigger"

Next iteration:
  Semgrep/CodeQL analyze:
    - /usr/src/glibc/malloc/malloc.c
    - /usr/src/openssl/ssl/ssl_lib.c

Findings:
  - malloc() has known vulnerability CVE-XXXX
  - myapp's heap allocation pattern triggers it
  - COMBINED FINDING: High confidence exploit
```

## TOCTOU Example

```
Frida detects:
  access("/tmp/file") at T0
  open("/tmp/file") at T0+100ms

  Risk: 100ms window for symlink race

Meta-Orchestrator:
  "TOCTOU found, need to verify"

LLM decides:
  "Check source code for fix possibility"

CodeQL analyzes:
  - Find all access() followed by open()
  - Check for openat() usage (safe alternative)

Result:
  - 5 TOCTOU vulnerabilities
  - None use openat()
  - Patch: Replace with openat(dirfd, ...)
```

## LD_PRELOAD Attack Surface

```
Binary Context Analyzer finds:
  - Binary calls: malloc(), system(), open()
  - No SUID (but still interesting)
  - Environment: LD_LIBRARY_PATH writable

Frida hooks:
  - Observe malloc() calls
  - Count: 10,000+ calls/second

LLM reasons:
  "High malloc() usage + LD_PRELOAD = memory corruption attack vector"

Next iteration:
  AFL++ fuzzes with custom malloc() via LD_PRELOAD

Result:
  - Crash in malloc() handling
  - Root cause: Use-after-free
  - Exploit: LD_PRELOAD malicious malloc()
```

## Complete Workflow Summary

1. **User Request** → Meta-Orchestrator
2. **Meta-Orchestrator** → LLM decides strategy
3. **Tools Execute** → Each in appropriate format
4. **Finding Normalizer** → Unified JSON
5. **LLM Analyzes** → Reasons about findings
6. **Cross-Tool Correlation** → Higher confidence
7. **Dependency Discovery** → Frida finds dependencies
8. **Iterative Refinement** → Feed deps back to static tools
9. **Comprehensive Report** → All tools' insights combined

## Key Innovation

**Traditional approach:**
- Run tools independently
- Manual correlation
- Miss dependencies
- No runtime context

**RAPTOR approach:**
- Tools aware of each other
- Automatic correlation
- Full dependency analysis
- Runtime + static combined
- LLM orchestrates everything
- JSONL audit trail

**Result:**
Higher confidence findings with complete context and exploitation analysis.

## For The User

When you run:
```bash
raptor-cli meta --target ./myapp --goal "Find vulnerabilities"
```

You get:
1. ✅ Complete binary environment (dependencies, SUID, LD_PRELOAD, etc.)
2. ✅ Static + dynamic analysis combined
3. ✅ All findings in unified format
4. ✅ LLM reasoning about attack surface
5. ✅ Cross-tool correlation
6. ✅ Dependency analysis
7. ✅ Exploitation assessment
8. ✅ Fix recommendations

All automatically, with full context awareness.
