# RAPTOR with Claude Code - Complete Usage Guide

## Available Commands

**Security testing:**
```
/scan     - Static code analysis (Semgrep + CodeQL + LLM)
/fuzz     - Binary fuzzing (AFL++ + crash analysis)
/web      - Web application security testing
/agentic  - Full autonomous workflow (most comprehensive)
/codeql   - CodeQL-only deep analysis
/analyze  - LLM analysis of existing SARIF files
/validate - Exploitability validation pipeline
```

**Exploit development & patching:**
```
/exploit - Generate exploit proof-of-concepts (beta)
/patch   - Generate security patches (beta)
```

**Code understanding & forensics:**
```
/understand     - Adversarial code comprehension (map attack surface, trace data flows)
/oss-forensics  - Evidence-backed GitHub forensic investigation
/crash-analysis - Autonomous crash root-cause analysis
```

**Skill management:**
```
/create-skill - Save custom approach for reuse (alpha)
```

**Note:** Skills are alpha - /create-skill creates skill definitions, but auto-loading and execution integration is not yet implemented.

---

## Expert Personas (9 total)

All personas load on-demand (0 tokens until invoked):

| Persona | Expert | Purpose | Tool/Component |
|---------|--------|---------|----------------|
| **Exploit Developer** | Mark Dowd | Generate working PoCs | llm_analysis/agent.py |
| **Crash Analyst** | Charlie Miller / Halvar Flake | Binary crash analysis | llm_analysis/crash_agent.py |
| **Security Researcher** | Research methodology | Vulnerability validation | llm_analysis/agent.py |
| **Patch Engineer** | Senior security engineer | Secure patch creation | llm_analysis/agent.py |
| **Penetration Tester** | Senior pentester | Web payload generation | web/fuzzer.py |
| **Fuzzing Strategist** | Expert strategist | Fuzzing decisions | autonomous/dialogue.py |
| **Binary Exploitation Specialist** | Binary expert | Crash exploit generation | llm_analysis/crash_agent.py |
| **CodeQL Dataflow Analyst** | Dataflow expert | Dataflow validation | codeql/dataflow_validator.py |
| **CodeQL Finding Analyst** | Mark Dowd methodology | CodeQL findings | codeql/autonomous_analyzer.py |

**Usage:**
```
"Use exploit developer persona to create PoC for finding #42"
"Use crash analyst persona to analyze this crash"
"Use fuzzing strategist persona to recommend AFL parameters"
```

See `tiers/personas/` directory for complete persona files.

---

## Example Workflow

```
User: /scan

Claude: [Python executes raptor.py agentic]
        [Scan completes]

        Results: 15 vulnerabilities found

        Analyzing with adversarial thinking:
        - 2 Secrets (instant compromise) - REVIEW FIRST
        - 5 SQLi (database access) - REVIEW SECOND
        - 3 Auth issues (broken access control) - REVIEW THIRD
        - 5 Config issues - REVIEW LAST

        What next?
        1. Deep - Analyze top findings
        2. Fix - Apply patches/improve exploits
        3. Generate report - Export results
        4. Retry - Different parameters
        5. Done - Finish

        Your choice? [1-5]

User: 2

Claude: Reviewing Python-generated patches...
        Found 2 template patches. Using Patch Engineer persona to create actual fixes...
        ✓ All patches now production-ready
        Apply patches? [Y/n]

User: Y

Claude: [Applies patches using Edit tool]
        ✓ Patches applied successfully
        Run /scan again to verify fixes? [Y/n]
```

---

## Adversarial Thinking

**Prioritization formula:** Impact × Exploitability / Detection Time

**Priority order for analysis:**
1. **Secrets** - Instant compromise, no exploitation needed
2. **Input Validation** - SQLi, XSS, command injection (common, highly exploitable)
3. **Authentication** - Broken access control (critical impact)
4. **Cryptography** - Weak algorithms, hardcoded keys (data protection)
5. **Configuration** - Debug mode, insecure defaults (security baseline)

**User can override:** Tell Claude to use different priority order for your threat model.

---

## Interaction Flow

```
User: /scan
   ↓
CLAUDE.md loads (360t)
Session greeting: "RAPTOR ready..."
   ↓
Python executes: raptor.py agentic
   ↓
Scan completes → Results saved to out/
   ↓
analysis-guidance.md auto-loads (565t)
   ↓
Claude analyzes with adversarial prioritization
   ↓
Decision template presented (5 options)
   ↓
User chooses → Claude executes → Repeat until Done
```

**Progressive loading:**
- Session start: 360 tokens
- After scan: 360 + 565 = 925 tokens
- With persona: 925 + 300-700 = up to 1,625 tokens

---

## Output Structure

Results are saved to `out/` directory regardless of interface:

```
out/scan_<repo>_<timestamp>/
├── semgrep_*.sarif              # Semgrep findings
├── codeql_*.sarif               # CodeQL findings (if enabled)
├── scan_metrics.json            # Statistics
├── autonomous_analysis_report.json  # LLM analysis
├── exploits/                    # Generated PoC code
└── patches/                     # Secure fixes
```

**Access:**
- **Claude Code:** Automatically analyzes and presents
- **Python CLI:** Read files directly

---

## Creating Custom Skills

After successful custom approach:

```
User: /create-skill

Claude: What successful approach should we save?

User: I focused on API security - checking auth endpoints first,
      found critical issues faster

Claude: [Extracts patterns]
        [Validates token budget]
        [Checks for overfitting]

        Skill: api_security_auth_focus
        Triggers: API, authentication, auth bypass
        Size: 380 tokens

        Create? [Y/n]

User: Y

Claude: ✓ Saved to: tiers/specialists/custom/api_security_auth_focus.md
        Will auto-load on keywords: API, authentication
```

**Skills are alpha** - Definition creation works, but auto-loading and execution integration not yet implemented.

---

## Troubleshooting

### Placeholder exploits (TODO comments)

**Issue:** Python generated template code instead of working exploits

**Fix:** Use Exploit Developer persona
```
"Use exploit developer persona to create working exploit for finding #X"
```

### Template patches

**Issue:** Patches are recommendations, not actual code

**Fix:** Use Patch Engineer persona
```
"Use patch engineer persona to create production-ready patch"
```

### No findings returned

**Causes:**
- Git not initialized (Semgrep needs .git/)
- Wrong policy groups
- Language not supported

**Fix:** Ask Claude "Why no findings?" and it will help diagnose

### LLM errors

**Python handles automatic fallback:** Claude → GPT-4 → Ollama

**Check:**
- API key set: `echo $ANTHROPIC_API_KEY`
- Sufficient credits
- Network connectivity

---

See docs/ directory for detailed documentation.
