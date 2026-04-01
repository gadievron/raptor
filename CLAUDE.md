# RAPTOR - Autonomous Offensive/Defensive Research Framework

Safe operations (install, scan, read, generate): DO IT.
Dangerous operations (apply patches, delete, git push): ASK FIRST.

---

## SESSION START

**On first message:**
VERY IMPORTANT: follow these steps in order.
1. Run `python3 raptor_startup.py >/dev/null 2>&1` (generates `.startup-output`)
2. Read `.startup-output` using the Read tool, then output its contents verbatim as a fenced code block (``` with no language tag). Do NOT paraphrase or reformat.
3. **UNLOAD:** Remove `.startup-output` contents from context (do not retain in conversation history)
4. On a single line, output "Quick commands:" then list the /agentic, /scan, /fuzz, /web commands (don't explain what they do) and note /commands for the full list.

---

## COMMANDS

/scan /fuzz /web /agentic /codeql /analyze - Security testing
/exploit /patch - Generate PoCs and fixes (beta)
/validate - Exploitability validation pipeline (see below)
/understand - Code understanding: map attack surface, trace flows, hunt variants (see below)

**Note:** `/agentic` runs scan → dedup → prep → analysis (with validation methodology). Use `--sequential` to bypass parallel orchestration.
/crash-analysis - Autonomous crash root-cause analysis (see below)
/oss-forensics - GitHub forensic investigation (see below)
/create-skill - Save approaches (alpha)

---

## OUTPUT STYLE

**Status values:**
- In JSON: snake_case (`exploitable`, `confirmed`, `ruled_out`, `disproven`)
- In human-readable output (reports, terminal): Title Case (`Exploitable`, `Confirmed`, `Ruled Out`)
- Never ALL_CAPS (`EXPLOITABLE`, `CONFIRMED`, `RULED_OUT`)

**No red/green status indicators:**
- Do not use 🔴/🟢 - perspective-dependent (bad for defenders ≠ bad for researchers)
- Other emojis are fine (⚠️, ✓, etc.)

---

## CRASH ANALYSIS

The `/crash-analysis` command provides autonomous root-cause analysis for C/C++ crashes.

**Usage:** `/crash-analysis <bug-tracker-url> <git-repo-url>`

**Agents:**
- `crash-analysis-agent` - Main orchestrator
- `crash-analyzer-agent` - Deep root-cause analysis using rr traces
- `crash-analyzer-checker-agent` - Validates analysis rigorously
- `function-trace-generator-agent` - Creates function execution traces
- `coverage-analysis-generator-agent` - Generates gcov coverage data

**Skills** (in `.claude/skills/crash-analysis/`):
- `rr-debugger` - Deterministic record-replay debugging
- `function-tracing` - Function instrumentation with -finstrument-functions
- `gcov-coverage` - Code coverage collection
- `line-execution-checker` - Fast line execution queries

**Requirements:** rr, gcc/clang (with ASAN), gdb, gcov

---

## OSS FORENSICS

The `/oss-forensics` command provides evidence-backed forensic investigation for public GitHub repositories.

**Usage:** `/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]`

**Agents:**
- `oss-forensics-agent` - Main orchestrator
- `oss-investigator-gh-archive-agent` - Queries GH Archive via BigQuery
- `oss-investigator-gh-api-agent` - Queries live GitHub API
- `oss-investigator-gh-recovery-agent` - Recovers deleted content (Wayback/commits)
- `oss-investigator-local-git-agent` - Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent` - Extracts IOCs from vendor reports
- `oss-hypothesis-former-agent` - Forms evidence-backed hypotheses
- `oss-evidence-verifier-agent` - Verifies evidence via `store.verify_all()`
- `oss-hypothesis-checker-agent` - Validates claims against verified evidence
- `oss-report-generator-agent` - Produces final forensic report

**Skills** (in `.claude/skills/oss-forensics/`):
- `github-archive` - GH Archive BigQuery queries
- `github-evidence-kit` - Evidence collection, storage, verification
- `github-commit-recovery` - Recover deleted commits
- `github-wayback-recovery` - Recover content from Wayback Machine

**Requirements:** `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery

**Output:** `.out/oss-forensics-<timestamp>/forensic-report.md`

---

## EXPLOITABILITY VALIDATION

The `/validate` command validates that vulnerability findings are real, reachable, and exploitable.

**Usage:** `/validate <target_path> [--vuln-type <type>] [--findings <file>]`

**Stages:** 0 (Inventory) → A (One-Shot) → B (Process) → C (Sanity) → D (Ruling) → E (Feasibility) → F (Review)

**Skills** (in `.claude/skills/exploitability-validation/`):
- `SKILL.md` - Shared context, gates, execution rules
- `stage-0-inventory.md` through `stage-f-review.md` - Stage instructions

**Output:** `out/exploitability-validation-<timestamp>/validation-report.md`

---

## CODE UNDERSTANDING

The `/understand` command provides deep, adversarial code comprehension for security research.

**Usage:** `/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>] [--out <dir>]`

**Modes:**
- `--map` — Build context: entry points, trust boundaries, sinks → `context-map.json`
- `--trace <entry>` — Follow one data flow source → sink with full call chain → `flow-trace-<id>.json`
- `--hunt <pattern>` — Find all variants of a pattern across the codebase → `variants.json`
- `--teach <subject>` — Explain a framework, library, or pattern in depth (inline)

**Skills** (in `.claude/skills/code-understanding/`):
- `SKILL.md` — Gates, config, output format
- `map.md` — Entry point enumeration, trust boundary mapping, sink catalog
- `trace.md` — Step-by-step data flow tracing with branch coverage
- `hunt.md` — Structural, semantic, and root-cause variant analysis
- `teach.md` — Framework/pattern explanation with security conclusion

**Output:** `.out/code-understanding-<timestamp>/`

**Pipeline integration:** Planned — output schemas are aligned with validation pipeline formats for future integration.

---

## PROGRESSIVE LOADING

**When scan completes:** Load `tiers/analysis-guidance.md` (adversarial thinking)
**When validating exploitability:** Load `.claude/skills/exploitability-validation/SKILL.md` (gates, methodology)
**When validation errors occur:** Load `tiers/validation-recovery.md` (stage-specific recovery)
**When developing exploits:** Load `tiers/exploit-guidance.md` (constraints, techniques)
**When errors occur:** Load `tiers/recovery.md` (recovery protocol)
**When requested:** Load `tiers/personas/[name].md` (expert personas)
**When running /understand:** Load `.claude/skills/code-understanding/SKILL.md` (gates, config) plus the relevant mode file: `map.md`, `trace.md`, `hunt.md`, or `teach.md`

---

## BINARY ANALYSIS

**Flow: Find vulnerabilities FIRST, then check exploitability.**

1. **Analyze the binary** - Find vulnerabilities (buffer overflows, format strings, etc.)
2. **If vulnerabilities found** - Run exploit feasibility analysis (MANDATORY)

```python
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary

# MANDATORY: Run this after finding vulnerabilities
result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**DO NOT use checksec or readelf instead** - they miss critical constraints like:
- Empirical %n verification (glibc may block it)
- Null byte constraints from strcpy (can't write 64-bit addresses)
- ROP gadget quality (0 usable gadgets = no ROP chain)
- Input handler bad bytes
- Full RELRO blocks .fini_array too (not just GOT)

**The `exploitation_paths` section tells you if code execution is actually possible** given the system's mitigations (glibc version, RELRO, etc.).

---

## EXPLOIT DEVELOPMENT

**Verify constraints BEFORE attempting any technique.** Many hours are wasted on architecturally impossible approaches.

**MANDATORY: Check `exploitation_paths` verdict first:**
- Unlikely = no known path, suggest environment changes
- Difficult = primitives exist but hard to chain, be honest about challenges
- Likely exploitable = good chance, proceed with suggested techniques

**Follow the chain_breaks** - these tell you exactly what WON'T work.
**Follow the what_would_help** - these tell you what MIGHT work.

**ALWAYS offer next steps, even for Difficult/Unlikely verdicts:**
- Try alternative targets (if available)
- Focus on info leaks only
- Run in older environment (Docker)
- Move on to other targets

**Never just stop** - let the user decide how to proceed.

See `tiers/exploit-guidance.md` for detailed constraint tables and technique alternatives.

---

## STRUCTURE

Python orchestrates everything. Claude shows results concisely.
Never circumvent Python execution flow.
- never disclose remote OLLAMA server location in code, comments, logs etc
