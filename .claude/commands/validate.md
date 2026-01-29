# /validate - Exploitability Validation Pipeline

Validates that vulnerability findings are real, reachable, and exploitable before investing in exploit development.

## Execution Model

**You (Claude) ARE the LLM for this pipeline.** Don't just run Python and expect results - you must perform the analysis work.

### Step-by-Step Execution

**All stages are mandatory. Execute in sequence: 0 → A → B → C → D → E**

1. **Stage 0 (Python):** Run `build_checklist()` to get inventory
   ```python
   from packages.exploitability_validation import build_checklist
   checklist = build_checklist(target_path, output_dir)
   ```
   Output: `{output_dir}/checklist.json` (saved automatically)

2. **Stage A (Claude):** One-shot analysis - identify potential vulnerabilities
   - Read source files with the Read tool
   - Look for: injection, overflow, UAF, format string, deserialization, etc.
   - For each finding, note: file, line, function, vuln_type, proof (actual code)
   - Output: `findings.json` with status "pending" or "not_disproven"

3. **Stage B (Claude):** Process - systematic analysis with attack trees
   - Build attack surface: sources, sinks, trust boundaries → `attack-surface.json`
   - Build attack tree: knowledge graph of attack paths → `attack-tree.json`
   - Form hypotheses: testable predictions for each finding → `hypotheses.json`
   - Test hypotheses: gather evidence, verify predictions
   - Track failures: why approaches didn't work → `disproven.json`
   - Track proximity: how close to exploitation (0-10 scale) → `attack-paths.json`

   **Stage B produces 5 working documents that MUST be created:**
   ```
   attack-surface.json  - Sources, sinks, trust boundaries
   attack-tree.json     - Attack knowledge graph
   hypotheses.json      - Testable predictions (status: testing/confirmed/disproven)
   disproven.json       - Failed approaches and why
   attack-paths.json    - Paths tried, PROXIMITY scores, blockers
   ```

4. **Stage C (Claude):** Sanity check - verify against actual code
   - Confirm file exists at stated path
   - Confirm vulnerable code exists at stated line (VERBATIM)
   - Confirm source→sink flow is real
   - Confirm code is reachable (called from main/handler)
   - Output: Update `findings.json` with `sanity_check` field

5. **Stage D (Claude):** Ruling - make final determinations
   - Rule out test code, dead code, already-mitigated code
   - Check for preconditions that prevent exploitation
   - Apply hypothesis results from Stage B
   - Final status: Exploitable, Confirmed, or Ruled Out
   - Output: Update `findings.json` with `ruling` and `final_status` fields

6. **Stage E (Python):** Feasibility - for memory corruption only
   ```python
   from packages.exploit_feasibility import analyze_binary
   result = analyze_binary(binary_path, vuln_type='buffer_overflow')
   ```
   Output: `exploit-context.json` (if binary provided)

### Write Results Back

After your analysis, save findings for Stage E:
```python
from packages.exploitability_validation.schemas import create_finding, create_empty_findings
import json

findings = create_empty_findings("D", target_path)
findings["findings"] = [
    create_finding("FIND-0001", "/path/file.c", "func_name", 42, "buffer_overflow", "confirmed"),
    # ... more findings
]
with open(f"{workdir}/findings.json", "w") as f:
    json.dump(findings, f, indent=2)
```

---

## Agentic vs Non-Agentic Mode

| Mode | Context | How Validation Works |
|------|---------|---------------------|
| **Non-Agentic** | `/validate` in Claude Code | Claude (you) performs Stages A-D directly by reading code |
| **Agentic** | `python3 raptor.py agentic` | Semgrep/CodeQL scan first → SARIF converted → deduplication or LLM API validation |

### Non-Agentic Mode (Claude Code)

When user runs `/validate <path>`:
1. **You are the LLM** - perform the analysis yourself
2. Run Stage 0 via Python (inventory) → `checklist.json`
3. Stage A: Read files, identify vulnerabilities → `findings.json`
4. **Stage B: Build attack trees, form & test hypotheses** → 5 working docs
5. Stage C: Verify findings against actual code
6. Stage D: Make rulings based on Stage B evidence
7. Run Stage E via Python if binary provided

```
User: /validate /tmp/vuln
       ↓
Claude: Stage 0 → Stage A → Stage B → Stage C → Stage D → Stage E
              ↓
        Output: checklist.json, findings.json, attack-surface.json,
                attack-tree.json, hypotheses.json, disproven.json,
                attack-paths.json, validation-report.md
```

### Agentic Mode (Python Orchestration)

When user runs `python3 raptor.py agentic --repo <path>`:
1. **Semgrep/CodeQL scan first** - produces SARIF files
2. **SARIF conversion** - deduplicates findings
3. **If LLM API available** - runs full validation pipeline via API calls
4. **If no LLM API** - deduplication only, skips validation theater
5. **Stage E** - runs if binary provided

```
python3 raptor.py agentic --repo /tmp/vuln
       ↓
Semgrep → SARIF (21 findings) → Dedupe (15 unique) → [LLM validation if API key] → Stage E
```

### Key Difference

| Aspect | Non-Agentic | Agentic |
|--------|-------------|---------|
| Scanner | None (Claude analyzes directly) | Semgrep + CodeQL |
| LLM | Claude (always available) | External API (optional) |
| Findings source | Claude's analysis | SARIF from scanners |
| Without LLM API | Always works | Deduplication only |

---

## Usage

```
/validate <target_path> [--vuln-type <type>] [--findings <file>] [--binary <path>] [--skip-feasibility]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `target_path` | Directory or file to analyze |
| `--vuln-type` | Focus on specific vulnerability type (optional) |
| `--findings` | Pre-existing findings.json to validate (skips discovery) |
| `--binary` | Path to compiled binary for Stage E feasibility analysis |
| `--skip-feasibility` | Skip Stage E even for memory corruption vulns |

## Vulnerability Types

- `command_injection` - OS command injection
- `sql_injection` - SQL injection
- `xss` - Cross-site scripting
- `path_traversal` - Directory traversal
- `ssrf` - Server-side request forgery
- `deserialization` - Insecure deserialization
- `buffer_overflow` - Buffer overflow (memory corruption)
- `format_string` - Format string vulnerabilities

## What This Does

Runs a 6-stage validation pipeline:

| Stage | Purpose | Output |
|-------|---------|--------|
| **0: Inventory** | Build checklist of all code | checklist.json |
| **A: One-Shot** | Quick exploitability + PoC attempt | findings.json |
| **B: Process** | Systematic analysis with attack trees | working docs |
| **C: Sanity** | Verify against actual code (catch hallucinations) | validated findings |
| **D: Ruling** | Filter test code, preconditions, hedging | confirmed findings |
| **E: Feasibility** | Binary constraint analysis (memory corruption only) | final findings |

**Note:** Stage E only runs for memory corruption vulnerabilities (buffer_overflow, format_string, use_after_free, etc.). Web vulnerabilities skip directly to final output after Stage D.

## Examples

```bash
# Scan a web application for command injection
/validate ./webapp --vuln-type command_injection

# Validate all vulnerability types in a codebase
/validate ./src

# Validate pre-existing scanner findings
/validate ./src --findings scanner-results.json

# Validate memory corruption with binary path for Stage E
/validate ./vuln_app --vuln-type format_string --binary ./build/vuln

# Skip feasibility analysis even for memory corruption
/validate ./vuln_app --vuln-type buffer_overflow --skip-feasibility
```

## Output

Results saved to `.out/exploitability-validation-<timestamp>/`:

```
.out/exploitability-validation-20260122-143022/
├── checklist.json           # All functions to check
├── findings.json            # Final validated findings
├── attack-tree.json         # Attack knowledge graph
├── hypotheses.json          # Tested hypotheses
├── disproven.json           # Failed approaches
├── attack-paths.json        # Paths tried + PROXIMITY
├── attack-surface.json      # Sources, sinks, boundaries
├── exploit-context.json     # Binary context (Stage E, if applicable)
└── validation-report.md     # Human-readable summary
```

## Stage E: Exploit Feasibility Integration

For memory corruption findings, Stage E automatically runs binary constraint analysis:

```python
from packages.exploit_feasibility import analyze_binary, save_exploit_context

# Analyzes: PIE, NX, Canary, RELRO, glibc mitigations, ROP gadgets, bad bytes
# Returns: verdict (Likely/Difficult/Unlikely) + chain breaks + recommendations
result = analyze_binary(binary_path, vuln_type='format_string')
context_file = save_exploit_context(binary_path)  # Survives context compaction
```

**Final Status After Stage E:**

| Verdict | Final Status | Meaning |
|---------|--------------|---------|
| Likely | Exploitable | Clear path to code execution |
| Difficult | Confirmed (Constrained) | Primitives exist but hard to chain |
| Unlikely | Confirmed (Blocked) | No viable path with current mitigations |
| N/A | Confirmed | Web/injection vuln (Stage E skipped) |

## Stage B: Systematic Analysis

Stage B is where superficial scanning becomes thorough validation:

| Without Stage B | With Stage B |
|-----------------|--------------|
| Quick ruling based on gut feel | Evidence-backed ruling from tested hypotheses |
| "Looks like a false positive" | "Hypothesis H2 disproven: ws:// only in comment (evidence: line 463)" |
| No record of what was tried | `disproven.json` documents failed approaches |
| No proximity tracking | PROXIMITY scores show how close to exploitation |

**If you're tempted to skip Stage B because findings "obviously" look like false positives:**
1. Create the hypothesis anyway (e.g., "H1: SSRF via urlretrieve")
2. List testable predictions (e.g., "P1.1: Script runs at runtime")
3. Gather evidence to disprove (e.g., "Script outputs .h file → build-time only")
4. Record in `disproven.json` with lesson learned

This creates an audit trail and catches cases where "obvious" false positives are actually exploitable.

---

## MUST-GATEs

This command enforces strict validation gates:

1. **ASSUME-EXPLOIT**: Investigate as if exploitable until proven otherwise
2. **STRICT-SEQUENCE**: Follow methodology, additional ideas presented separately
3. **CHECKLIST**: Track coverage compliance
4. **NO-HEDGING**: Verify all "if/maybe/uncertain" claims
5. **FULL-COVERAGE**: Check ALL code, no sampling
6. **PROOF**: Show vulnerable code for every finding

## When to Use

- After `/scan` or `/agentic` produces findings
- Before investing time in `/exploit` development
- When you suspect false positives from scanners
- To validate third-party security reports

## Workflow Integration

```
/scan -> /validate -> /exploit
   |         |           |
   v         v           v
 Finds    Confirms    Develops
 vulns    they're     working
          real        exploits
```
