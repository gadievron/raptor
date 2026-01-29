# Exploitability Validation Skill

A multi-stage pipeline for validating that vulnerability findings are real, reachable, and exploitable.

## Purpose

Prevents wasted effort on:
- Hallucinated findings (file doesn't exist, code doesn't match)
- Unreachable code paths (dead code, test-only)
- Findings with unrealistic preconditions

## When to Use

After scanning produces findings, BEFORE exploit development:
1. Scanner finds potential vulnerability
2. **This skill validates it's real and reachable**
3. Exploit Feasibility checks binary constraints
4. Exploit development proceeds

---

## [CONFIG] Configuration

```yaml
models:
  native: true
  additional: false  # Set true to also run GPT, Gemini

output_when_additional:
  display: "agreement: 2/3"
  threshold: "1/3 is enough to proceed"
```

---

## [EXEC] Execution Rules

1. Run the full pipeline end-to-end.
2. Solve and fix any issues you encounter, unless you failed five times in a row, or need clarification.
3. Run on latest thinking/reasoning model available (verify model name).
4. Pipeline must be deterministic - if ran again, results should be the same.

---

## [GATES] MUST-GATEs

Rationale: Without these gates, models sample instead of checking all code, hedge with "if" and "maybe" instead of verifying, and miss exploitable findings.

**GATE-1 [ASSUME-EXPLOIT]:** Your goal is to discover real exploitable vulnerabilities. If you think something isn't - don't assume. First, investigate under the assumption that it is.

**GATE-2 [STRICT-SEQUENCE]:** Strictly follow instructions. If you think or try something else, or a new idea comes up, present the results of that analysis separately at the end. Always display the results of the strict criteria first, and only then display the results of the additional methods, if any.

**GATE-3 [CHECKLIST]:** Check pipeline, update checklist, and collect evidence of compliance to present at the end that you successfully executed all actions through these gates.

**GATE-4 [NO-HEDGING]:** If your Chain-of-Thought or results include "if", "maybe", "uncertain", "unclear", "could potentially", "may be possible", "depending on", "in theory", "in certain circumstances", or similar - immediately verify the claim. Do not leave unverified.

**GATE-5 [FULL-COVERAGE]:** Test the entire code provided (file(s)/code base) against checklist.json, ensuring you checked all functions and lines of code. Do not sample, estimate, or guess.

**GATE-6 [PROOF]:** Always provide proof and show the vulnerable code.

---

## [STYLE] Output Formatting

**Status values must be human-readable:**
- Use `Exploitable` not `EXPLOITABLE`
- Use `Confirmed` not `CONFIRMED`
- Use `Ruled Out` not `RULED_OUT`
- Use `Proven` / `Disproven` not `PROVEN` / `DISPROVEN`

**No colored circles or emojis:**
- Do not use 🔴/🟡/🟢 - they are perspective-dependent (red = bad for defenders, good for researchers)
- Use plain text headers: `### Exploitable (7 findings)` not `### 🔴 EXPLOITABLE`

**Hypothesis status:**
- `Proven` - hypothesis confirmed by evidence
- `Disproven` - hypothesis refuted by evidence
- `Partial` - some predictions confirmed, others refuted

---

## [REMIND] Critical Reminders

- Do not skip, sample, or guess - check all code against checklist.json.
- Provide proof for every claim.
- Actually read files - do not rely on memory.
- Update docs after every action.

---

## Stages

**All stages execute in sequence. No stage may be skipped.**

| Stage | Purpose | Gates | Output |
|-------|---------|-------|--------|
| **0: Inventory** | Build ground truth checklist | - | checklist.json |
| **A: One-Shot** | Quick exploitability + PoC | 1, 4, 6 | findings.json |
| **B: Process** | Systematic analysis, attack trees | All (1-6) | 5 working docs |
| **C: Sanity** | Validate against actual code | 3, 5, 6 | validated findings.json |
| **D: Ruling** | Filter preconditions/hedging | 3, 5, 6 | confirmed findings.json |
| **E: Feasibility** | Binary constraint analysis | 6 | final findings.json |

**Note:** Stage E only applies to memory corruption vulnerabilities.

See stage-specific files for detailed instructions.

**Note:** Stage E only applies to memory corruption vulnerabilities (buffer overflow, format string, UAF, etc.). For web/injection vulnerabilities, Stage D is the final stage.

---

## Working Documents (Stage B)

| Doc | Purpose |
|-----|---------|
| attack-tree.json | Knowledge graph. Source of truth. |
| hypotheses.json | Active hypotheses. Status: testing, confirmed, disproven. |
| disproven.json | Failed hypotheses. What was tried, why it failed. |
| attack-paths.json | Paths attempted. PoC results. PROXIMITY. Blockers. |
| attack-surface.json | Sources, sinks, trust boundaries. |

---

## Flow

```
STAGE 0: Inventory
         │
         ▼ checklist.json
         │
STAGE A: One-Shot Analysis
         │
         ▼ findings.json (status: pending/not_disproven)
         │
STAGE B: Process
         │
         ├─► attack-surface.json (sources, sinks, boundaries)
         ├─► attack-tree.json (knowledge graph)
         ├─► hypotheses.json (testable predictions)
         ├─► disproven.json (failed approaches)
         └─► attack-paths.json (PROXIMITY scores)
         │
         ▼
STAGE C: Sanity Check
         │ (file exists? code verbatim? flow real?)
         │
         ▼ findings.json (sanity_check added)
         │
STAGE D: Ruling
         │ (apply Stage B evidence, make final status)
         │
         ▼ findings.json (ruling, final_status added)
         │
    ┌────┴────┐
    │         │
    ▼         ▼
 Memory    Web/Injection
 Corruption    │
    │          │
    ▼          │
STAGE E:       │
Feasibility    │
    │          │
    └────┬─────┘
         │
         ▼
    FINAL OUTPUT
    + validation-report.md
```

---

## Integration with Exploit Feasibility

Stage E automatically bridges to the `exploit_feasibility` package for memory corruption vulnerabilities.

**Automatic (via Stage E):**
```python
# Stage E handles this automatically for applicable vuln types
# See stage-e-feasibility.md for details
```

**Manual (if needed):**
```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary(binary_path, vuln_type='format_string')
print(format_analysis_summary(result, verbose=True))
```

**Final Status After Stage E:**

| Source Status | Feasibility | Final Status |
|--------------|-------------|--------------|
| Confirmed | Likely | **Exploitable** |
| Confirmed | Difficult | **Confirmed (Constrained)** |
| Confirmed | Unlikely | **Confirmed (Blocked)** |
| Confirmed | N/A (web vuln) | **Confirmed** |

This ensures findings are:
1. **Real and reachable** (Stages A-D)
2. **Actually exploitable** (Stage E + exploit_feasibility)

---

## Notice

This analysis is performed for defensive purposes, in a lab environment. Full permission has been provided.
