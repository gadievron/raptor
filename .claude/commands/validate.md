---
description: Validate that vulnerability findings are real, reachable, and exploitable
---

# /validate - Exploitability Validation Pipeline

Validates that vulnerability findings are real, reachable, and exploitable before investing in exploit development.

## Execution Model

**You (Claude) ARE the LLM for this pipeline.** You perform the analysis work in LLM stages (A-D, F). Mechanical stages (0, E, 1) run via Python/libexec scripts.

**Data flow:** Each stage writes a small `stage-X.json` file with only its own output. The prep script merges it into the cumulative `findings.json` and deletes the stage file. Claude never reads or writes findings.json directly.

**Prep script:** Before each LLM stage, run the prep script which merges the previous stage's output, validates, and sets up the current stage:

```bash
libexec/raptor-validation-helper <A|B|C|D|E|F> "$OUTPUT_DIR" [--target "$TARGET_PATH"]
```

**All stages are mandatory. Execute in sequence: 0 → A → B → C → D → E → F → 1.**
Stage E only applies to memory corruption vulnerabilities. All others are mandatory.

### Stage 0 (Python): Inventory

```bash
libexec/raptor-validation-helper 0 --target "$TARGET_PATH"
```

This starts the run lifecycle, builds the checklist, and imports any /understand output. The last line of output is `OUTPUT_DIR=<path>` — use that path for all subsequent stages.

### Stage A (Claude): One-Shot Assessment

**Load:** `.claude/skills/exploitability-validation/stage-a-oneshot.md`

1. **Prep:** `libexec/raptor-validation-helper A "$OUTPUT_DIR" --target "$TARGET_PATH"`
   Discovers binaries, builds PoCs for standalone C files (mitigations disabled, in `$OUTPUT_DIR/build/`).
2. **Reasoning:** Read source files, assess each function for vulnerabilities. If binaries are available (from prep output), run them for PoC evidence. If no binaries, do source-only analysis.
3. **Output:** Write `stage-a.json` — full findings array with origin + stage_a_summary

**Carry-forward:** Each finding MUST include `origin` and `stage_a_summary` — downstream stages and the prep script check for these.

### Stage B (Claude): Systematic Analysis

**Load:** `.claude/skills/exploitability-validation/stage-b-process.md`

1. **Prep:** `libexec/raptor-validation-helper B "$OUTPUT_DIR" --target "$TARGET_PATH"`
   Merges stage-a.json into findings.json. Fast-paths poc_success findings. Reports how many need full analysis.
2. **Reasoning:** Build attack surface, form hypotheses with value-level predictions, test them, track proximity (0-10 scale). Only analyse findings without `stage_b_summary` (fast-pathed findings already have it).
3. **Output:** Write 5 working docs directly + `stage-b.json` (per-finding updates with stage_b_summary)

**Why Stage B matters:** Without it, you'd make rulings on gut feel with no audit trail. Stage B forces evidence-backed hypotheses, tracks what was tried and failed (`disproven.json`), and measures how close to exploitation (PROXIMITY). Even "obvious" false positives need a tested hypothesis — sometimes they turn out exploitable.

### Stage C (Claude): Sanity Check

**Load:** `.claude/skills/exploitability-validation/stage-c-sanity.md`

1. **Prep:** `libexec/raptor-validation-helper C "$OUTPUT_DIR" --target "$TARGET_PATH"`
   Merges stage-b.json, validates 6 working docs, pre-checks findings against inventory.
2. **Reasoning:** Open each file, verify code verbatim, confirm source→sink flows are real, confirm reachability
3. **Output:** Write `stage-c.json` (per-finding sanity_check + stage_c_summary)

### Stage D (Claude): Ruling

**Load:** `.claude/skills/exploitability-validation/stage-d-ruling.md`

1. **Prep:** `libexec/raptor-validation-helper D "$OUTPUT_DIR" --target "$TARGET_PATH"`
   Merges stage-c.json, flags test/mock paths, assembles evidence cards from carry-forward.
2. **Reasoning:** Synthesize evidence from A/B/C, apply disqualifier checks (D-0 through D-4), assign CVSS vectors
3. **Output:** Write `stage-d.json` (per-finding ruling, cvss_vector, stage_d_summary)

### Stage E (Claude + Python): Feasibility — memory corruption only

**Load:** `.claude/skills/exploitability-validation/stage-e-feasibility.md`

**Display rule:** When displaying Stage E verdicts or final statuses in chat, use Title Case (e.g., "Confirmed (Constrained)" not `confirmed_constrained`). snake_case is for JSON only.

1. **Prep:** `libexec/raptor-validation-helper E "$OUTPUT_DIR" --target "$TARGET_PATH"`
   Merges stage-d.json, validates Stage D output, auto-discovers binaries in the target directory.
2. **Analysis:** For each binary group found by prep, run feasibility:
   ```bash
   libexec/raptor-run-feasibility <binary_path> "$OUTPUT_DIR/findings.json" "$OUTPUT_DIR"
   ```
   This analyzes the binary, maps constraints to findings, and updates findings.json.

3. **Output:** Findings are updated automatically with feasibility verdicts and `final_status`:

| Feasibility Verdict | `final_status` |
|---------------------|----------------|
| likely / likely_exploitable | `exploitable` |
| difficult | `confirmed_constrained` |
| unlikely | `confirmed_blocked` |
| not_applicable | `confirmed` (unchanged) |
| binary_not_found | `confirmed_unverified` |

Skip Stage E if `--skip-feasibility` or no memory corruption findings.

### Stage F (Claude): Self-Review

**Load:** `.claude/skills/exploitability-validation/stage-f-review.md`

1. **Prep:** `libexec/raptor-validation-helper F "$OUTPUT_DIR"`
   Merges stage-e.json, maps verdicts to final_status, computes CVSS scores, checks consistency.
2. **Reasoning:** Review all findings — misclassifications, weak evidence, CVSS accuracy, missed instances. Ask: "What did I get wrong?"
3. **Output:** Write `stage-f.json` (per-finding corrections + stage_f_summary). **Do not write validation-report.md** — Stage 1 generates it.

### Stage 1 (Python): Report Generation

```bash
libexec/raptor-validation-helper 1 "$OUTPUT_DIR"
```

This merges stage-f.json, generates the validation report, diagrams, coverage records, and completes the run lifecycle. The findings summary and coverage summary are printed to stdout.

Then read `{output_dir}/validation-report.md` and add a 1-2 sentence summary paragraph
after the `# Exploitability Validation Report` header — e.g., "All 3 buffer overflows are
real and reachable. 2 are directly exploitable; the third is constrained by RELRO." Use only
facts from the findings data.

**GATE: VERBATIM OUTPUT.** Read `$OUTPUT_DIR/summary.txt` and copy its ENTIRE contents
into your chat response exactly as-is. No editing, no reformatting, no column removal. If
the table has 7 columns, your output must have 7 columns.

---

## Examples

```bash
# Validate all vulnerability types in a codebase
/validate ./src

# Focus on a specific vulnerability type
/validate ./webapp --vuln-type command_injection

# Validate pre-existing scanner findings (skips Stage A discovery)
/validate ./src --findings scanner-results.json

# Validate memory corruption with binary path for Stage E
/validate ./vuln_app --vuln-type format_string --binary ./build/vuln

# Skip feasibility analysis even for memory corruption
/validate ./vuln_app --vuln-type buffer_overflow --skip-feasibility

# Use explicit output directory (e.g. shared with /understand)
/validate ./src --out out/shared-run/
```

---

## MUST-GATEs

This command enforces strict validation gates. Full definitions are in `.claude/skills/exploitability-validation/SKILL.md` — read it before starting.

1. **ASSUME-EXPLOIT**: Investigate as if exploitable until proven otherwise
2. **STRICT-SEQUENCE**: Follow methodology, additional ideas presented separately
3. **CHECKLIST**: Track coverage compliance
4. **NO-HEDGING**: Verify all "if/maybe/uncertain" claims
5. **FULL-COVERAGE**: Check ALL code, no sampling
6. **PROOF**: Show vulnerable code for every finding
7. **CONSISTENCY**: Verify vuln_type/severity/status match description and proof
8. **POC-EVIDENCE**: PoC must produce observable evidence, not just "ran without error"

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

---
