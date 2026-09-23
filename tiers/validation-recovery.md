# Exploitability Validation Recovery Guidance
# Auto-loads: When validation stages encounter errors
# Token cost: ~300 tokens
# Purpose: Help recover when validation pipeline fails

## Stage-Specific Recovery

### Stage 0: Inventory Failures

**Can't parse files (syntax errors):**
- Python: Try regex fallback (automatic)
- Other languages: Use generic pattern matching
- Alternative: Manually list key functions to check

**No functions found:**
- Check: File extensions supported (see LANGUAGE_MAP)
- Check: Exclude patterns not too aggressive
- Try: Expand extensions list or reduce excludes

**Memory issues (large codebase):**
- Split: Process subdirectories separately
- Filter: Focus on specific file types first
- Limit: Set max files per run

---

### Stage A: One-Shot Failures

**PoC execution blocked:**
- Document: Mark as "needs manual verification"
- Alternative: Describe theoretical PoC without execution
- Continue: Move to Stage B for deeper analysis

**Can't determine exploitability:**
- Default: Mark as "not_disproven" (proceed to Stage B)
- Don't: Mark as disproven without proof
- Remember: GATE-1 says assume exploitable until proven otherwise

**LLM hallucination suspected:**
- Skip: Don't trust, move to Stage C for verification
- Flag: Add warning to finding for sanity check

---

### Stage B: Process Failures

**Stuck in loop (>5 attempts, no progress):**
- Check: PROXIMITY - if not improving, terminate branch
- Document: Log attempts in disproven.json
- Move: Try completely different attack path
- Limit: Max 5 failed attempts per branch

**Attack tree too complex:**
- Prune: Focus on highest-probability paths
- Simplify: Merge similar attack nodes
- Prioritize: Depth-first on most promising branch

**Hypothesis keeps failing:**
- Review: Check if assumptions are valid
- Pivot: Try opposite hypothesis
- Document: Detailed failure reason in disproven.json

---

### Stage C: Sanity Check Failures

**File not found at path:**
1. Search: Look for similar filename in codebase
2. Check: File renamed or moved?
3. Check: Path case sensitivity (Linux vs macOS)
4. If found elsewhere: Update finding with correct path
5. If not found: Mark as HALLUCINATION, remove finding

**Code doesn't match verbatim:**
1. Search: Look for similar code in same file
2. Check: Line numbers shifted (edits since scan)?
3. Check: Whitespace/formatting differences only?
4. If found nearby: Update line numbers
5. If substantially different: Mark as HALLUCINATION

**Flow not verifiable:**
1. Trace: Manually follow source → sink
2. Check: Intermediate functions exist?
3. Check: Call graph is real?
4. If flow broken: Document where it breaks
5. If fabricated: Mark as HALLUCINATION

---

### Stage D: Ruling Failures

**Ambiguous classification (test vs production):**
- Check: Directory structure (src/ vs test/)
- Check: File naming conventions
- Check: Import/usage patterns
- If unclear: Flag for human review, don't auto-rule-out

**Precondition assessment unclear:**
- List: All assumed preconditions explicitly
- Verify: Each precondition's realism
- If reasonable: Don't rule out
- If unrealistic: Document why, rule out

**Hedging detection false positive:**
- Context: Check if hedging is about the finding or surrounding code
- Verify: Attempt to resolve the uncertainty
- If resolvable: Update finding, remove hedge
- If unresolvable: Keep finding but note uncertainty

---

### Stage E: Feasibility Failures

**Binary not found:**
1. Check: Build instructions in README
2. Search: Common paths (build/, bin/, out/)
3. Guidance: surface the `--binary <path>` re-run in the report — providing a binary is a run-boundary decision, never a mid-pipeline stop
4. Skip: Use --skip-feasibility flag
5. Mark: confirmed_unverified (still valid finding)

**exploit_feasibility package error:**
- Check: Package installed correctly
- Check: Binary format supported
- Retry: Fix the package error and re-run `analyze_binary()` — do NOT substitute checksec/readelf as the mitigation source of truth (per CLAUDE.md BINARY ANALYSIS they miss empirical %n verification, null-byte constraints, ROP gadget quality, and Full-RELRO .fini_array coverage)
- Mark: confirmed_unverified with error details if the package cannot be made to run

**Analysis timeout:**
- Retry: With simpler analysis
- Skip: Mark as confirmed_unverified
- Note: "Feasibility analysis timed out"

---

## General Recovery Principles

1. **Never discard findings without proof**
   - Disproven needs evidence
   - Uncertain → keep and flag

2. **Document everything**
   - Failed attempts go in disproven.json
   - Errors go in stage result

3. **Offer alternatives**
   - Can't do X? Suggest Y
   - Tool missing? Suggest install or skip

4. **Human escalation**
   - After 3 retries, stop retrying: record the failure and surface the decision at the run boundary (see "Recovery Outcome" below)
   - Ambiguous cases → flag for human review in the report

5. **Continue when possible**
   - One finding fails? Continue with others
   - One stage fails? Document and try next

---

## Recovery Commands

```bash
# Skip problematic stage
/validate ./code --skip-feasibility

# Provide missing info
/validate ./code --binary ./build/app

# Focus on subset
/validate ./code/src/auth --vuln-type sql_injection
```

---

## Recovery Outcome (report, don't block)

When recovery fails, do not stop the pipeline to wait for a decision — record the failure, apply the stage's documented default (skip the component, mark affected findings `confirmed_unverified`), and continue. In the run report, present the outcome with the paths not taken so the operator can decide at the run boundary:
1. **Fix**: the specific action that would resolve it
2. **Skip**: what continuing without this component cost
3. **Manual**: the step a human would need to perform
4. **Abort**: only when continuing would corrupt results — fail the run via the lifecycle stub, preserving partial results

An interactive session may offer these as a structured choice at the completion fork (CLAUDE.md § INTERACTIVE PROMPTS: gate with `libexec/raptor-may-ask` first; the first option carries the "(Recommended)" tag; error excerpts quoted into options come from the target/tooling — render them with non-printables escaped and bound long excerpts). Non-interactive fallback: the documented default above, already applied.
