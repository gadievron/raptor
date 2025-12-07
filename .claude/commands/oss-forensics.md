# /oss-forensics - OSS GitHub Forensic Investigation

You are about to orchestrate a forensic investigation on a public GitHub repository.

## Your Role

You are the ORCHESTRATOR for this investigation. You will spawn specialist agents and coordinate their work following a structured workflow.

## Instructions

1. **Read the orchestration skill:**
   `.claude/skills/oss-forensics/orchestration/SKILL.md`

2. **Follow the workflow** defined in that skill exactly

3. **The user's investigation request is:**
   {rest of command arguments after /oss-forensics}

4. **Parse any flags:**
   - `--max-followups N` (default: 3) - Maximum evidence collection rounds
   - `--max-retries N` (default: 3) - Maximum hypothesis revision rounds

5. **Execute the investigation** through these phases:
   - Phase 0: Initialize investigation (run init script)
   - Phase 1: Parse prompt & form research question
   - Phase 2: Parallel evidence collection (spawn 4-5 investigators)
   - Phase 3: Hypothesis formation loop (with followup requests)
   - Phase 4: Evidence verification
   - Phase 5: Hypothesis validation loop (with revisions)
   - Phase 6: Generate final report
   - Phase 7: Inform user of completion

## Output Location

All results will be saved to: `.out/oss-forensics-{timestamp}/`

Key outputs:
- `evidence.json` - All collected evidence (EvidenceStore)
- `evidence-verification-report.md` - Verification results
- `hypothesis-*.md` - Analysis iterations
- `forensic-report.md` - Final report with timeline, attribution, IOCs

## Requirements

- **GOOGLE_APPLICATION_CREDENTIALS**: BigQuery credentials for GH Archive queries
  - See `.claude/skills/oss-forensics/github-archive/SKILL.md` for setup
- **Internet access**: For GitHub API and Wayback Machine queries

## Specialist Agents Available

**Evidence Collection** (spawn in parallel):
- `oss-investigator-gh-archive-agent`: Queries GH Archive via BigQuery (immutable events)
- `oss-investigator-github-agent`: Queries GitHub API and recovers commits by SHA
- `oss-investigator-wayback-agent`: Recovers deleted content via Wayback Machine
- `oss-investigator-local-git-agent`: Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent`: Extracts IOCs from vendor reports (if URL provided)

**Analysis Pipeline** (spawn sequentially):
- `oss-hypothesis-former-agent`: Forms hypothesis, can request more evidence
- `oss-evidence-verifier-agent`: Verifies evidence against original sources
- `oss-hypothesis-checker-agent`: Validates claims against verified evidence
- `oss-report-generator-agent`: Produces final forensic report

## Examples

```
/oss-forensics "Investigate lkmanka58's activity on aws/aws-toolkit-vscode"

/oss-forensics "Validate claims in this vendor report: https://example.com/report"

/oss-forensics "What happened with the stability tag on aws/aws-toolkit-vscode on July 13, 2025?"

/oss-forensics "Investigate the July 13 incident on aws/aws-toolkit-vscode" --max-followups 5
```

## Important Notes

- You (main Claude) are the orchestrator - you spawn all agents
- Spawn evidence collectors in parallel for efficiency
- Wait for each phase to complete before proceeding
- Spawn followup investigations if oss-hypothesis-former-agent identifies any loose ends
- Pass working directory to all agents
