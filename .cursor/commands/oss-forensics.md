# OSS-Forensics - OSS GitHub Forensic Investigation

Investigate security incidents on public GitHub repositories with evidence-backed analysis.

## Usage

`/oss-forensics <prompt> [--max-followups N] [--max-retries N]`

## Examples

- `/oss-forensics "Investigate lkmanka58's activity on aws/aws-toolkit-vscode"`
- `/oss-forensics "Validate claims in this vendor report: https://example.com/report"`
- `/oss-forensics "What happened with the stability tag on aws/aws-toolkit-vscode on July 13, 2025?"`
- `/oss-forensics "Investigate suspicious commits in owner/repo" --max-followups 5 --max-retries 3`

## Execution Steps

1. **Parse arguments**:
   - Extract prompt/research question (required)
   - Extract optional: `--max-followups` (default: 3), `--max-retries` (default: 3)
   - If prompt is ambiguous, ask for clarification to form a clear research question

2. **Check prerequisites**:
   - Verify `GOOGLE_APPLICATION_CREDENTIALS` is set (required for BigQuery)
   - If missing, inform user and provide setup instructions

3. **Execute command**:
   ```bash
   python3 raptor.py oss-forensics "<prompt>" [--max-followups N] [--max-retries N]
   ```

4. **Monitor execution**: This is a complex multi-agent workflow that may take time.

5. **Read results** from `.out/oss-forensics-<timestamp>/`:
   - `evidence.json` - All collected evidence (EvidenceStore)
   - `evidence-verification-report.md` - Verification results
   - `hypothesis-*.md` - Analysis iterations
   - `forensic-report.md` - Final report with timeline, attribution, IOCs

6. **Summarize findings**:
   - Present key findings from forensic report
   - Show timeline of events
   - List IOCs (Indicators of Compromise)
   - Offer to show detailed evidence or report

## Workflow

This command orchestrates a 10-agent workflow:

**Evidence Collection** (parallel):
- `oss-investigator-gh-archive-agent`: Queries GH Archive via BigQuery
- `oss-investigator-gh-api-agent`: Queries live GitHub API
- `oss-investigator-gh-recovery-agent`: Recovers deleted content via Wayback/commits
- `oss-investigator-local-git-agent`: Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent`: Extracts IOCs from vendor reports (if URL provided)

**Analysis Pipeline**:
- `oss-hypothesis-former-agent`: Forms hypothesis, can request more evidence (max followups)
- `oss-evidence-verifier-agent`: Verifies evidence against original sources
- `oss-hypothesis-checker-agent`: Validates claims against verified evidence (max retries)
- `oss-report-generator-agent`: Produces final forensic report

The analysis follows a hypothesis-validation loop - if the checker rejects, the hypothesis-former agent is re-invoked with feedback.

## Prerequisites

- **GOOGLE_APPLICATION_CREDENTIALS**: BigQuery credentials for GH Archive queries
  - See `.claude/skills/oss-forensics/github-archive/SKILL.md` for setup
- **Internet access**: For GitHub API and Wayback Machine queries

## Reference

See `.cursor/rules/oss-forensics-workflow.mdc` for complete workflow documentation.
