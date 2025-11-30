# /oss-forensics - OSS GitHub Forensic Investigation

Investigates security incidents on public GitHub repositories with evidence-backed analysis.

## Usage

```
/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]
```

## What This Does

1. Parses prompt to extract repos, actors, dates, vendor report URLs
2. Forms a clear research question (asks for clarification if ambiguous)
3. Collects evidence in parallel from multiple sources
4. Builds hypothesis with evidence citations
5. Verifies all evidence against original sources
6. Validates hypothesis claims against verified evidence
7. Produces forensic report with timeline, attribution, and IOCs

## Examples

```
/oss-forensics "Investigate lkmanka58's activity on aws/aws-toolkit-vscode"

/oss-forensics "Validate claims in this vendor report: https://example.com/report"

/oss-forensics "What happened with the stability tag on aws/aws-toolkit-vscode on July 13, 2025?"
```

## Output

Results saved to `.out/oss-forensics-<timestamp>/`:
- `evidence.json` - All collected evidence (EvidenceStore)
- `evidence-verification-report.md` - Verification results
- `hypothesis-*.md` - Analysis iterations
- `forensic-report.md` - Final report with timeline, attribution, IOCs

## Requirements

- **GOOGLE_APPLICATION_CREDENTIALS**: BigQuery credentials for GH Archive queries
  - See `.claude/skills/oss-forensics/github-archive/SKILL.md` for setup
- **Internet access**: For GitHub API and Wayback Machine queries

## Workflow Details

This command invokes `oss-forensics-agent` which orchestrates:

**Evidence Collection** (parallel):
- `oss-investigator-gh-archive-agent`: Queries GH Archive via BigQuery
- `oss-investigator-gh-api-agent`: Queries live GitHub API
- `oss-investigator-gh-recovery-agent`: Recovers deleted content via Wayback/commits
- `oss-investigator-local-git-agent`: Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent`: Extracts IOCs from vendor reports (if URL provided)

**Analysis Pipeline**:
- `oss-hypothesis-former-agent`: Forms hypothesis, can request more evidence (max 3 rounds)
- `oss-evidence-verifier-agent`: Verifies evidence via `store.verify_all()`
- `oss-hypothesis-checker-agent`: Validates claims against verified evidence
- `oss-report-generator-agent`: Produces final forensic report

The analysis follows a hypothesis-validation loop - if the checker rejects, the hypothesis-former agent is re-invoked with feedback (max 3 retries).
