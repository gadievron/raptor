---
description: CodeQL deep static analysis with dataflow validation
---

# /codeql - RAPTOR CodeQL Analysis

Runs CodeQL-only deep static analysis with dataflow validation.

Execute: `python3 raptor.py codeql --repo <path>`

Slower but finds complex vulnerabilities that Semgrep misses.

---

## SAGE MEMORY

When SAGE is available:
- **Before analysis**: Call `sage_recall` with domain `raptor-findings` for known dataflow patterns in similar codebases
- **After analysis**: Store significant CodeQL findings via `sage_remember` in domain `raptor-findings`
- **If SAGE is unavailable, skip — purely additive**
