---
description: Analyze existing SARIF findings with LLM
---

# /analyze - RAPTOR LLM Analysis

Analyzes existing SARIF files with LLM (for findings from previous scans).

Execute: `python3 raptor.py analyze --repo <path> --sarif <sarif-file>`

Use when you already have SARIF findings and want LLM analysis.

---

## SAGE MEMORY

When SAGE is available:
- **Before analysis**: Call `sage_recall` with domain `raptor-findings` for context on similar vulnerabilities
- **After analysis**: Store analysis results via `sage_remember` in domain `raptor-findings`
- **If SAGE is unavailable, skip — purely additive**
