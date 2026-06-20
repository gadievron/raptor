---
name: "source-command-analyze"
description: "Analyze existing SARIF findings with LLM"
---

# source-command-analyze

Use this skill when the user asks to run the migrated source command `analyze`.

## Command Template

# /analyze - RAPTOR LLM Analysis

Analyzes existing SARIF files with LLM (for findings from previous scans).

Execute: `python3 raptor.py analyze --repo <path> --sarif <sarif-file>`

Use when you already have SARIF findings and want LLM analysis.

---
