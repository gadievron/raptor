---
description: Analyze existing SARIF findings with LLM
---

# /analyze - RAPTOR LLM Analysis

Analyzes existing SARIF files with LLM (for findings from previous scans).

Execute: `python3 raptor.py analyze --repo <path> --sarif <sarif-file>`

Use when you already have SARIF findings and want LLM analysis.

## Multi-model support

The same `--model`, `--consensus`, and `--judge` flags from `/agentic`
work here. When any role flag is provided, `/analyze` preps findings
then dispatches them through the parallel orchestrator:

```
# Analyze with a specific model
python3 raptor.py analyze --repo /path --sarif findings.sarif --model gemini-2.5-pro

# Add consensus + judge
python3 raptor.py analyze --repo /path --sarif findings.sarif \
  --model gemini-2.5-pro --consensus claude-opus-4-6 --judge gpt-5.4
```

Without role flags, `/analyze` runs the sequential single-model path as before.

---
