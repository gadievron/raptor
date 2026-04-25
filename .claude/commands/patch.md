---
description: Generate secure patches for vulnerabilities (beta)
---

# /patch - Generate Secure Patches (beta)

Generate secure patches to fix vulnerabilities.

**Requires:** SARIF file from previous /scan

**What it does:**
- Analyzes findings with LLM
- Generates secure patch code
- Saves to out/*/patches/
- Does NOT generate exploits (use /exploit for that)

**Run:** `python3 raptor.py agentic --repo <path> --sarif <sarif-file> --no-exploits --max-findings <N>`

**Example:**
```bash
/scan test/                    # First, find vulnerabilities
/patch                         # Then, generate fixes for findings
```

**Note:** Review patches before applying to production code.

---
