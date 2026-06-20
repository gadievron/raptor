---
name: "source-command-patch"
description: "Generate secure patches for vulnerabilities (beta)"
---

# source-command-patch

Use this skill when the user asks to run the migrated source command `patch`.

## Command Template

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
