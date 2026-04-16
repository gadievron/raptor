---
description: Scan a repository with Semgrep and CodeQL
---

# RAPTOR Security Scanner

You are helping the user run RAPTOR's autonomous security scanning on a code repository.

## Your Task

1. **Understand the user's request**: They want to scan code for security vulnerabilities
2. **Identify the target**: Ask which directory/repository to scan if not specified
3. **Run RAPTOR scan**: Execute the appropriate command based on what they need:
   - For full autonomous scan (recommended): `python3 raptor.py agentic --repo <path>`
   - For quick Semgrep scan: `python3 raptor.py scan --repo <path>`
   - For CodeQL only: `python3 raptor.py codeql --repo <path>`

4. **Analyze results**: After the scan completes:
   - Read the output SARIF files and reports
   - Summarize the vulnerabilities found
   - Explain the severity and exploitability
   - Show any generated exploits or patches

5. **Help fix issues**: Offer to:
   - Apply the generated patches
   - Explain how to fix vulnerabilities manually
   - Run additional analysis on specific findings

## Example Commands

Full autonomous workflow (Semgrep + CodeQL + LLM analysis):
```bash
python3 raptor.py agentic --repo /path/to/code --max-findings 10
```

Quick Semgrep scan:
```bash
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp
```

## Important Notes

- Always use absolute paths for repositories
- The scan outputs go to `out/` directory
- RAPTOR generates:
  - SARIF files with findings
  - Exploit PoC code (in `exploits/` directory)
  - Secure patches (in `patches/` directory)
  - Detailed analysis reports

Be helpful and explain security concepts clearly!

---
