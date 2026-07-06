---
description: Web application security scanner (alpha)
dispatch: python3 raptor.py web
---

# /web - RAPTOR Web Application Scanner

WARNING: `/web` is in alpha — expect false positives and incomplete
coverage. Use against test endpoints you own.

**`--help` / `-h`:** If the user passes only `--help` or `-h`, run `python3 raptor.py web --help` and present its output. That command is side-effect-free (no run, lifecycle, output directory, or LLM dispatcher) and is the complete, authoritative flag list — do NOT start a scan or hand-summarise flags from this doc.

You are helping the user scan a web application for security vulnerabilities.

1. **Understand the target**: Get the web application URL
   - Full URL (e.g., https://example.com)
   - Ask about authentication if needed
   - Ask about scope (crawl depth, max pages)

2. **Run RAPTOR web scan**: Execute the web scanning command:
   ```bash
   python3 raptor.py web --url <url>
   ```

   For a live target, RAPTOR writes a scope receipt and defaults to `active`
   actions only. Use `--validator nuclei` for an opt-in second opinion, or
   `--ffuf-wordlist <path>` to feed external content discovery into the crawl.

3. **Analyze results**: After the scan:
   - Summarize vulnerabilities found (XSS, SQLi, CSRF, etc.)
   - Show severity ratings
   - Explain how to exploit them (if safe to do so)
   - Show generated patches or mitigation advice

4. **Help fix issues**: Offer to:
   - Explain each vulnerability type
   - Suggest secure coding practices
   - Help implement fixes

## Example Commands

Basic web scan:
```bash
python3 raptor.py web --url https://example.com
```

Authenticated scanning is supported with `--auth-mode form`, `bearer`,
`cookie`, or `basic`. MFA/SSO apps are best handled with a manually exported
cookie or bearer token rather than pretending RAPTOR can magic its way through
an MFA flow.

## Important Notes

- Only scan applications you own or have permission to test
- Web scanning looks for OWASP Top 10 vulnerabilities
- Results are saved to `out/web_scan_<timestamp>/`
- `scope-receipt.json` and `web-execution-policy.json` show what RAPTOR was allowed to touch
- `web-evidence-ledger.json` shows the baseline/attack/diff chain behind each finding
- External validator no-match results are not refutations

Be ethical and responsible with security testing!
