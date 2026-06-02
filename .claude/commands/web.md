---
description: Web application security scanner (alpha)
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

(Authenticated scanning is not currently supported by
`raptor.py web`. Track future support via the web-
scanner roadmap; for now, scan only unauthenticated
endpoints.)

## Important Notes

- Only scan applications you own or have permission to test
- Web scanning looks for OWASP Top 10 vulnerabilities
- Results are saved to `out/web_scan_<timestamp>/`

Be ethical and responsible with security testing!
