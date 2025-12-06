# Web - Web Application Security Scanning

Scan web applications for OWASP Top 10 vulnerabilities.

## Usage

`/web [--url <url>] [--auth-token <token>] [options]`

## Examples

- `/web --url https://example.com`
- `/web --url https://myapp.com --auth-token "Bearer xyz"`
- `/web --url https://localhost:3000 --depth 5 --max-pages 50`

## Execution Steps

1. **Parse arguments**:
   - Extract `--url` (required)
   - Extract optional: `--auth-token`, `--depth` (default: 3), `--max-pages`
   - If `--url` is missing, ask the user

2. **Execute command**:
   ```bash
   python3 raptor.py web --url <url> [options]
   ```

3. **Monitor execution**: Wait for crawl and scan to complete

4. **Read results** from `out/web_scan_<timestamp>/`:
   - `findings.sarif` - Vulnerability findings
   - `reports/` - Detailed analysis reports

5. **Summarize findings**:
   - Parse SARIF file and list vulnerabilities found
   - Group by vulnerability type (SQL Injection, XSS, CSRF, etc.)
   - Offer to show details or explain vulnerabilities

## Workflow

This command:
1. Crawls web application
2. Tests for OWASP Top 10 vulnerabilities:
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - CSRF (Cross-Site Request Forgery)
   - Authentication bypass
   - And more
3. Generates vulnerability report

## Prerequisites

- Playwright installed
- Internet access

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
