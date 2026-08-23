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

(The crawler itself has no auth flags, but the ffuf content-discovery
channel accepts repeatable `--ffuf-header 'Header-Name: value'` and
`--ffuf-cookie 'session=...'` for authenticated discovery. See also
`--ffuf-wordlist`.)

## ffuf content discovery (opt-in)

ffuf runs sandboxed (egress pinned to the target host) whenever
`--ffuf-wordlist` is set. Common recipes — `python3 raptor.py web --help`
for the full flag list:

```bash
# Deep directory discovery: recursion + extensions
python3 raptor.py web --url https://target --ffuf-wordlist dirs.txt \
  --ffuf-recursion --ffuf-extensions '.php,.bak'

# POST parameter discovery (fixed URL, FUZZ in the body)
python3 raptor.py web --url https://target --ffuf-wordlist params.txt \
  --ffuf-path 'api/login' --ffuf-method POST --ffuf-data 'FUZZ=1' \
  --ffuf-header 'Content-Type: application/x-www-form-urlencoded'

# Virtual-host discovery (fixed URL, FUZZ in the Host header)
python3 raptor.py web --url https://target --ffuf-wordlist subdomains.txt \
  --ffuf-vhost

# Multi-wordlist: parameter name x value (clusterbomb)
python3 raptor.py web --url https://target \
  --ffuf-wordlist params.txt --ffuf-wordlist 'values.txt:W2' \
  --ffuf-path 'search?FUZZ=W2'

# API fuzzing from a raw request (e.g. generated from an OpenAPI spec)
python3 raptor.py web --url https://target --ffuf-wordlist payloads.txt \
  --ffuf-request request.txt

# Automatic OpenAPI body sweep: the scan generates a raw request per
# documented JSON operation, ffuf sweeps the payload wordlist through
# each string field matching static error signatures, and every hit is
# re-verified first-party through the three-gate oracle
python3 raptor.py web --url https://target --ffuf-api-sweep payloads.txt

# Blind-timing probe: sleep-payload wordlist + response-time matcher
python3 raptor.py web --url https://target --ffuf-wordlist sleep-payloads.txt \
  --ffuf-path 'search?q=FUZZ' --ffuf-match-time '>3000' --ffuf-rate 5
# (verify every timing hit with the replay oracle before believing it)

# Secret hunting in response bodies
python3 raptor.py web --url https://target --ffuf-wordlist dirs.txt \
  --ffuf-match-regex 'AKIA[0-9A-Z]{16}'

# Headless-browser phases (needs `python3 -m playwright install
# chromium`; on distros newer than the pinned playwright recognizes,
# prefix PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64). Rendered
# crawl sees the post-JS DOM (SPA routes, dynamic forms); XSS is graded
# by actual JavaScript execution, not reflection; fragment probes catch
# DOM sinks the server never sees. Page requests are origin-gated.
python3 raptor.py web --url https://target --browser

# Blind SSRF via out-of-band callbacks: the listener runs INSIDE the
# scanner process (trusted code, never sandboxed — callbacks are
# inbound from the target). One callback proves nothing; findings are
# confirmed only when a replay with a FRESH token calls back too.
python3 raptor.py web --url https://target --oob-listen 8880 \
  --oob-callback-host scanner.reachable.example:8880
```

Operational notes:

- When the SAGE sidecar is running, the scan recalls per-target priors
  at discovery (fingerprint, previously confirmed classes, wordlist
  effectiveness) and stores fresh observations at report time. Priors
  are hint tier only: they reorder vulnerability classes and bias
  payload prompts, and never suppress a check or demote a finding —
  only the current run's oracle concludes.
- Recursion and clusterbomb apply a default `-rate 50` unless
  `--ffuf-rate` is set; recursion also caps each sub-job with
  `-maxtime-job`.
- Every run is capped by ffuf's own `-maxtime` (`--ffuf-max-runtime`,
  default 300s) so partial results are always flushed; `timed_out` in
  the report marks a run the backstop had to kill.
- `--ffuf-stop-on-403` stops early when >95% of responses are 403 —
  the usual WAF signal.

## Important Notes

- Only scan applications you own or have permission to test
- Web scanning looks for OWASP Top 10 vulnerabilities
- Results are saved to `out/web_scan_<timestamp>/`

Be ethical and responsible with security testing!
