# RAPTOR Web Scanner

A web application security scanner built into RAPTOR. It does two things: runs 36 passive checks mapped to ASVS 5.0 against any target, and uses an LLM to generate and evaluate injection payloads against discovered parameters and forms. It works unauthenticated or with a live session.

---

## Quick start

```bash
# Unauthenticated scan
python3 raptor.py web --url https://target.example.com

# With a project (results go into the project output directory)
python3 raptor.py project create myapp --target https://target.example.com
python3 raptor.py project use myapp
python3 raptor.py web --url https://target.example.com

# Authenticated -- form login
python3 raptor.py web --url https://target.example.com \
  --auth-mode form --login-url /login \
  --username admin --password secret

# Authenticated -- MFA/SSO apps (log in manually, export cookies from devtools)
python3 raptor.py web --url https://target.example.com \
  --auth-mode cookie --cookies "session=abc123; csrftoken=xyz"

# Authenticated -- bearer/JWT token
python3 raptor.py web --url https://target.example.com \
  --auth-mode bearer --token "eyJhbGci..."

# Full pipeline: map the attack surface first, then validate findings after
python3 raptor.py web --url https://target.example.com --understand --validate
```

---

## How it works

Seven phases run in sequence.

### Phase 0: Preflight
Checks the target responds. Resets defense telemetry.

### Phase 1: Authentication
Four modes are supported:

| Mode | When to use |
|---|---|
| `none` | Unauthenticated scan (default) |
| `form` | Standard login form with username and password |
| `bearer` | JWT or opaque token |
| `cookie` | MFA, SSO, CAPTCHA -- log in manually and export cookies |
| `basic` | HTTP Basic |

MFA is not automated, and that is deliberate. Automating it means storing TOTP seeds or hooking into authenticator apps, which creates a new security risk and breaks constantly as providers update their flows. The practical answer is cookie import: log in through a browser, copy the session cookies from devtools, pass them via `--cookies`. Burp Suite, Caido, and ZAP all handle MFA the same way.

### Phase 2: Discovery
Before crawling, the scanner tries to find things a link-follower would miss:

- `robots.txt` Disallow paths
- `sitemap.xml` (recursively, including sitemap index files)
- ~200 common admin, debug, config, and backup paths probed in parallel
- JavaScript route extraction from inline scripts and external bundles
- GraphQL introspection and OpenAPI/Swagger spec detection
- Tech stack fingerprinting from response headers, cookies, and HTML

### Phase 3: Crawl
Recursive HTML crawler seeded with Phase 2 results. Follows links, parses forms, extracts inline JS endpoints. Stays within the configured origin, rate-limits requests, and handles redirects without following them off-target.

### Phase 4: Passive checks

36 checks that send no attack payloads, organised by ASVS 5.0 category.

**V14.4 -- Security headers**
CSP (including unsafe-inline and wildcard analysis), HSTS and its max-age, X-Content-Type-Options, X-Frame-Options and CSP frame-ancestors, Referrer-Policy, Permissions-Policy, server version disclosure via Server and X-Powered-By.

**V14.5 -- CORS**
Wildcard origin with credentials, reflected origin with credentials, null origin, sensitive headers in Access-Control-Expose-Headers.

**V3 -- Session management**
Secure, HttpOnly, and SameSite cookie flags; session token in URL; session fixation in authenticated mode (pre/post-login token rotation check).

**V9 -- TLS**
HTTP to HTTPS redirect, mixed content in HTTPS pages.

**V7/V8 -- Information disclosure**
Stack traces in error responses, `.git/HEAD` and `.git/config` exposure, `.env` files, Spring Boot actuator endpoints (`/actuator/env`, `/actuator/heapdump`), phpinfo pages, directory listing, verbose HTTP methods via OPTIONS.

**V2 -- Authentication**
Default credentials (admin/admin, admin/password, admin/blank), account enumeration via response body or status code differences, brute-force protection via repeated failed login attempts.

**V13 -- API security**
GraphQL introspection enabled, OpenAPI/Swagger spec publicly accessible, verbose API error responses from malformed input, mass assignment via JSON body (authenticated mode).

**Infrastructure-layer checks**
This is where most scanners stop looking. These checks follow the methodology James Kettle documented at PortSwigger Research:

- Host header injection (X-Forwarded-Host, X-Host and others reflected in body or Location)
- Password reset link poisoning via host header
- Web cache poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
- Web cache deception on authenticated endpoints
- HTTP request smuggling CL.TE probe via raw socket
- Server-side prototype pollution via `__proto__` in JSON bodies and query strings
- OAuth open redirect in redirect_uri
- OAuth missing state parameter
- SSRF via URL-shaped parameters and proxy headers

### Phase 5: Authenticated checks
The same registry, filtered to checks that require a live session. Session fixation, mass assignment.

### Phase 6: Injection and fuzzing
The LLM generates payloads per parameter per vulnerability class. Five classes by default: SQL injection, XSS, SSTI, command injection, path traversal.

The response analysis requires actual exploitation evidence, not keyword matching. That distinction matters in practice. A page about SQL injection will have the word "SQL" in it. The check only flags if the response contains an unambiguous server-side signal:

- SQLi: MySQL/PostgreSQL/Oracle error messages
- XSS: payload appears verbatim and unescaped in the response body
- SSTI: `{{7*7}}` evaluates to `49` in the response
- Command injection: `/etc/passwd` content, `uid=` output
- Path traversal: actual file content (`root:x:0:0`, `[boot loader]`)

Findings are grouped by endpoint and vulnerability type. Fourteen vulnerable parameters on the same endpoint produce one finding with all parameters listed, not fourteen near-identical entries.

Without an LLM, Phase 6 falls back to a small static payload list and the same evidence-based response analysis.

### Phase 7: Report
Output directory gets:
- `web_findings.json` -- findings in RAPTOR's native schema
- `web_scan_report.json` -- full summary
- `discovery.json` -- discovered URLs, fingerprint, API specs
- `crawl_results.json` -- pages, forms, parameters
- `defense-telemetry.json` -- LLM defense signals (injection hit rate, schema rejection rate)

---

## Output and findings

Findings use RAPTOR's standard schema. Run `python3 raptor.py project findings` to see findings merged across all runs on the active project.

Severity: `critical`, `high`, `medium`, `low`, `informational`.

Injection findings from Phase 6 get `status: needs_review`. Pass `--validate` to run the validation pipeline on them.

---

## Pipeline flags

| Flag | Effect |
|---|---|
| `--understand` | Runs `/understand --map` before Phase 6, builds an adversarial context map of the target, and uses it to prioritise parameters for fuzzing |
| `--validate` | Runs `/validate` on `needs_review` findings after Phase 6 to confirm exploitability and produce PoCs |

Both require an interactive session. They are blocked in CI/CD per the Rule of Two: an agent with write access processing untrusted web content needs a human in the loop.

---

## What makes it different

Most LLM-powered web scanners swap static payload lists for LLM-generated ones and stop there. The problem is they are still only looking at the application layer.

The most interesting web vulnerabilities are often not in the application. They are in the gap between the load balancer, the CDN, the reverse proxy, and the application behind them. Each hop in that chain is an independent HTTP parser with its own quirks. Host header injection, cache poisoning, and request smuggling all exist because front-end and back-end components interpret the same request differently. The passive check set here covers that infrastructure layer explicitly, following the research James Kettle has published at PortSwigger over the last several years.

The other thing most scanners do not handle is what happens when the target is adversarial. If an attacker controls the web content being scanned, they can try to manipulate the LLM doing the analysis. When this scanner's LLM analyses a response body, that content is treated as untrusted: the scanner tracks injection pattern hit rates and LLM nonce leakage across the run and records both in `defense-telemetry.json`. A high preflight hit rate means the target probably contains content designed to skew analysis results.

Findings from the web scanner go into the same schema as findings from static analysis and code review. They can be validated, have PoCs generated against them, and get merged with code findings in the project report. The scanner is one phase in a research workflow, not a tool that produces a report and expects you to do something useful with it.

---

## Extending the scanner

A new check is a single decorated class. Register it and it runs on every scan automatically.

```python
from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

@registry.register(CheckCategory.HEADERS, "V14.4.9", "My new check")
class MyCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # probe the target
        return [self._result(
            passed=False,
            url=target_url,
            evidence="what was observed",
            detail="why it is a problem",
            recommendation="how to fix it",
            severity="medium",
        )]
```

For checks that only make sense with an authenticated session:

```python
@registry.register(CheckCategory.SESSION, "V3.x.x", "My auth check", requires_auth=True)
```

The check will only run in Phase 5 when a live session is present.

---

## Requirements

```
beautifulsoup4>=4.12.0
requests>=2.31.0
PyYAML>=6.0
cryptography>=42.0.0
```

Set `ANTHROPIC_API_KEY` (or equivalent) for LLM payload generation. Without it, Phase 6 uses static fallback payloads.

`pip install instructor` gives more reliable structured output from the LLM. Not required but worth having.
