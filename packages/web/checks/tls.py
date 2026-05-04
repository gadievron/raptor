"""ASVS V9 -- TLS and transport security checks."""

from __future__ import annotations

from typing import List, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession


@registry.register(CheckCategory.TLS, "V9.1.1", "HTTP not redirected to HTTPS")
class HttpsRedirectCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        parsed = urlparse(target_url)
        if parsed.scheme == "https":
            # Check if HTTP version redirects
            http_url = urlunparse(parsed._replace(scheme="http"))
            http_parsed = urlparse(http_url)
            http_path = http_parsed.path or "/"
            try:
                # Use a fresh session to avoid auth cookies interfering
                import requests
                resp = requests.get(
                    http_url,
                    allow_redirects=False,
                    timeout=10,
                    verify=False,
                )
                if resp.status_code not in (301, 302, 307, 308):
                    return [self._result(
                        passed=False, url=http_url,
                        evidence=f"HTTP {http_url} returned {resp.status_code} (no redirect to HTTPS)",
                        detail=(
                            "The HTTP version of the site does not redirect to HTTPS. Users who "
                            "visit via HTTP are exposed to network eavesdropping and MITM attacks. "
                            "Combined with a missing HSTS header, this is a persistent downgrade risk."
                        ),
                        recommendation=(
                            "Configure the web server to issue 301 (permanent) redirects from HTTP "
                            "to HTTPS for all paths. Also set an HSTS header with a long max-age."
                        ),
                        severity="high", asvs_ref="ASVS 5.0 V9.1.1",
                    )]
                location = resp.headers.get("Location", "")
                if location and urlparse(location).scheme != "https":
                    return [self._result(
                        passed=False, url=http_url,
                        evidence=f"Redirect target is not HTTPS: Location: {location}",
                        detail="HTTP redirects to another HTTP URL rather than HTTPS.",
                        recommendation="Ensure all redirects from HTTP point to the HTTPS equivalent.",
                        severity="high", asvs_ref="ASVS 5.0 V9.1.1",
                    )]
            except Exception:
                pass
            return []
        else:
            # Target itself is HTTP
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Target URL scheme: {parsed.scheme}",
                detail=(
                    "The target application is being scanned over plain HTTP. All traffic is "
                    "transmitted in cleartext, exposing credentials, session tokens, and data to "
                    "network eavesdropping."
                ),
                recommendation=(
                    "Deploy TLS and redirect all HTTP traffic to HTTPS. Obtain a certificate "
                    "from Let's Encrypt (free) or a commercial CA."
                ),
                severity="critical", asvs_ref="ASVS 5.0 V9.1.1",
            )]


@registry.register(CheckCategory.TLS, "V9.1.2", "Mixed content served over HTTPS")
class MixedContentCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse
        if urlparse(target_url).scheme != "https":
            return []

        try:
            resp = client.get("/")
            html = resp.text
        except Exception:
            return []

        import re
        mixed = re.findall(
            r'''(?:src|href|action)\s*=\s*['"]http://([^'"]+)['"]''',
            html, re.I
        )
        if mixed:
            examples = mixed[:3]
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Mixed content URLs: {', '.join(f'http://{u}' for u in examples)}",
                detail=(
                    f"The HTTPS page loads {len(mixed)} resource(s) over HTTP. Browsers block "
                    "active mixed content (scripts, iframes) and warn on passive (images). "
                    "Active mixed content allows network attackers to inject malicious scripts."
                ),
                recommendation=(
                    "Update all resource URLs to use HTTPS. Use protocol-relative URLs (//...) "
                    "or HTTPS-absolute URLs. Enable CSP 'upgrade-insecure-requests' as a safety net."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V9.1.2",
            )]
        return []
