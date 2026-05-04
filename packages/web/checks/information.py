"""ASVS V7/V8 -- Information disclosure and error handling checks."""

from __future__ import annotations

import re
from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_STACK_TRACE_PATTERNS = [
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"at [a-z_$][\w$]*\.[a-z_$][\w$]*\(.*\.java:\d+\)", re.I),
    re.compile(r"System\.NullReferenceException", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"PHP Fatal error|PHP Warning|PHP Notice", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"ORA-\d{5}:", re.I),
    re.compile(r"Warning: mysql_", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"<b>Warning</b>:.*on line <b>\d+</b>", re.I),
    re.compile(r"undefined method|NoMethodError|NameError", re.I),
    re.compile(r"RuntimeError|ValueError|KeyError|AttributeError", re.I),
]

_DEBUG_PATHS = [
    ("/.git/HEAD", "Git repository exposed"),
    ("/.git/config", "Git config exposed"),
    ("/phpinfo.php", "PHP info page exposed"),
    ("/info.php", "PHP info page exposed"),
    ("/test.php", "PHP test page exposed"),
    ("/server-status", "Apache mod_status exposed"),
    ("/server-info", "Apache mod_info exposed"),
    ("/nginx_status", "nginx stub_status exposed"),
    ("/.env", ".env file exposed"),
    ("/actuator/env", "Spring Boot env actuator exposed"),
    ("/actuator/heapdump", "Spring Boot heap dump exposed"),
    ("/actuator/threaddump", "Spring Boot thread dump exposed"),
    ("/debug/vars", "Go debug vars exposed"),
    ("/debug/pprof", "Go pprof endpoint exposed"),
    ("/config.php", "Config file exposed"),
    ("/wp-config.php", "WordPress config exposed"),
    ("/database.yml", "Database credentials file exposed"),
    ("/secrets.json", "Secrets file exposed"),
]


@registry.register(CheckCategory.INFORMATION, "V7.4.1", "Stack trace in error response")
class StackTraceCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Trigger a likely-404 path to see error response
        trigger_paths = [
            "/this-path-does-not-exist-raptor-probe",
            "/api/does-not-exist-raptor",
            "/?id=<script>",
        ]
        for path in trigger_paths:
            try:
                resp = client.get(path)
                body = resp.text
                for pattern in _STACK_TRACE_PATTERNS:
                    if pattern.search(body):
                        snippet = body[:500].strip()
                        return [self._result(
                            passed=False, url=target_url + path,
                            evidence=f"Pattern matched in error response: {snippet!r:.300}",
                            detail=(
                                "The application returns detailed stack traces or framework error "
                                "messages in error responses. This discloses internal file paths, "
                                "class names, library versions, and logic flow that aid exploit development."
                            ),
                            recommendation=(
                                "Disable debug mode and detailed error pages in production. Configure "
                                "a generic error page that logs the full trace server-side but returns "
                                "only a correlation ID to the client."
                            ),
                            severity="medium", asvs_ref="ASVS 5.0 V7.4.1",
                        )]
            except Exception:
                continue
        return []


@registry.register(CheckCategory.INFORMATION, "V8.3.4", "Sensitive files and debug endpoints exposed")
class SensitiveFileCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        findings = []
        for path, label in _DEBUG_PATHS:
            try:
                resp = client.get(path)
                if resp.status_code in (200, 403):
                    severity = "critical" if any(
                        kw in path for kw in (".env", "config", "secret", "database", "heapdump")
                    ) else "high"
                    findings.append(self._result(
                        passed=False, url=target_url.rstrip("/") + path,
                        evidence=f"GET {path} returned HTTP {resp.status_code}",
                        detail=(
                            f"{label} at '{path}' (HTTP {resp.status_code}). "
                            "This path may expose credentials, internal configuration, or "
                            "debugging information that significantly aids an attacker."
                        ),
                        recommendation=(
                            f"Block public access to '{path}' at the web server level. "
                            "Remove debug endpoints and sensitive files from production deployments. "
                            "A 403 still confirms the path exists -- a 404 is safer."
                        ),
                        severity=severity, asvs_ref="ASVS 5.0 V8.3.4",
                    ))
            except Exception:
                continue
        return findings


@registry.register(CheckCategory.INFORMATION, "V8.3.1", "Directory listing enabled")
class DirectoryListingCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        probe_paths = ["/static/", "/assets/", "/uploads/", "/files/", "/images/"]
        for path in probe_paths:
            try:
                resp = client.get(path)
                if resp.status_code == 200:
                    if re.search(
                        r"Index of /|Directory listing|<title>.*directory.*</title>",
                        resp.text, re.I
                    ):
                        return [self._result(
                            passed=False, url=target_url.rstrip("/") + path,
                            evidence=f"Directory listing at {path} (HTTP 200)",
                            detail=(
                                f"Directory listing is enabled at '{path}'. An attacker can "
                                "enumerate all files in this directory, potentially discovering "
                                "backup files, configuration files, or unlinked sensitive content."
                            ),
                            recommendation=(
                                "Disable directory indexing. For Apache: 'Options -Indexes'. "
                                "For nginx: remove 'autoindex on'. For IIS: disable directory browsing."
                            ),
                            severity="medium", asvs_ref="ASVS 5.0 V8.3.1",
                        )]
            except Exception:
                continue
        return []


@registry.register(CheckCategory.INFORMATION, "V7.1.1", "Verbose HTTP methods enabled")
class VerbosHttpMethodsCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/", headers={"X-HTTP-Method-Override": "OPTIONS"})
            # Also try a real OPTIONS request
            import requests as req_lib
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            opts = req_lib.options(base + "/", timeout=10, verify=client.verify_ssl)
            allow = opts.headers.get("Allow", "")
            if allow:
                dangerous = {"TRACE", "TRACK", "DELETE", "PUT"} & {
                    m.strip().upper() for m in allow.split(",")
                }
                if dangerous:
                    return [self._result(
                        passed=False, url=target_url,
                        evidence=f"Allow: {allow}",
                        detail=(
                            f"The server advertises potentially dangerous HTTP methods: "
                            f"{', '.join(sorted(dangerous))}. TRACE can be used for XST attacks. "
                            "PUT/DELETE may allow unauthorised file manipulation."
                        ),
                        recommendation=(
                            "Restrict allowed HTTP methods to only those required by the application. "
                            "Disable TRACE globally. Protect PUT/DELETE with strong authentication."
                        ),
                        severity="low", asvs_ref="ASVS 5.0 V7.1.1",
                    )]
        except Exception:
            pass
        return []
