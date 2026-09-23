"""ASVS V7/V8 -- Information disclosure and error handling checks."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

_STACK_TRACE_PATTERNS = [
    # Co-occurrence gaps are bounded ({0,1000}): with an unbounded
    # `.*` gap a crafted response that repeats the head token makes
    # every occurrence re-scan the rest of the body — quadratic.
    # Real trace lines sit well inside the bound.
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"at [a-z_$][\w$]*\.[a-z_$][\w$]*\(.{0,1000}\.java:\d+\)", re.I),
    re.compile(r"System\.NullReferenceException", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"PHP Fatal error|PHP Warning|PHP Notice", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"ORA-\d{5}:", re.I),
    re.compile(r"Warning: mysql_", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"<b>Warning</b>:.{0,1000}on line <b>\d+</b>", re.I),
    re.compile(r"undefined method|NoMethodError|NameError", re.I),
    re.compile(r"RuntimeError|ValueError|KeyError|AttributeError", re.I),
]

@registry.register(CheckCategory.INFORMATION, "V7.4.1", "Stack trace in error response")
class StackTraceCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Trigger a likely-404 path to see error response. Paths must
        # stay benign: this check is passive-tier, and an attack-shaped
        # value (an earlier "/?id=<script>" probe) is a crafted probe —
        # active-tier by the vocabulary the receipt gates on.
        trigger_paths = [
            "/this-path-does-not-exist-raptor-probe",
            "/api/does-not-exist-raptor",
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
    """Probes the shared sensitive-path catalog PLUS any external-
    discovery candidates (ffuf hits classified by sensitive_paths):
    external tools nominate, this check verifies with first-party
    request/response evidence."""

    def run(self, client, target_url, session=None, discovery=None):
        import secrets

        from packages.web.sensitive_paths import SENSITIVE_PATHS

        findings = []
        probes = list(SENSITIVE_PATHS.items())
        external = (discovery or {}).get("external_paths") or []
        known = {path for path, _label in probes}
        probes.extend(
            (path, label) for path, label in external if path not in known
        )

        # Soft-404 / blanket-403 calibration: probe a path that cannot
        # exist and remember how the target answers it. SPA catch-alls
        # (200 + app shell for every path) and WAFs (403 for every
        # path) would otherwise turn the whole catalog into findings.
        control_status: int | None = None
        control_length: int | None = None
        try:
            control = client.get(
                f"/raptor-{secrets.token_hex(8)}-does-not-exist",
            )
            control_status = control.status_code
            control_length = len(control.content or b"")
        except Exception:
            pass

        def _matches_control(resp) -> bool:
            if control_status is None or resp.status_code != control_status:
                return False
            if control_length is None:
                return True
            length = len(resp.content or b"")
            bigger = max(length, control_length) or 1
            return abs(length - control_length) / bigger <= 0.1

        for path, label in probes:
            try:
                resp = client.get(path)
                # A response indistinguishable from the known-nonexistent
                # control is the catch-all answer, not the file.
                if _matches_control(resp):
                    continue
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
                    # Bounded title gaps: unbounded `.*` chains
                    # re-scan a crafted body from every <title>;
                    # the two gaps multiply per attempt, so they
                    # stay small (real titles are far shorter).
                    if re.search(
                        r"Index of /|Directory listing|"
                        r"<title>.{0,200}directory.{0,200}</title>",
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
class VerboseHttpMethodsCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        try:
            client.get("/", headers={"X-HTTP-Method-Override": "OPTIONS"})
            # Also try a real OPTIONS request. This bypasses WebClient
            # (which speaks only GET/POST), so its transport failures
            # must be counted here for degraded-coverage accounting;
            # WebClient's own failures above already self-count.
            import ipaddress

            import requests as req_lib
            from urllib.parse import urlparse

            from packages.web.checks.base import note_transport_error
            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            # Mirror WebClient's rule (the tls.py sibling implements the
            # same): loopback/private targets must not route through a
            # corporate proxy env whose NO_PROXY rarely covers loopback —
            # the off-client OPTIONS probe otherwise silently lost
            # coverage on proxied hosts scanning local fixtures.
            _host = (parsed.hostname or "").lower()
            _local = _host == "localhost"
            if not _local:
                try:
                    _ip = ipaddress.ip_address(_host)
                    _local = _ip.is_loopback or _ip.is_private
                except ValueError:
                    pass
            _session = req_lib.Session()
            _session.trust_env = not _local
            try:
                # allow_redirects=False: the check needs only the FIRST
                # response's Allow header. Following a target-controlled
                # Location on this off-client lane (requests' default)
                # walked the scanner past _is_in_scope, the private-IP/
                # DNS-rebinding gate, and the execution-policy audit —
                # and let a different host supply the graded evidence.
                # Sibling off-client probe tls.py passes the same flag.
                try:
                    opts = _session.options(
                        base + "/", timeout=10, verify=client.verify_ssl,
                        allow_redirects=False,
                    )
                except req_lib.RequestException:
                    note_transport_error(client)
                    return []
            finally:
                _session.close()
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
