"""ASVS V14.5 -- CORS misconfiguration checks."""

from __future__ import annotations

from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_PROBE_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.com",
]


@registry.register(CheckCategory.CORS, "V14.5.1", "CORS allows arbitrary origin with credentials")
class CorsWildcardWithCredentialsCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        findings = []
        for probe_origin in _PROBE_ORIGINS:
            try:
                resp = client.get(
                    "/",
                    headers={
                        "Origin": probe_origin,
                        "Access-Control-Request-Method": "GET",
                    },
                )
            except Exception:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                findings.append(self._result(
                    passed=False, url=target_url,
                    evidence=(
                        f"Origin: {probe_origin} -> "
                        f"Access-Control-Allow-Origin: {acao}, "
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    detail=(
                        "The server returns 'Access-Control-Allow-Origin: *' combined with "
                        "'Access-Control-Allow-Credentials: true'. While browsers block this "
                        "combination per spec, some older or misconfigured clients honour it, "
                        "and the configuration indicates intent to allow cross-origin credentialed "
                        "requests which is a design error."
                    ),
                    recommendation=(
                        "Never combine a wildcard origin with credentials. If credentialed "
                        "cross-origin requests are needed, explicitly allowlist the trusted origin(s)."
                    ),
                    severity="high", asvs_ref="ASVS 5.0 V14.5.1",
                ))
                break

            if acao and acao == probe_origin and acac.lower() == "true":
                if probe_origin != "null":
                    findings.append(self._result(
                        passed=False, url=target_url,
                        evidence=(
                            f"Origin: {probe_origin} -> "
                            f"Access-Control-Allow-Origin: {acao}, "
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        detail=(
                            f"The server reflects the attacker-supplied origin '{probe_origin}' "
                            "back in Access-Control-Allow-Origin while also setting "
                            "Access-Control-Allow-Credentials: true. This allows any website "
                            "to make credentialed cross-origin requests and read the response, "
                            "enabling session token theft and CSRF bypass."
                        ),
                        recommendation=(
                            "Maintain an explicit allowlist of trusted origins. Validate the "
                            "incoming Origin header against this list -- never reflect it back unconditionally."
                        ),
                        severity="critical", asvs_ref="ASVS 5.0 V14.5.1",
                    ))
                    break

        return findings


@registry.register(CheckCategory.CORS, "V14.5.2", "CORS allows null origin")
class CorsNullOriginCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/", headers={"Origin": "null"})
        except Exception:
            return []

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "null":
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Origin: null -> Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                detail=(
                    "The server accepts 'null' as a trusted CORS origin. The null origin is sent "
                    "by sandboxed iframes, local files, and redirected requests -- all attacker-controllable "
                    "contexts. Accepting it effectively bypasses CORS protections."
                ),
                recommendation=(
                    "Remove 'null' from the allowed origins list. Only explicitly allowlisted "
                    "HTTPS origins should be trusted."
                ),
                severity="high", asvs_ref="ASVS 5.0 V14.5.2",
            )]
        return []


@registry.register(CheckCategory.CORS, "V14.5.3", "Sensitive headers exposed via CORS")
class CorsSensitiveHeadersCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/", headers={"Origin": "https://test.example.com"})
        except Exception:
            return []

        exposed = resp.headers.get("Access-Control-Expose-Headers", "")
        if not exposed:
            return []

        sensitive = {"authorization", "cookie", "set-cookie", "x-auth-token", "x-api-key"}
        exposed_lower = {h.strip().lower() for h in exposed.split(",")}
        leaked = sensitive & exposed_lower

        if leaked:
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Access-Control-Expose-Headers: {exposed}",
                detail=(
                    f"The following sensitive headers are exposed to cross-origin JavaScript "
                    f"via Access-Control-Expose-Headers: {', '.join(leaked)}. This allows "
                    "cross-origin scripts to read authentication credentials."
                ),
                recommendation=(
                    "Remove sensitive headers from Access-Control-Expose-Headers. "
                    "Only expose headers that cross-origin clients genuinely need to read."
                ),
                severity="high", asvs_ref="ASVS 5.0 V14.5.3",
            )]
        return []
