"""Prototype pollution checks -- server-side and client-side indicators.

Server-side prototype pollution (SSPP) injects properties into
Object.prototype on the server, affecting every subsequent object created
in the same process. Can escalate from information disclosure to RCE.

Reference: Gareth Heyes (PortSwigger Research)
"""

from __future__ import annotations

from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_SENTINEL = "raptor_pp_probe_value_8472"


@registry.register(CheckCategory.INJECTION, "V5.3.1", "Server-side prototype pollution")
class ServerSidePrototypePollutionCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Try __proto__ injection in JSON POST body
        api_paths = ["/api", "/api/v1", "/api/v2"]
        if discovery:
            for url in discovery.get("apis", []):
                from urllib.parse import urlparse
                path = urlparse(url.get("url", "")).path
                if path:
                    api_paths.insert(0, path)

        for path in api_paths[:5]:
            try:
                resp = client.post(
                    path,
                    json_data={
                        "__proto__": {_SENTINEL: True},
                        "constructor": {"prototype": {f"{_SENTINEL}2": True}},
                    },
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text if isinstance(resp.text, str) else ""

                # If the sentinel appears in the response, the object was polluted
                if _SENTINEL in body:
                    return [self._result(
                        passed=False, url=target_url.rstrip("/") + path,
                        evidence=(
                            f"POST {path} with __proto__ payload "
                            f"reflected sentinel '{_SENTINEL}' in response"
                        ),
                        detail=(
                            "The server-side application appears to merge user-supplied JSON "
                            "properties including __proto__ or constructor.prototype into "
                            "application objects. Server-side prototype pollution can "
                            "escalate from information disclosure (leaking hidden properties) "
                            "to remote code execution by overwriting properties like "
                            "'shell', 'env', or 'argv' used by child_process.spawn()."
                        ),
                        recommendation=(
                            "Never use recursive merge functions (lodash.merge, jQuery.extend) "
                            "with user-supplied objects without filtering __proto__ and "
                            "constructor keys. Use JSON schema validation on all inbound payloads. "
                            "Freeze Object.prototype in Node.js: Object.freeze(Object.prototype)."
                        ),
                        severity="critical", asvs_ref="ASVS 5.0 V5.3.1",
                    )]
            except Exception:
                continue

        # Also probe via query string (some frameworks merge query params into objects)
        try:
            resp = client.get(
                "/",
                params={
                    f"__proto__[{_SENTINEL}]": "polluted",
                    f"constructor[prototype][{_SENTINEL}2]": "polluted",
                },
            )
            body = resp.text if isinstance(resp.text, str) else ""
            if _SENTINEL in body or "polluted" in body:
                return [self._result(
                    passed=False, url=target_url,
                    evidence=f"Query string __proto__ injection reflected sentinel in response",
                    detail=(
                        "Prototype pollution via query string: the application merges query "
                        "parameters into objects without filtering prototype-chain properties."
                    ),
                    recommendation=(
                        "Filter __proto__, constructor, and prototype keys from all user-supplied "
                        "input before merging into application objects."
                    ),
                    severity="high", asvs_ref="ASVS 5.0 V5.3.1",
                )]
        except Exception:
            pass

        return []
