"""Prototype pollution checks -- server-side and client-side indicators.

Server-side prototype pollution (SSPP) injects properties into
Object.prototype on the server, affecting every subsequent object created
in the same process. Can escalate from information disclosure to RCE.

Reference: Gareth Heyes (PortSwigger Research)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

_SENTINEL = "raptor_pp_probe_value_8472"


def _clean_request_shows(client, needle: str) -> bool:
    """Whether *needle* appears on a CLEAN request that never sent it.

    Prototype pollution persists process-wide, so a genuinely polluted
    property surfaces on unrelated requests. Echo does not: a page that
    merely reflects the probe body/query shows the sentinel only on the
    probe response. This is the behavioral oracle that separates the
    two — sentinel-in-probe-response alone is just parameter echo.
    """
    try:
        resp = client.get("/")
        body = resp.text if isinstance(resp.text, str) else ""
        return needle in body
    except Exception:
        return False


@registry.register(CheckCategory.INJECTION, "V5.3.1", "Server-side prototype pollution")
class ServerSidePrototypePollutionCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        # Baseline guard: if the sentinel is already on the page before
        # any probe (a previous run's stored content), the oracle below
        # cannot attribute it to this probe — bail out.
        if _clean_request_shows(client, _SENTINEL):
            return []

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

                # Sentinel in the probe response could be a mere echo of
                # the rejected payload (validation errors); pollution is
                # confirmed only when a clean request also shows it.
                if _SENTINEL in body and _clean_request_shows(client, _SENTINEL):
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
            client.get(
                "/",
                params={
                    f"__proto__[{_SENTINEL}]": "polluted",
                    f"constructor[prototype][{_SENTINEL}2]": "polluted",
                },
            )
            # Reflection of the probe VALUE ('polluted') or sentinel key
            # in the probed response is plain parameter echo (search
            # pages, validation errors). Only a clean follow-up request
            # showing the sentinel demonstrates the prototype was
            # actually polluted.
            if _clean_request_shows(client, _SENTINEL):
                return [self._result(
                    passed=False, url=target_url,
                    evidence=(
                        "Query string __proto__ injection: sentinel visible "
                        "on a subsequent clean request"
                    ),
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
