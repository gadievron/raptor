"""Build a compact application/session model from a web scan."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable
from urllib.parse import urlparse

from packages.web.auth import AuthSession
from packages.web.client import WebClient
from packages.web.discovery import DiscoveryResult
from packages.web.models import WebFinding


def build_web_session_context(
    *,
    base_url: str,
    discovery: DiscoveryResult,
    crawl_data: dict[str, Any],
    client: WebClient,
    session: AuthSession | None,
    findings: Iterable[WebFinding],
) -> dict[str, Any]:
    """Return a sanitized context record for downstream agents."""

    forms = crawl_data.get("discovered_forms", []) or discovery.forms or []
    parameters = list(dict.fromkeys(
        (crawl_data.get("discovered_parameters") or [])
        + list(getattr(discovery, "parameters", []) or [])
    ))
    urls = list(dict.fromkeys(
        (crawl_data.get("discovered_urls") or crawl_data.get("visited_urls") or [])
        + list(getattr(discovery, "urls", []) or [])
        + [base_url]
    ))

    finding_types = Counter(f.vuln_type for f in findings)
    request_history = _request_history(client)
    methods = Counter(str(req.get("method", "GET")).upper() for req in request_history)

    return {
        "target": {
            "base_url": base_url,
            "origin": _origin(base_url),
            "fingerprint": discovery.fingerprint,
        },
        "auth": _auth_context(session),
        "surface": {
            "url_count": len(urls),
            "form_count": len(forms),
            "parameter_count": len(parameters),
            "api_count": len(getattr(discovery, "apis", []) or []),
            "sample_urls": urls[:50],
            "parameters": parameters[:100],
            "forms": [_form_summary(form) for form in forms[:50]],
            "request_methods_seen": dict(methods),
        },
        "objects": _object_hints(parameters, forms),
        "functions": _function_hints(urls, forms),
        "findings": {
            "count": sum(finding_types.values()),
            "by_type": dict(finding_types),
            "confirmed_oracle_findings": [
                f.id for f in findings if f.to_dict().get("confirmed") and f.oracle == "web"
            ],
        },
        "request_history": request_history[-100:],
    }


def _request_history(client: WebClient) -> list[dict[str, Any]]:
    try:
        return list(getattr(client, "request_history", []) or [])
    except TypeError:
        return []


def _auth_context(session: AuthSession | None) -> dict[str, Any]:
    if not session:
        return {
            "mode": "none",
            "authenticated": False,
            "cookie_count": 0,
            "cookie_names": [],
        }
    return {
        "mode": session.mode,
        "authenticated": session.authenticated,
        "username": session.username,
        "session_cookie_name": session.session_cookie_name,
        "cookie_count": len(session.cookies),
        "cookie_names": sorted(session.cookies.keys()),
        "login_url": session.login_url,
        "logout_url": session.logout_url,
    }


def _origin(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
    }


def _form_summary(form: dict[str, Any]) -> dict[str, Any]:
    inputs = form.get("inputs") or {}
    return {
        "action": form.get("action"),
        "method": str(form.get("method", "GET")).upper(),
        "field_names": list(inputs.keys()),
        "field_types": {
            name: details.get("type", "text")
            for name, details in inputs.items()
            if isinstance(details, dict)
        },
    }


def _object_hints(parameters: list[str], forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = set(parameters)
    for form in forms:
        names.update((form.get("inputs") or {}).keys())

    objects = []
    for name in sorted(names):
        lower = name.lower()
        role = "generic_input"
        if any(token in lower for token in ("id", "uuid", "account", "user", "tenant")):
            role = "object_identifier"
        elif any(token in lower for token in ("token", "secret", "password", "csrf")):
            role = "security_sensitive_value"
        elif any(token in lower for token in ("url", "uri", "next", "redirect", "callback")):
            role = "navigation_or_fetch_target"
        objects.append({"name": name, "role": role})
    return objects[:100]


def _function_hints(urls: list[str], forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    functions = []
    for url in urls[:100]:
        path = urlparse(url).path or "/"
        functions.append({
            "type": "endpoint",
            "method": "GET",
            "path": path,
            "action": _classify_path(path),
        })
    for form in forms[:50]:
        action = form.get("action") or "/"
        path = urlparse(action).path or action
        functions.append({
            "type": "form",
            "method": str(form.get("method", "GET")).upper(),
            "path": path,
            "action": _classify_path(path),
        })
    return functions


def _classify_path(path: str) -> str:
    lower = path.lower()
    if any(token in lower for token in ("login", "signin", "auth")):
        return "authentication"
    if any(token in lower for token in ("admin", "manage", "settings")):
        return "administration"
    if any(token in lower for token in ("api", "graphql", "json")):
        return "api"
    if any(token in lower for token in ("search", "query", "filter")):
        return "search"
    return "content"
