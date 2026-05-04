"""Extract API routes and endpoints from inline and external JavaScript."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, List, Set
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

_MAX_SCRIPT_SIZE = 512 * 1024  # 512 KB per script

_ROUTE_PATTERNS = [
    # fetch / axios / XHR
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|patch|delete|head))\s*\(\s*['"`]([^'"`\s]+)['"`]''', re.I),
    # $.ajax url:
    re.compile(r'''\.ajax\s*\(\s*\{[^}]*?url\s*:\s*['"`]([^'"`\s]+)['"`]''', re.I | re.DOTALL),
    # Express-style route definitions
    re.compile(r'''app\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]''', re.I),
    # React Router / Vue Router path:
    re.compile(r'''path\s*:\s*['"`](/[^'"`\s]*)['"`]'''),
    # Generic api/endpoint keys
    re.compile(r'''['"`](?:api|endpoint|url|baseUrl|baseURL)\s*['"`]\s*:\s*['"`]([^'"`\s]+)['"`]''', re.I),
    # href/action strings starting with /api
    re.compile(r'''['"`](/api[^'"`\s]*)['"`]'''),
]

_SCRIPT_SRC_RE = re.compile(r'''<script[^>]+src\s*=\s*['"]([^'"]+)['"]''', re.I)


def extract_js_routes(client: "WebClient", base_url: str) -> List[str]:
    """Fetch the root page, gather script tags, extract route patterns."""
    found_urls: List[str] = []
    seen_routes: Set[str] = set()
    base_origin = _origin(base_url)

    def _add(route: str) -> None:
        if not route or route in seen_routes:
            return
        seen_routes.add(route)
        if route.startswith("/"):
            url = base_url.rstrip("/") + route
        elif route.startswith("http"):
            if _origin(route) != base_origin:
                return
            url = route
        else:
            return
        found_urls.append(url)

    try:
        resp = client.get("/")
        html = resp.text
        if not isinstance(html, str):
            return []
    except Exception as e:
        logger.debug(f"JS route extraction: root fetch failed: {e}")
        return []

    # Inline scripts
    inline_re = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>", re.I | re.DOTALL)
    for m in inline_re.finditer(html):
        for route in _extract_routes(m.group(1)):
            _add(route)

    # External scripts on same origin
    for src_match in _SCRIPT_SRC_RE.finditer(html):
        src = src_match.group(1)
        absolute = urljoin(base_url, src)
        if _origin(absolute) != base_origin:
            continue
        parsed = urlparse(absolute)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        try:
            script_resp = client.get(path)
            if script_resp.status_code == 200 and len(script_resp.content) < _MAX_SCRIPT_SIZE:
                for route in _extract_routes(script_resp.text):
                    _add(route)
        except Exception:
            continue

    logger.info("JS route extraction: %d routes found", len(found_urls))
    return found_urls


def _extract_routes(js_text: str) -> List[str]:
    routes = []
    for pattern in _ROUTE_PATTERNS:
        for m in pattern.finditer(js_text):
            route = m.group(1).strip()
            if route and not route.startswith(("//", "http://www.w3", "#")):
                routes.append(route)
    return routes


def _origin(url: str) -> tuple:
    p = urlparse(url)
    default_port = 443 if p.scheme == "https" else 80
    return (p.scheme.lower(), (p.hostname or "").lower(), p.port or default_port)
