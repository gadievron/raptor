"""Extract API routes and endpoints from inline and external JavaScript."""

from __future__ import annotations

import re
from core.logging import get_logger

from typing import TYPE_CHECKING, List, Set
from urllib.parse import urljoin, urlparse

from packages.web.origin import origin_of

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = get_logger()

_MAX_SCRIPT_SIZE = 512 * 1024  # 512 KB per script

# Cap on JS text fed to the route patterns (inline bodies included —
# a page body is only bounded by the client's much larger response
# cap). Same rationale as the crawler's endpoint scan: modern SPA
# bundles stay well under 4 MB, and a hostile body must not buy
# scan time proportional to its size.
_MAX_JS_BYTES = 4 * 1024 * 1024

# Every quantifier is bounded: a URL over 4 KB is a misclassified
# blob, not a route, and the lazy-DOTALL `.ajax({...url` scan was
# O(occurrences x body) on hostile input with many unclosed braces —
# the exact backtracking shape already fixed in the crawler's twin.
_ROUTE_PATTERNS = [
    # fetch / axios / XHR
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|patch|delete|head))\s*\(\s*['"`]([^'"`\s]{1,4096})['"`]''', re.I),
    # $.ajax url:
    re.compile(r'''\.ajax\s*\(\s*\{[^}]{0,4096}?url\s*:\s*['"`]([^'"`\s]{1,4096})['"`]''', re.I | re.DOTALL),
    # Express-style route definitions
    re.compile(r'''app\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]{1,4096})['"`]''', re.I),
    # React Router / Vue Router path:
    re.compile(r'''path\s*:\s*['"`](/[^'"`\s]{0,4095})['"`]'''),
    # Generic api/endpoint keys
    re.compile(r'''['"`](?:api|endpoint|url|baseUrl|baseURL)\s*['"`]\s*:\s*['"`]([^'"`\s]{1,4096})['"`]''', re.I),
    # href/action strings starting with /api
    re.compile(r'''['"`](/api[^'"`\s]{0,4095})['"`]'''),
]

# The tag interior is bounded ({1,500}): unbounded, a crafted page
# that repeats "<script" makes every occurrence re-scan the rest of
# the page — quadratic. Real script tags put src= well inside the
# bound (attributes before src are a handful of tokens).
_SCRIPT_SRC_RE = re.compile(
    r'''<script[^>]{1,500}src\s*=\s*['"]([^'"]+)['"]''', re.I)


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

    # Inline scripts — linear string scan, not a lazy-DOTALL regex: the
    # regex form re-scanned to end-of-document for every unclosed
    # '<script' occurrence, going quadratic in (tag count x page size);
    # a hostile page with thousands of unclosed tags stalled the whole
    # discovery phase for minutes to hours.
    for script_body in _inline_scripts(html):
        for route in _extract_routes(script_body):
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


def _inline_scripts(html: str, max_scripts: int = 200) -> List[str]:
    """Bodies of inline (non-src) <script> elements, via one linear pass."""
    scripts: List[str] = []
    lower = html.lower()
    pos = 0
    while len(scripts) < max_scripts:
        start = lower.find("<script", pos)
        if start < 0:
            break
        tag_end = lower.find(">", start)
        if tag_end < 0:
            break
        close = lower.find("</script", tag_end + 1)
        if close < 0:
            break
        tag = lower[start:tag_end]
        if "src=" not in tag and "src =" not in tag:
            scripts.append(html[tag_end + 1:close])
        close_end = lower.find(">", close)
        pos = close + 9 if close_end < 0 else close_end + 1
    return scripts


def _extract_routes(js_text: str) -> List[str]:
    routes = []
    if len(js_text) > _MAX_JS_BYTES:
        logger.debug(
            "JS body (%s chars) exceeds route-scan cap (%s); truncating",
            len(js_text), _MAX_JS_BYTES,
        )
        js_text = js_text[:_MAX_JS_BYTES]
    for pattern in _ROUTE_PATTERNS:
        for m in pattern.finditer(js_text):
            route = m.group(1).strip()
            if route and not route.startswith(("//", "http://www.w3", "#")):
                routes.append(route)
    return routes


def _origin(url: str) -> tuple[str, str, int]:
    return origin_of(url)
