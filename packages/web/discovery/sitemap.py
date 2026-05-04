"""sitemap.xml parser -- recursively collects URLs from sitemap and sitemap index."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, List, Set
from urllib.parse import urlparse

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

_MAX_SITEMAPS = 10
_MAX_URLS = 500

_NS = {
    "sm": "http://www.sitemaps.org/schemas/sitemap/0.9",
    "image": "http://www.google.com/schemas/sitemap-image/1.1",
}


def fetch_sitemap(client: "WebClient", base_url: str) -> List[str]:
    """Return all URLs found in sitemap.xml (including sitemap index). Capped at 500."""
    seen_sitemaps: Set[str] = set()
    urls: List[str] = []
    base_origin = _origin(base_url)

    _process_sitemap(
        client, "/sitemap.xml", base_origin, seen_sitemaps, urls, depth=0
    )
    return urls[:_MAX_URLS]


def _process_sitemap(
    client: "WebClient",
    path: str,
    base_origin: tuple,
    seen: Set[str],
    urls: List[str],
    depth: int,
) -> None:
    if depth > 3 or len(seen) >= _MAX_SITEMAPS or len(urls) >= _MAX_URLS:
        return
    if path in seen:
        return
    seen.add(path)

    try:
        resp = client.get(path)
        if resp.status_code != 200:
            return
        root = ET.fromstring(resp.text)
    except Exception as e:
        logger.debug("sitemap fetch/parse failed for %s: %s", path, e)
        return

    tag = root.tag.lower()

    if "sitemapindex" in tag:
        # Sitemap index -- recurse into each child sitemap
        for loc in root.iter():
            if "loc" in loc.tag.lower() and loc.text:
                child_url = loc.text.strip()
                child_parsed = urlparse(child_url)
                if _origin(child_url) == base_origin:
                    child_path = child_parsed.path
                    if child_parsed.query:
                        child_path += f"?{child_parsed.query}"
                    _process_sitemap(
                        client, child_path, base_origin, seen, urls, depth + 1
                    )
    else:
        # Regular sitemap -- collect <loc> URLs
        for loc in root.iter():
            if "loc" in loc.tag.lower() and loc.text:
                url = loc.text.strip()
                if _origin(url) == base_origin and url not in urls:
                    urls.append(url)
                    if len(urls) >= _MAX_URLS:
                        return


def _origin(url: str) -> tuple:
    p = urlparse(url)
    default_port = 443 if p.scheme == "https" else 80
    return (p.scheme.lower(), (p.hostname or "").lower(), p.port or default_port)
