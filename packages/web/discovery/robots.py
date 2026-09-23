"""robots.txt parser -- collects Disallow paths as candidate URLs."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

# Bounds on hostile robots.txt input. fetch_robots runs unconditionally
# in Phase 2, unauthenticated and before any budget, and the WebClient
# response cap (128 MiB) is far beyond what a Disallow parse should
# retain or walk: real-world robots.txt files are a few KiB, and an
# uncapped parse of a served-to-order multi-MiB file wedged discovery
# for hours. Path cap follows sitemap's _MAX_URLS pattern.
_MAX_PARSE_BYTES = 256 * 1024
_MAX_PATHS = 500


def fetch_robots(client: "WebClient", base_url: str) -> List[str]:
    """Return Disallow paths from robots.txt. Empty list on any failure."""
    try:
        resp = client.get("/robots.txt")
        if resp.status_code != 200:
            return []
        return _parse_disallow(resp.text)
    except Exception as e:
        logger.debug("robots.txt fetch failed: %s", e)
        return []


def _parse_disallow(text: str) -> List[str]:
    if len(text) > _MAX_PARSE_BYTES:
        logger.warning(
            "robots.txt is %d bytes; parsing only the first %d",
            len(text), _MAX_PARSE_BYTES,
        )
        text = text[:_MAX_PARSE_BYTES]
    paths: List[str] = []
    # Set-backed dedup: `path not in list` is O(n) per line, O(n^2)
    # over the file — a hostile line count turned the parse quadratic.
    seen: set = set()
    for line in text.splitlines():
        if len(paths) >= _MAX_PATHS:
            logger.warning(
                "robots.txt Disallow paths capped at %d", _MAX_PATHS,
            )
            break
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/" and not path.startswith("#"):
                # Strip wildcards -- keep the base path
                path = path.split("*")[0].rstrip("?")
                if path and path not in seen:
                    seen.add(path)
                    paths.append(path)
        elif line.lower().startswith("sitemap:"):
            # Handled by sitemap.py, skip here
            pass
    return paths
