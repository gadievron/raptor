"""robots.txt parser -- collects Disallow paths as candidate URLs."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)


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
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/" and not path.startswith("#"):
                # Strip wildcards -- keep the base path
                path = path.split("*")[0].rstrip("?")
                if path and path not in paths:
                    paths.append(path)
        elif line.lower().startswith("sitemap:"):
            # Handled by sitemap.py, skip here
            pass
    return paths
