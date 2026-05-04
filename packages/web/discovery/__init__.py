"""Web application discovery layer.

Runs before crawling to expand the attack surface with content that
a pure HTML link-follower would miss: robots.txt disallow paths,
sitemap URLs, common admin/config paths, JS-extracted routes,
API spec endpoints, and tech stack fingerprinting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """Aggregated output from the discovery phase."""

    urls: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    apis: List[dict] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    fingerprint: Dict[str, str] = field(default_factory=dict)
    openapi_spec: Optional[dict] = None
    graphql_schema: Optional[str] = None
    common_paths_found: List[str] = field(default_factory=list)
    robots_disallow: List[str] = field(default_factory=list)

    def stats(self) -> dict:
        return {
            "total_urls": len(self.urls),
            "total_forms": len(self.forms),
            "total_apis": len(self.apis),
            "total_parameters": len(self.parameters),
            "common_paths_found": len(self.common_paths_found),
            "fingerprint": self.fingerprint,
            "has_openapi": self.openapi_spec is not None,
            "has_graphql": self.graphql_schema is not None,
        }


class Discoverer:
    """Orchestrates all discovery sub-modules."""

    def __init__(self, client: "WebClient") -> None:
        self.client = client

    def discover(self, base_url: str) -> DiscoveryResult:
        from packages.web.discovery.robots import fetch_robots
        from packages.web.discovery.sitemap import fetch_sitemap
        from packages.web.discovery.common_paths import probe_common_paths
        from packages.web.discovery.fingerprint import fingerprint_target
        from packages.web.discovery.api_specs import probe_api_specs
        from packages.web.discovery.js_routes import extract_js_routes

        result = DiscoveryResult()
        seen: Set[str] = set()

        def _add_url(url: str) -> None:
            if url and url not in seen:
                seen.add(url)
                result.urls.append(url)

        logger.info("Discovery: fetching robots.txt")
        robots = fetch_robots(self.client, base_url)
        result.robots_disallow = robots
        for path in robots:
            _add_url(base_url.rstrip("/") + path)

        logger.info("Discovery: fetching sitemap")
        for url in fetch_sitemap(self.client, base_url):
            _add_url(url)

        logger.info("Discovery: probing common paths")
        found = probe_common_paths(self.client, base_url)
        result.common_paths_found = found
        for url in found:
            _add_url(url)

        logger.info("Discovery: fingerprinting tech stack")
        result.fingerprint = fingerprint_target(self.client, base_url)

        logger.info("Discovery: probing API specs and GraphQL")
        api_result = probe_api_specs(self.client, base_url)
        result.openapi_spec = api_result.get("openapi_spec")
        result.graphql_schema = api_result.get("graphql_schema")
        for url in api_result.get("spec_urls", []):
            _add_url(url)

        logger.info("Discovery: extracting JS routes")
        for url in extract_js_routes(self.client, base_url):
            _add_url(url)

        logger.info(
            "Discovery complete: %d URLs, %d common paths found",
            len(result.urls),
            len(result.common_paths_found),
        )
        return result
