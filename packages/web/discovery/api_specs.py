"""Probe for GraphQL introspection and OpenAPI/Swagger spec exposure."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

_OPENAPI_PATHS = [
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs/",
    "/api/swagger.json", "/api/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/docs/api.json",
]

_GRAPHQL_PATHS = ["/graphql", "/graphql/", "/api/graphql", "/query"]

_INTROSPECTION_QUERY = (
    '{"query":"{__schema{types{name kind description}}}"}'
)


def probe_api_specs(client: "WebClient", base_url: str) -> Dict:
    """Probe for exposed API specs and GraphQL. Returns findings dict."""
    result: Dict = {
        "openapi_spec": None,
        "graphql_schema": None,
        "spec_urls": [],
    }

    # OpenAPI / Swagger
    for path in _OPENAPI_PATHS:
        try:
            resp = client.get(path)
            if resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct or path.endswith((".json", ".yaml")):
                    logger.info("OpenAPI spec found at %s", path)
                    result["spec_urls"].append(base_url.rstrip("/") + path)
                    if "json" in ct or path.endswith(".json"):
                        try:
                            result["openapi_spec"] = resp.json()
                        except Exception:
                            pass
                    break
        except Exception:
            continue

    # GraphQL introspection
    for path in _GRAPHQL_PATHS:
        try:
            resp = client.post(
                path,
                json_data={"query": "{__schema{types{name}}}"},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in str(data):
                        logger.info("GraphQL introspection enabled at %s", path)
                        result["graphql_schema"] = json.dumps(data, indent=2)[:4096]
                        result["spec_urls"].append(base_url.rstrip("/") + path)
                        break
                except Exception:
                    pass
        except Exception:
            continue

    return result
