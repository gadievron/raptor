"""ASVS V13 -- API and web service security checks."""

from __future__ import annotations

import json
from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession


@registry.register(CheckCategory.API, "V13.1.1", "GraphQL introspection enabled in production")
class GraphQLIntrospectionCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Use discovery data if available, else probe known paths
        graphql_urls = []
        if discovery and discovery.get("graphql_schema"):
            return [self._result(
                passed=False, url=target_url,
                evidence="GraphQL introspection schema obtained via discovery phase",
                detail=(
                    "GraphQL introspection is enabled. This allows any client to enumerate the "
                    "complete API schema including all types, queries, mutations, and fields. "
                    "Attackers use this to identify undocumented endpoints and attack surface."
                ),
                recommendation=(
                    "Disable introspection in production. In Apollo Server: "
                    "'introspection: false'. In graphene-django: set GRAPHENE['INTROSPECTION'] = False. "
                    "Consider allowing introspection only for authenticated staff users."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V13.1.1",
            )]

        for path in ["/graphql", "/graphql/", "/api/graphql"]:
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
                            return [self._result(
                                passed=False, url=target_url.rstrip("/") + path,
                                evidence=f"Introspection query returned {len(str(data))} bytes of schema data",
                                detail=(
                                    "GraphQL introspection is enabled. An attacker can enumerate "
                                    "the full API schema including all queries, mutations, and types."
                                ),
                                recommendation=(
                                    "Disable introspection in production environments."
                                ),
                                severity="medium", asvs_ref="ASVS 5.0 V13.1.1",
                            )]
                    except Exception:
                        pass
            except Exception:
                continue
        return []


@registry.register(CheckCategory.API, "V13.2.1", "OpenAPI / Swagger spec publicly accessible")
class SwaggerExposureCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        if discovery and discovery.get("openapi_spec"):
            spec = discovery["openapi_spec"]
            paths_count = len(spec.get("paths", {}))
            return [self._result(
                passed=False, url=target_url,
                evidence=f"OpenAPI spec accessible -- {paths_count} paths documented",
                detail=(
                    "The OpenAPI/Swagger specification is publicly accessible. This provides "
                    "attackers with a complete map of the API: all endpoints, HTTP methods, "
                    "parameters, and response schemas, dramatically reducing reconnaissance effort."
                ),
                recommendation=(
                    "Restrict access to API documentation to authenticated users or internal "
                    "networks only. Do not expose the raw spec to anonymous users in production."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V13.2.1",
            )]

        spec_paths = [
            "/swagger.json", "/openapi.json", "/swagger-ui.html",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
        ]
        for path in spec_paths:
            try:
                resp = client.get(path)
                if resp.status_code == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct or path.endswith(".json"):
                        try:
                            data = resp.json()
                            if "paths" in data or "swagger" in data or "openapi" in data:
                                paths_count = len(data.get("paths", {}))
                                return [self._result(
                                    passed=False,
                                    url=target_url.rstrip("/") + path,
                                    evidence=f"OpenAPI spec at {path} ({paths_count} paths)",
                                    detail=(
                                        "OpenAPI/Swagger spec is publicly exposed. Attackers can "
                                        "use it to enumerate all API endpoints and parameters."
                                    ),
                                    recommendation=(
                                        "Restrict API documentation to authenticated/internal access in production."
                                    ),
                                    severity="medium", asvs_ref="ASVS 5.0 V13.2.1",
                                )]
                        except Exception:
                            pass
                    elif "html" in ct:
                        if "swagger" in resp.text.lower() or "redoc" in resp.text.lower():
                            return [self._result(
                                passed=False,
                                url=target_url.rstrip("/") + path,
                                evidence=f"Swagger UI accessible at {path}",
                                detail="Swagger UI is publicly accessible.",
                                recommendation="Restrict API documentation to authenticated access.",
                                severity="low", asvs_ref="ASVS 5.0 V13.2.1",
                            )]
            except Exception:
                continue
        return []


@registry.register(CheckCategory.API, "V13.2.5", "API returns verbose error details")
class ApiVerboseErrorCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        import re
        api_paths = ["/api", "/api/v1", "/api/v2"]
        if discovery:
            for url in discovery.get("apis", []):
                from urllib.parse import urlparse
                api_paths.insert(0, urlparse(url.get("url", "")).path)

        for path in api_paths[:5]:
            try:
                # Send malformed JSON to trigger an error
                resp = client.post(
                    path,
                    data="{{invalid_json",
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text
                has_trace = any(
                    p.search(body) for p in [
                        re.compile(r"Traceback", re.I),
                        re.compile(r"at com\.|at org\.|at sun\."),
                        re.compile(r"NullPointerException|IndexOutOfBoundsException"),
                        re.compile(r"stack.*:.*\[", re.I),
                    ]
                )
                if has_trace:
                    return [self._result(
                        passed=False, url=target_url.rstrip("/") + path,
                        evidence=f"Error response from malformed JSON POST: {body[:400]}",
                        detail=(
                            "The API endpoint returns detailed error information including stack "
                            "traces when it receives malformed input. This aids exploit development."
                        ),
                        recommendation=(
                            "Return generic error responses in production. Log detailed errors "
                            "server-side with a correlation ID returned to the client."
                        ),
                        severity="medium", asvs_ref="ASVS 5.0 V13.2.5",
                    )]
            except Exception:
                continue
        return []


@registry.register(CheckCategory.API, "V13.3.1", "Mass assignment via JSON body",
                   requires_auth=True)
class MassAssignmentCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        if not session:
            return []

        # Look for profile update or similar endpoints in discovery
        candidates = []
        if discovery:
            for url in discovery.get("urls", []):
                from urllib.parse import urlparse
                path = urlparse(url).path.lower()
                if any(kw in path for kw in ("profile", "account", "user", "settings", "me")):
                    candidates.append(urlparse(url).path)

        if not candidates:
            candidates = ["/api/user", "/api/me", "/api/profile", "/api/v1/user"]

        for path in candidates[:3]:
            try:
                resp = client.post(
                    path,
                    json_data={"is_admin": True, "role": "admin", "verified": True},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if data.get("is_admin") is True or data.get("role") == "admin":
                            return [self._result(
                                passed=False, url=target_url.rstrip("/") + path,
                                evidence=(
                                    f"POST {path} with {{is_admin: true, role: admin}} "
                                    f"returned: {json.dumps(data)[:300]}"
                                ),
                                detail=(
                                    "The endpoint appears to accept and persist attacker-supplied "
                                    "privileged fields (is_admin, role). Mass assignment allows "
                                    "privilege escalation by manipulating request body fields."
                                ),
                                recommendation=(
                                    "Use an allowlist of fields that are permitted to be set via "
                                    "the API. Never bind request body fields directly to model "
                                    "attributes without explicit field selection."
                                ),
                                severity="critical", asvs_ref="ASVS 5.0 V13.3.1",
                            )]
                    except Exception:
                        pass
            except Exception:
                continue
        return []
