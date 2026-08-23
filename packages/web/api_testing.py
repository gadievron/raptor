"""Spec-driven API testing from collected OpenAPI and GraphQL schemas.

Discovery already captures OpenAPI documents and GraphQL introspection
schemas; this module turns them into PRECISION test surface instead of
letting them rot in the artifact:

* OpenAPI operations become typed fuzz targets — parameters are tested
  at their documented locations (query vs JSON body) with schema-typed
  baseline values, instead of being guessed at from crawled URLs;
* GraphQL query fields with string arguments become injection probes
  through the same three-gate oracle.

Everything runs through the scan's fuzzer and client, so scope, rate
limiting, the execution policy, and the baseline/attack/diff oracle
apply unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from core.logging import get_logger

logger = get_logger()

# Baseline value per OpenAPI schema type for body construction.
_TYPE_BASELINES: dict[str, Any] = {
    "string": "raptor-baseline",
    "integer": 1,
    "number": 1,
    "boolean": True,
    "array": [],
    "object": {},
}

_FUZZABLE_METHODS = {"get", "post"}


@dataclass
class ApiOperation:
    """One testable operation derived from an OpenAPI document."""

    method: str
    url: str
    query_params: list[str] = field(default_factory=list)
    body_template: dict[str, Any] | None = None
    string_body_fields: list[tuple[str, ...]] = field(default_factory=list)


def operations_from_openapi(spec: dict, base_url: str) -> list[ApiOperation]:
    """Typed operations from an OpenAPI 3.x (or Swagger 2) document.

    Path parameters are substituted with benign typed values — fuzzing
    path segments produces routing noise, not injection signal. Query
    parameters and string-typed JSON body fields are the fuzz surface.
    """
    operations: list[ApiOperation] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return operations
    server_prefix = _server_prefix(spec)

    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        shared_params = methods.get("parameters") or []
        for method, op in methods.items():
            if method.lower() not in _FUZZABLE_METHODS or not isinstance(op, dict):
                continue
            params = list(shared_params) + list(op.get("parameters") or [])
            path = str(raw_path)
            query_params: list[str] = []
            for param in params:
                if not isinstance(param, dict):
                    continue
                name = str(param.get("name") or "")
                where = param.get("in")
                if not name:
                    continue
                if where == "query":
                    query_params.append(name)
                elif where == "path":
                    schema_type = str(
                        (param.get("schema") or {}).get("type")
                        or param.get("type") or "string"
                    )
                    benign = _TYPE_BASELINES.get(schema_type, "raptor-baseline")
                    path = path.replace("{" + name + "}", str(benign))
            body_template, string_fields = _body_from_operation(op)
            if not query_params and not string_fields:
                continue
            operations.append(ApiOperation(
                method=method.upper(),
                url=urljoin(base_url.rstrip("/") + "/", (server_prefix + path).lstrip("/")),
                query_params=query_params,
                body_template=body_template,
                string_body_fields=string_fields,
            ))
    return operations


def _server_prefix(spec: dict) -> str:
    """Relative server path prefix (absolute servers stay origin-pinned:
    the scan client rejects off-origin URLs regardless)."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = str((servers[0] or {}).get("url") or "")
        if url.startswith("/"):
            return url.rstrip("/")
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path.startswith("/"):
        return base_path.rstrip("/")
    return ""


def _body_from_operation(
    op: dict,
) -> tuple[dict[str, Any] | None, list[tuple[str, ...]]]:
    """Minimal typed JSON body + the paths of its string fields."""
    content = (
        (op.get("requestBody") or {}).get("content") or {}
    )
    media = content.get("application/json")
    if not isinstance(media, dict):
        return None, []
    schema = media.get("schema")
    if not isinstance(schema, dict):
        return None, []
    template: dict[str, Any] = {}
    string_fields: list[tuple[str, ...]] = []
    _fill_body(schema, (), template, string_fields, depth=0)
    return (template or None), string_fields


def _fill_body(
    schema: dict,
    prefix: tuple[str, ...],
    out: dict,
    string_fields: list[tuple[str, ...]],
    depth: int,
) -> None:
    if depth > 3 or schema.get("type") not in (None, "object"):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    node = out
    for key in prefix:
        node = node.setdefault(key, {})
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        prop_type = prop.get("type", "string")
        if prop_type == "object":
            _fill_body(prop, (*prefix, str(name)), out, string_fields, depth + 1)
            continue
        node[str(name)] = _TYPE_BASELINES.get(str(prop_type), "raptor-baseline")
        if prop_type == "string":
            string_fields.append((*prefix, str(name)))


# Classes whose response markers are static error signatures, safe to
# match at ffuf scale without a baseline leg. ssti's arithmetic marker
# and xss's reflection signal are deliberately absent — both need the
# baseline/containment legs only the in-Python oracle has, so at the
# sweep layer they would be pure noise. Flags reproduce each Python
# pattern's compile flags as Go/RE2 inline groups.
_SWEEP_MARKER_FLAGS: dict[str, str] = {
    "sqli": "i",
    "command_injection": "im",
    "path_traversal": "ims",
}


def sweep_match_regex() -> str:
    """One Go-regexp alternation of the static error-signature markers.

    Built from ``markers.MARKER_RES`` so the ffuf pre-filter and the
    verification oracle can never drift apart on what counts as a
    signal; the marker patterns use only RE2-compatible syntax (no
    lookarounds, no backreferences).
    """
    from packages.web.markers import MARKER_RES

    return "|".join(
        f"(?{flags}:{MARKER_RES[name].pattern})"
        for name, flags in _SWEEP_MARKER_FLAGS.items()
    )


_RAW_REQUEST_TOKEN = "__RAPTOR_SWEEP_POSITION__"


def build_raw_request(
    op: ApiOperation,
    base_url: str,
    field_path: tuple[str, ...],
    keyword: str = "FUZZ",
) -> str | None:
    """A raw HTTP request file body fuzzing one JSON string field.

    The keyword is spliced into the JSON-encoded body as the field's
    string value, which is exactly the position ``-u``/``-d`` cannot
    express for nested fields. Query parameters ride along with benign
    values so operations that require them do not 400 every probe.
    The output satisfies the engine's strict scope parser: path-only
    request line, exactly one ``Host`` header, blank-line-terminated
    header section. Content-Length is omitted deliberately — ffuf
    recomputes it per substituted payload.

    Returns None for operations without a JSON body template (nothing
    to splice into).
    """
    from urllib.parse import urlencode, urlparse

    import json

    if not op.body_template or not field_path:
        return None
    parsed = urlparse(op.url)
    base = urlparse(base_url)
    if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc):
        return None
    path = parsed.path or "/"
    if op.query_params:
        path += "?" + urlencode({name: "1" for name in op.query_params})

    body_obj = json.loads(json.dumps(op.body_template))
    node: Any = body_obj
    for key in field_path[:-1]:
        node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return None
    if not isinstance(node, dict) or field_path[-1] not in node:
        return None
    node[field_path[-1]] = _RAW_REQUEST_TOKEN
    body = json.dumps(body_obj).replace(_RAW_REQUEST_TOKEN, keyword)

    return (
        f"{op.method} {path} HTTP/1.1\n"
        f"Host: {base.netloc}\n"
        "Content-Type: application/json\n"
        "Accept: */*\n"
        "\n"
        f"{body}"
    )


@dataclass
class GraphQLProbe:
    """One string-argument query field worth injecting into."""

    field_name: str
    arg_name: str

    def query(self, value: str) -> dict[str, Any]:
        import json as _json
        return {
            "query": (
                f"query {{ {self.field_name}"
                f"({self.arg_name}: {_json.dumps(value)}) }}"
            ),
        }


def graphql_probes_from_schema(schema: dict, cap: int = 10) -> list[GraphQLProbe]:
    """String-argument query fields from an introspection result."""
    data = schema.get("data") if isinstance(schema.get("data"), dict) else schema
    root = (
        ((data or {}).get("__schema") or {}) if isinstance(data, dict) else {}
    )
    query_type_name = ((root.get("queryType") or {}) or {}).get("name")
    types = root.get("types") or []
    probes: list[GraphQLProbe] = []
    for gql_type in types:
        if not isinstance(gql_type, dict) or gql_type.get("name") != query_type_name:
            continue
        for gql_field in gql_type.get("fields") or []:
            if not isinstance(gql_field, dict):
                continue
            for arg in gql_field.get("args") or []:
                arg_type = arg.get("type") or {}
                named = arg_type.get("name") or (
                    (arg_type.get("ofType") or {}).get("name")
                )
                if named == "String":
                    probes.append(GraphQLProbe(
                        field_name=str(gql_field.get("name")),
                        arg_name=str(arg.get("name")),
                    ))
                    break
            if len(probes) >= cap:
                return probes
    return probes


def run_graphql_probes(
    fuzzer: Any,
    graphql_url: str,
    probes: list[GraphQLProbe],
) -> list[dict[str, Any]]:
    """Inject through GraphQL string arguments via the three-gate oracle.

    Reuses the fuzzer's payload generation, class-signal analysis, and
    baseline-containment veto; requests go through the scan client.
    """
    findings: list[dict[str, Any]] = []
    for probe in probes:
        for vuln_type in ("sqli", "ssti", "command_injection"):
            payloads = fuzzer._generate_payloads(
                probe.arg_name, "graphql", vuln_type,
            )
            for payload in payloads:
                try:
                    baseline = fuzzer.client.post(
                        graphql_url,
                        json_data=probe.query(fuzzer._baseline_value(probe.arg_name)),
                    )
                    response = fuzzer.client.post(
                        graphql_url, json_data=probe.query(payload),
                    )
                except Exception:
                    logger.debug("graphql probe failed", exc_info=True)
                    break
                confirmation = fuzzer._analyze_response(response, payload, vuln_type)
                if confirmation and fuzzer._passes_three_gate_oracle(
                    baseline, response, confirmation,
                ):
                    findings.append({
                        "url": graphql_url,
                        "parameter": f"{probe.field_name}.{probe.arg_name}",
                        "payload": payload,
                        "vulnerability_type": vuln_type,
                        "method": "POST",
                        "attack_vector": "graphql_argument",
                        "status_code": response.status_code,
                        "response_length": len(response.content),
                        "confirmed": True,
                        "response_evidence": confirmation["snippet"],
                        "attack_evidence": confirmation["snippet"],
                        "baseline_evidence": fuzzer._response_summary(baseline),
                        "diff_summary": fuzzer._diff_summary(
                            baseline, response, confirmation["signal"],
                        ),
                        "oracle_signal": confirmation["signal"],
                    })
                    break
    return findings
