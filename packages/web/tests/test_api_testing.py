"""Spec-driven API testing (no network)."""

from __future__ import annotations

from types import SimpleNamespace

from packages.web.api_testing import (
    GraphQLProbe,
    graphql_probes_from_schema,
    operations_from_openapi,
    run_graphql_probes,
)

_SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "/api/v1"}],
    "paths": {
        "/users/{user_id}/orders": {
            "get": {
                "parameters": [
                    {"name": "user_id", "in": "path",
                     "schema": {"type": "integer"}},
                    {"name": "status", "in": "query",
                     "schema": {"type": "string"}},
                ],
            },
        },
        "/orders": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "note": {"type": "string"},
                                    "quantity": {"type": "integer"},
                                    "shipping": {
                                        "type": "object",
                                        "properties": {
                                            "address": {"type": "string"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "/health": {"get": {}},
    },
}


def test_openapi_operations_typed_and_path_substituted():
    ops = operations_from_openapi(_SPEC, "https://example.test")

    by_url = {op.url: op for op in ops}
    get_op = by_url["https://example.test/api/v1/users/1/orders"]
    assert get_op.method == "GET"
    assert get_op.query_params == ["status"]

    post_op = by_url["https://example.test/api/v1/orders"]
    assert post_op.method == "POST"
    assert post_op.body_template == {
        "note": "raptor-baseline",
        "quantity": 1,
        "shipping": {"address": "raptor-baseline"},
    }
    assert ("note",) in post_op.string_body_fields
    assert ("shipping", "address") in post_op.string_body_fields
    # Parameterless operations are not fuzz targets.
    assert not any(op.url.endswith("/health") for op in ops)


def test_graphql_probes_from_full_introspection():
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {"name": "user", "args": [
                                {"name": "name",
                                 "type": {"name": None,
                                          "ofType": {"name": "String"}}},
                            ]},
                            {"name": "version", "args": []},
                        ],
                    },
                ],
            },
        },
    }

    probes = graphql_probes_from_schema(schema)

    assert len(probes) == 1
    assert probes[0].field_name == "user"
    assert probes[0].arg_name == "name"
    query = probes[0].query("' OR 1=1--")
    assert query["query"] == 'query { user(name: "\' OR 1=1--") }'


def test_graphql_probe_runner_uses_three_gate_oracle():
    from packages.web.client import WebClient
    from packages.web.fuzzer import WebFuzzer

    client = WebClient("https://example.test")
    responses = iter([
        SimpleNamespace(status_code=200, text="ok", content=b"ok"),
        SimpleNamespace(
            status_code=500,
            text="You have an error in your SQL syntax near name",
            content=b"x" * 50,
        ),
    ])
    client.post = lambda url, json_data=None, **kw: next(responses)
    fuzzer = WebFuzzer(client)

    findings = run_graphql_probes(
        fuzzer, "/graphql", [GraphQLProbe("user", "name")],
    )

    assert findings, "expected a confirmed graphql injection"
    assert findings[0]["attack_vector"] == "graphql_argument"
    assert findings[0]["parameter"] == "user.name"
    assert findings[0]["oracle_signal"].startswith("sqli_error:")


def test_json_field_fuzzing_three_gate(tmp_path):
    from packages.web.client import WebClient
    from packages.web.fuzzer import WebFuzzer

    client = WebClient("https://example.test")
    bodies = []

    def post(url, data=None, json_data=None, **kw):
        bodies.append(json_data)
        if json_data and "raptor-baseline" not in str(json_data.get("note", "")):
            return SimpleNamespace(
                status_code=500,
                text="unclosed quotation mark after the character string",
                content=b"e" * 60,
            )
        return SimpleNamespace(status_code=200, text="created", content=b"created")

    client.post = post
    fuzzer = WebFuzzer(client)

    findings = fuzzer.fuzz_json_field(
        "https://example.test/api/orders",
        {"note": "x", "quantity": 1},
        ("note",),
        vulnerability_types=["sqli"],
    )

    assert len(findings) == 1
    assert findings[0]["attack_vector"] == "json_body"
    assert findings[0]["parameter"] == "note"
    # Baseline body used the typed benign value, not the payload.
    assert any(
        body and body.get("note") == "raptor-baseline" for body in bodies
    )
