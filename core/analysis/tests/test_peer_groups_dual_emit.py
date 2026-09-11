"""Dual-emit JOERN_PEERS record parsing tests for
:mod:`core.analysis.peer_groups`."""
from __future__ import annotations

import json

from core.analysis.peer_groups import _CO_CALLEE_QUERY, _parse_joern_peers


def _record(caller: str, file: str, callees: list) -> str:
    return "JOERN_PEERS:" + json.dumps(
        {"caller": caller, "file": file, "callees": callees},
    )


def test_json_records_parse_from_println_transport():
    raw = (
        _record("dispatch", "src/main.c",
                ["handle_get", "handle_post", "handle_delete"]) + "\n"
        + _record("router", "src/route.c", ["route_api", "route_static"])
        + "\n"
    )
    result = _parse_joern_peers(raw)
    assert result == [
        ("dispatch", "src/main.c",
         ["handle_get", "handle_post", "handle_delete"]),
        ("router", "src/route.c", ["route_api", "route_static"]),
    ]


def test_json_records_recovered_from_server_value_echo():
    # The server transport drops println output; records ride the
    # final expression's Java-escaped value echo.
    record = _record("dispatch", "src/main.c", ["handle_get", "handle_post"])
    echoed = 'val res0: String = "' + record.replace('"', '\\"') + '"'
    result = _parse_joern_peers(echoed + "\n")
    assert result == [
        ("dispatch", "src/main.c", ["handle_get", "handle_post"]),
    ]


def test_hostile_delimiters_in_names_survive_json_records():
    # The old pipe/comma wire format let a scanned-repo name carrying
    # ``|`` or ``,`` forge or destroy records; JSON records carry them
    # verbatim.
    raw = _record("weird|name", "a,b.c", ["x|y", "p,q"]) + "\n"
    result = _parse_joern_peers(raw)
    assert result == [("weird|name", "a,b.c", ["x|y", "p,q"])]


def test_legacy_pipe_format_still_parses():
    raw = "JOERN_PEERS:dispatch|src/main.c|handle_get,handle_post\n"
    result = _parse_joern_peers(raw)
    assert result == [
        ("dispatch", "src/main.c", ["handle_get", "handle_post"]),
    ]


def test_fewer_than_two_callees_dropped_in_both_formats():
    assert _parse_joern_peers(_record("m", "m.c", ["only_one"])) == []
    assert _parse_joern_peers("JOERN_PEERS:m|m.c|only_one\n") == []


def test_query_is_dual_emit_with_escaping():
    # The query must println each record AND return them as the final
    # expression (the server transport carries only the latter), and
    # must escape interpolated repo-derived names.
    assert "foreach(println)" in _CO_CALLEE_QUERY
    assert _CO_CALLEE_QUERY.rstrip().endswith('peerLines.mkString("\\n")')
    assert "jsonEsc" in _CO_CALLEE_QUERY


def test_embedded_json_esc_matches_canonical_definition():
    import pytest

    runner = pytest.importorskip("packages.joern.runner")
    esc_lines = [
        line for line in _CO_CALLEE_QUERY.splitlines()
        if line.startswith("def jsonEsc")
    ]
    assert esc_lines == [runner.SCALA_JSON_ESC_DEF]
