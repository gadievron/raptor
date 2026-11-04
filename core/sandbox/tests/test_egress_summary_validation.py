"""Invalid proxy records must not erase intact egress evidence."""

import json

import pytest

from core.sandbox import egress_summary as summary


def good(**fields):
    return {
        "host": "example.test", "port": 443, "result": "allowed",
        "bytes_u2c": 20, "bytes_c2u": 10, **fields,
    }


def write_events(tmp_path, events):
    (tmp_path / "proxy-events.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("field,value", [
    ("result", []), ("result", {}), ("result", 42), ("result", None),
    ("result", ""), ("result", True),
    ("host", []), ("host", {}), ("host", 42), ("host", True),
    ("port", []), ("port", {}), ("port", "443"), ("port", True),
    ("bytes_u2c", "20"), ("bytes_u2c", []), ("bytes_u2c", {}),
    ("bytes_u2c", -1), ("bytes_u2c", True), ("bytes_u2c", 1.5),
    ("bytes_c2u", -1), ("bytes_c2u", False), ("bytes_c2u", "10"),
    ("bytes_c2u", float("nan")), ("bytes_c2u", float("inf")),
])
def test_malformed_record_does_not_hide_valid_neighbors(tmp_path, field, value):
    write_events(tmp_path, [good(), good(**{field: value}), good(result="denied_host")])
    result = summary.finalize_egress_summary(tmp_path)
    assert result is not None
    assert result["total_connections"] == 2
    assert result["allowed"] == 1
    assert result["denied"] == 1
    assert result["total_bytes_in"] == 40
    assert result["total_bytes_out"] == 20
    saved = json.loads((tmp_path / summary.EGRESS_SUMMARY_FILE).read_text())
    assert saved == result


def test_only_malformed_records_produce_no_summary(tmp_path):
    write_events(tmp_path, [{}, good(host=[]), good(bytes_c2u=-5)])
    assert summary.finalize_egress_summary(tmp_path) is None
    assert not (tmp_path / summary.EGRESS_SUMMARY_FILE).exists()


def test_nullable_fields_and_refused_port_diagnostics_are_retained(tmp_path):
    write_events(tmp_path, [
        good(host=None, port=None, bytes_u2c=None, bytes_c2u=None),
        good(port=-1, result="bad_request"),
        good(port=65536, result="bad_request"),
    ])
    result = summary.summarise_egress(tmp_path)
    assert result["total_connections"] == 3
    assert result["failed"] == 2
    assert {entry["port"] for entry in result["hosts"]} == {None, -1, 65536}
    assert result["total_bytes_in"] == 40


@pytest.mark.parametrize("host,port,other_host", [
    ("2001:db8::1", 443, "2001:db8::1:443"),
    ("example.test", 0, "example.test"),
])
def test_distinct_endpoints_cannot_collide(tmp_path, host, port, other_host):
    write_events(tmp_path, [
        good(host=host, port=port),
        good(host=other_host, port=None, result="bad_request"),
        good(host=host, port=port),
    ])
    result = summary.summarise_egress(tmp_path)
    assert result["total_connections"] == 3
    assert result["unique_hosts"] == len({host, other_host})
    endpoints = {(entry["host"], entry["port"]): entry for entry in result["hosts"]}
    assert len(endpoints) == 2
    assert endpoints[(host, port)]["allowed"] == 2
    assert endpoints[(other_host, None)]["failed"] == 1


def test_decoder_recursion_failure_does_not_end_reading(tmp_path, monkeypatch):
    write_events(tmp_path, [good(), good(), good()])
    real_loads = json.loads
    calls = []

    def decode(line):
        calls.append(line)
        if len(calls) == 2:
            raise RecursionError("excessive JSON nesting")
        return real_loads(line)

    monkeypatch.setattr(summary.json, "loads", decode)
    result = summary.summarise_egress(tmp_path)
    assert result["total_connections"] == 2
    assert len(calls) == 3


def test_unknown_string_result_remains_a_failed_connection(tmp_path):
    write_events(tmp_path, [good(result="future_failure")])
    result = summary.summarise_egress(tmp_path)
    assert result["total_connections"] == result["failed"] == 1
