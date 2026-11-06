"""Streaming shared SARIF context preserves legacy selection identities."""

import copy
import hashlib
import json

import pytest

from core.sarif import parser
from packages.codeql import finding_selection as selection


def legacy_key(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8", errors="surrogateescape")).hexdigest()


@pytest.mark.parametrize("value", [
    {}, {"text": "café / 中文 / \ud800"},
    {"values": [None, True, False, 2**100, -0.0, 1e200]},
    {"values": [float("nan"), float("inf"), float("-inf")]},
    {"z": [{"b": 2, "a": 1}], "a": {"path": "a\\b.c", "message": "line\ntext"}},
])
@pytest.mark.parametrize("stream", [False, True])
def test_content_keys_match_legacy_bytes(value, stream):
    before = copy.deepcopy(value)
    assert selection._content_key(value, stream=stream) == legacy_key(value)
    # Compare encodings because NaN is deliberately not equal to itself.
    assert json.dumps(value, sort_keys=True) == json.dumps(before, sort_keys=True)


def test_selection_streams_shared_context_once_and_keeps_result_hashes_fast(tmp_path, monkeypatch):
    rule = {"id": "sample", "defaultConfiguration": {"level": "warning"}}
    def result(line):
        return {"ruleId": "sample", "ruleIndex": 0, "message": {"text": "candidate"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.c"},
                "region": {"startLine": line}}}]}
    first, second = result(1), result(2)
    run = {"tool": {"driver": {"name": "CodeQL", "rules": [rule]}},
           "artifacts": [{"location": {"uri": "app.c"}}],
           "context_marker": "shared", "results": [first, second, copy.deepcopy(first)]}
    monkeypatch.setattr(selection, "load_sarif", lambda path: {"runs": [run]})
    original = selection._sarif_content_identity
    observed = []

    def identity(value, *, stream=False):
        observed.append((value, stream))
        return original(value, stream=stream)

    monkeypatch.setattr(selection, "_sarif_content_identity", identity)
    selected, count, duplicates = selection.select_findings_for_analysis([tmp_path / "report.sarif"], 2)
    assert (len(selected), count, duplicates) == (2, 3, 1)
    streamed = [value for value, stream in observed if stream]
    assert len(streamed) == 3  # Component identity, source tables and ranking context.
    assert sum("tables" in value for value in streamed) == 1
    assert sum("context_marker" in value for value in streamed) == 1
    assert all(not stream for value, stream in observed if value is first or value is second)
    assert any(value is first for value, _ in observed)


def test_partial_stream_failure_uses_a_complete_legacy_identity(monkeypatch):
    value = {"tables": {"artifacts": [{"location": {"uri": "app.c"}}]}}

    def incomplete(data):
        yield b'{"partial-prefix":'
        raise RecursionError("iterator depth limit")

    monkeypatch.setattr(parser, "iterencode_canonical", incomplete)
    assert selection._content_key(value, stream=True) == legacy_key(value)


def test_small_result_hashes_do_not_enter_streaming_encoder(monkeypatch):
    def unexpected(data):
        pytest.fail("small result entered the streaming encoder")

    monkeypatch.setattr(parser, "iterencode_canonical", unexpected)
    value = {"ruleId": "small", "message": {"text": "candidate"}}
    assert selection._content_key(value) == legacy_key(value)
