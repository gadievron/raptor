"""Preserve peer rules and checklist order while bounding discarded work."""

import pytest

from core.audit import spec_inference as specs


def test_peer_cap_keeps_first_five_in_file_item_order(monkeypatch):
    checklist = {"files": [
        {"path": "b.c", "items": [{"name": f"parse_v{i}", "line_start": i}
                                   for i in range(1, 5)]},
        {"path": "a.c", "functions": [{"name": f"parse_v{i}", "line_start": i}
                                       for i in range(5, 100)]},
    ]}
    original = specs._is_peer
    calls = []

    def counted(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(specs, "_is_peer", counted)
    assert specs.find_peer_functions("parse_v0", checklist) == [
        {"name": f"parse_v{i}", "file": "b.c" if i < 5 else "a.c", "line": i}
        for i in range(1, 6)]
    assert len(calls) == 5


@pytest.mark.parametrize(("original", "candidate"), [
    ("abc_new", "abc_v2"),
    ("abc_new\n", "abc_v2\n"),
    ("parse_v1", "parse_v٢"),
    ("validate_email", "validate_phone"),
], ids=["short-base", "final-newline", "unicode-digits", "shared-prefix"])
def test_peer_rules_keep_normalization_and_prefix_alternatives(original, candidate):
    assert specs._is_peer(specs._extract_base_name(original), original, candidate)


def test_unrelated_native_candidate_skips_base_normalization(monkeypatch):
    calls = []
    normalize = specs._extract_base_name

    def counted(name):
        calls.append(name)
        return normalize(name)

    monkeypatch.setattr(specs, "_extract_base_name", counted)
    assert not specs._is_peer("parse", "parse_v1", "handle_request_v2")
    assert calls == []
    assert specs._is_peer("parse", "parse_v1", "parse_v2")
    assert calls == ["parse_v2"]
