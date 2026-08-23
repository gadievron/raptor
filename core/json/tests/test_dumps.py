"""Tests for the string-level dumpers: ``dumps_canonical`` / ``dumps_display``.

``dumps_canonical`` is the frozen canonical byte form for MAC / hash /
content-address call sites — the tests here pin its bytes against the
reference form (``json.dumps(..., sort_keys=True, separators=(",", ":"),
default=str)``) and cross-check it against the review-journal MAC
canonicalisation in ``core.coverage.journal_mac`` (the frozen contract
it must byte-match forever).

``dumps_display`` is the human/LLM-facing renderer — its bytes are NOT
contractual, so the tests assert behaviour (round-trip fidelity,
readable UTF-8, totality on awkward inputs) rather than exact output,
and exercise both the orjson and stdlib branches where possible.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

import core.json.utils as utils
from core.json.utils import dumps_canonical, dumps_display

# Representative payload shapes drawn from the real canonical lanes:
# journal rows (verdict/spans/producer), scorecard sidecar payloads,
# evidence-id payloads. Unicode, nesting, numeric edge values, empty
# containers, and key-order scrambling are all covered.
CANONICAL_FIXTURES = [
    {},
    {"a": 1},
    {"b": 2, "a": 1, "_z": None},
    {"verdict": "confirmed", "source_hash": "ab" * 32,
     "spans": [[10, 42], [50, 61]], "producer": "audit",
     "model": "x-1", "strategies": ["taint", "smt"],
     "body": "café ☕ — naïve\n\ttab"},
    {"nested": {"deep": {"er": [1, 2.5, -0.0, 1e20, True, False, None]}}},
    {"empty_list": [], "empty_dict": {}, "zero": 0, "neg": -17},
    {"unicode_key_é": "value", "ascii": "\u0000\u001f control"},
    {"float_repr": [0.1 + 0.2, 3.0, 1e-9]},
]


class TestDumpsCanonical:
    def test_byte_equality_with_reference_form(self) -> None:
        """dumps_canonical == the pinned stdlib reference form, byte for
        byte, on every representative payload."""
        for payload in CANONICAL_FIXTURES:
            expected = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), default=str,
            )
            assert dumps_canonical(payload) == expected

    def test_byte_equality_with_journal_mac_canonical_form(self) -> None:
        """sha256(dumps_canonical(scrubbed row)) must equal
        journal_mac.row_sha256(row) — the review-journal MAC contract
        dumps_canonical exists to reproduce."""
        journal_mac = pytest.importorskip("core.coverage.journal_mac")
        for payload in CANONICAL_FIXTURES:
            row = dict(payload)
            row[journal_mac.TOKEN_KEY] = "deadbeef"  # popped by both sides
            scrubbed = {k: v for k, v in row.items()
                        if k != journal_mac.TOKEN_KEY}
            ours = hashlib.sha256(
                dumps_canonical(scrubbed).encode("utf-8")).hexdigest()
            assert ours == journal_mac.row_sha256(row)

    def test_key_order_never_varies(self) -> None:
        a = dumps_canonical({"x": 1, "a": 2, "m": 3})
        b = dumps_canonical({"m": 3, "x": 1, "a": 2})
        assert a == b == '{"a":2,"m":3,"x":1}'

    def test_compact_separators(self) -> None:
        assert dumps_canonical({"a": [1, 2], "b": 3}) == '{"a":[1,2],"b":3}'

    def test_non_ascii_is_escaped(self) -> None:
        """ensure_ascii default: canonical bytes stay pure ASCII (this is
        exactly where orjson would silently fork the byte stream)."""
        out = dumps_canonical({"k": "café"})
        assert out == '{"k":"caf\\u00e9"}'
        assert out.encode("ascii")  # must not raise

    def test_default_str_stringifies_objects(self) -> None:
        out = dumps_canonical({
            "p": Path("/tmp/x"),
            "d": datetime(2026, 8, 23, 12, 0, 0),
        })
        assert out == (
            '{"d":"2026-08-23 12:00:00","p":"/tmp/x"}'
        )

    def test_nan_token_behaviour_is_frozen(self) -> None:
        """stdlib allow_nan default is part of the frozen byte contract:
        journal-MAC rows minted over non-finite floats must keep
        verifying. Pin the token so a future 'tidy-up' to
        allow_nan=False fails here instead of in the field."""
        assert dumps_canonical({"x": float("nan")}) == '{"x":NaN}'
        assert dumps_canonical({"x": float("inf")}) == '{"x":Infinity}'

    def test_never_uses_orjson(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A poisoned orjson stub proves the canonical path never
        consults it, installed or not."""

        class _Poison:
            def __getattr__(self, name: str) -> None:
                raise AssertionError(
                    "dumps_canonical must never touch orjson")

        monkeypatch.setattr(utils, "_orjson", _Poison())
        assert dumps_canonical({"b": 1, "a": "é"}) == '{"a":"\\u00e9","b":1}'

    def test_int_keys_coerce_like_stdlib(self) -> None:
        assert dumps_canonical({1: "a"}) == '{"1":"a"}'

    def test_big_ints_serialise(self) -> None:
        assert dumps_canonical({"n": 2**70}) == '{"n":%d}' % (2**70)


class TestDumpsDisplay:
    ROUND_TRIP_FIXTURES = [
        {"a": 1, "b": [1, 2, {"c": None, "d": True}]},
        {"unicode": "café ☕", "s": "line\nbreak"},
        [],
        {"nested": {"x": [1.5, -2, "три"]}},
    ]

    def test_round_trip(self) -> None:
        for payload in self.ROUND_TRIP_FIXTURES:
            assert json.loads(dumps_display(payload)) == payload
            assert json.loads(dumps_display(payload, indent=None)) == payload

    def test_returns_str_and_pretty_by_default(self) -> None:
        out = dumps_display({"a": {"b": 1}})
        assert isinstance(out, str)
        assert "\n" in out  # indent=2 default

    def test_compact_mode_single_line(self) -> None:
        assert "\n" not in dumps_display({"a": {"b": [1, 2]}}, indent=None)

    def test_readable_utf8(self) -> None:
        """Display strings show raw UTF-8, not \\uXXXX escapes — on both
        encoder branches (orjson always, stdlib via ensure_ascii=False)."""
        assert "café" in dumps_display({"k": "café"})
        assert "café" in dumps_display({"k": "café"}, indent=None)

    def test_sort_keys(self) -> None:
        out = dumps_display({"z": 1, "a": 2}, indent=None, sort_keys=True)
        assert out.index('"a"') < out.index('"z"')

    def test_path_and_datetime_stringify(self) -> None:
        parsed = json.loads(dumps_display({
            "p": Path("/tmp/x"), "d": datetime(2026, 1, 2, 3, 4, 5),
        }))
        assert parsed["p"] == "/tmp/x"
        assert "2026" in parsed["d"]

    def test_total_on_big_ints(self) -> None:
        """>64-bit ints are an orjson TypeError — the helper must fall
        back to stdlib rather than surface it to a display caller."""
        assert json.loads(dumps_display({"n": 2**70}))["n"] == 2**70

    def test_int_keys(self) -> None:
        assert json.loads(dumps_display({1: "a"}, indent=None)) == {"1": "a"}

    def test_stdlib_branch_when_orjson_absent(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(utils, "_orjson", None)
        payload = {"unicode": "café", "n": [1, 2]}
        assert json.loads(dumps_display(payload)) == payload
        assert "café" in dumps_display(payload)

    def test_orjson_branch_when_installed(self) -> None:
        orjson = pytest.importorskip("orjson")
        assert orjson is not None
        # Same observable contract on the fast path.
        payload = {"unicode": "café", "n": [1, 2]}
        assert json.loads(dumps_display(payload)) == payload
        assert "café" in dumps_display(payload)

    def test_non_default_indent_takes_stdlib_branch(self) -> None:
        out = dumps_display({"a": 1}, indent=4)
        assert json.loads(out) == {"a": 1}
        assert '    "a"' in out

    def test_non_finite_floats_do_not_raise(self) -> None:
        """Display must be total: NaN renders as either the stdlib token
        or orjson's null, but never raises."""
        out = dumps_display({"x": float("nan")}, indent=None)
        assert ("NaN" in out) or ("null" in out)
