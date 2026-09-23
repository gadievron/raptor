"""The x-source known-values set is bounded end to end.

``_MAX_KNOWN_VALUES`` used to be advisory: the JSON walk checked it
locally, but the non-JSON token fallback was uncapped, the per-run
union never trimmed, and no per-value length bound existed — one
hostile 24 MB tool result (file contents / command output from the
analysed target) parked a multi-million-entry set in the
orchestration process for the whole run. These tests pin the bound at
every layer: the token fallback, the JSON walk, the per-value length
ceiling, and the shared-union merge.
"""

from __future__ import annotations

import pytest

from core.llm.tool_use import loop as loop_mod
from core.llm.tool_use.loop import (
    _MAX_KNOWN_VALUE_LEN,
    _MAX_KNOWN_VALUES,
    _extract_tokens_from_text,
    _extract_values_from_json,
    _merge_known_values,
)


def test_token_fallback_respects_cap(monkeypatch):
    monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 50)
    text = " ".join(f"token{i:04d}" for i in range(500))
    values = _extract_tokens_from_text(text)
    assert len(values) <= 50


def test_json_fallback_lane_respects_cap(monkeypatch):
    # Non-JSON input routes through the token fallback — the lane the
    # hostile-blob case hits.
    monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 50)
    text = "not json " + " ".join(f"tok{i:04d}" for i in range(500))
    values = _extract_values_from_json(text)
    assert len(values) <= 50


def test_json_walk_respects_cap(monkeypatch):
    monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 50)
    import json
    payload = json.dumps({"items": [f"value{i:04d}" for i in range(500)]})
    values = _extract_values_from_json(payload)
    assert len(values) <= 50


def test_per_value_length_ceiling_json_leaf():
    import json
    big = "A" * (_MAX_KNOWN_VALUE_LEN + 1)
    payload = json.dumps({"blob": big, "small": "srv1"})
    values = _extract_values_from_json(payload)
    assert big not in values
    assert all(len(v) <= _MAX_KNOWN_VALUE_LEN for v in values)
    assert "srv1" in values


def test_per_value_length_ceiling_token_lane():
    big = "B" * (_MAX_KNOWN_VALUE_LEN + 1)
    values = _extract_tokens_from_text(f"small {big} other")
    assert big not in values
    assert {"small", "other"} <= values


def test_merge_known_values_enforces_shared_cap(monkeypatch):
    monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 10)
    dest = {f"seed{i}" for i in range(8)}
    clipped = _merge_known_values(dest, {f"new{i}" for i in range(10)})
    assert clipped is True
    assert len(dest) == 10


def test_merge_known_values_existing_members_are_free(monkeypatch):
    monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 10)
    dest = {f"seed{i}" for i in range(10)}
    # Re-merging already-known values must not report clipping.
    assert _merge_known_values(dest, set(dest)) is False
    assert len(dest) == 10


def test_default_cap_constants_sane():
    # The named bound must actually be the operative one.
    assert _MAX_KNOWN_VALUES == 50_000
    assert 0 < _MAX_KNOWN_VALUE_LEN <= 4096


@pytest.mark.slow
def test_large_non_json_blob_bounded_end_to_end():
    # Scaled-down analogue of the measured 40x escape: ~1M unique
    # tokens of non-JSON text must extract at most the cap.
    import random
    import string
    rng = random.Random(1)
    toks = {
        "".join(rng.choices(string.ascii_lowercase, k=11))
        for _ in range(120_000)
    }
    values = _extract_values_from_json(" ".join(toks))
    assert len(values) <= _MAX_KNOWN_VALUES


class TestNumericLeavesDiscoverable:
    """The gate requires numerically-typed values to have been
    'discovered in string form' (str(val) membership) — but the
    extractor collected str leaves only, so a numeric JSON field
    (pid, port, count) was permanently blocked for any x-source gated
    tool argument: no way to discover it. Numeric leaves now register
    their str() form, keeping the >=3-char rule."""

    def test_int_leaf_registers_string_form(self):
        from core.llm.tool_use.loop import _iter_undiscovered_values
        vals = _extract_values_from_json('{"pid": 1234, "host": "srv1"}')
        assert "1234" in vals
        assert list(_iter_undiscovered_values(1234, vals)) == []
        assert list(_iter_undiscovered_values("1234", vals)) == []

    def test_float_leaf_registers_string_form(self):
        vals = _extract_values_from_json('{"score": 3.75}')
        assert "3.75" in vals

    def test_bool_and_short_numbers_excluded(self):
        vals = _extract_values_from_json(
            '{"flag": true, "tiny": 12, "ok": 456}',
        )
        # bool is structural (the gate passes it unconditionally);
        # numbers under the min token length keep the string rule.
        assert "True" not in vals and "true" not in vals
        assert "12" not in vals
        assert "456" in vals


class TestCapIsStrictAtTheBoundary:
    """The extraction lanes must honour the cap STRICTLY: the
    per-token accounting checked the budget only at the top of each
    token, so a token whose slash-parts landed at the boundary could
    overshoot by a few entries (the union merge clamps the run set,
    but the lane-level bound advertised by the constant must hold
    too)."""

    def test_token_lane_never_exceeds_cap(self, monkeypatch):
        # Cap smaller than one token's contribution (token + 4
        # slash-parts = 5 entries): the boundary token must be
        # clipped mid-parts, never finish over the cap.
        monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 3)
        text = " ".join(
            f"alpha{i}/beta{i}/gamma{i}/delta{i}" for i in range(10)
        )
        values = _extract_tokens_from_text(text)
        assert len(values) <= 3

    def test_json_walk_never_exceeds_cap(self, monkeypatch):
        import json
        monkeypatch.setattr(loop_mod, "_MAX_KNOWN_VALUES", 3)
        payload = json.dumps({
            "items": [
                f"alpha{i}/beta{i}/gamma{i}/delta{i}" for i in range(10)
            ],
            "nums": [1000 + i for i in range(10)],
        })
        values = _extract_values_from_json(payload)
        assert len(values) <= 3
