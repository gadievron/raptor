"""Deferred materialization retains the legacy renderer's exact byte identity."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from engine.coccinelle import vocab_renderer as renderer


def test_prepared_bytes_match_legacy_output_without_initial_file(tmp_path, monkeypatch):
    rule = tmp_path / "unicode.cocci"
    rule.write_text('// café\n// @vocab: deallocators\n\\(free\\)(p);\n')
    vocab = SimpleNamespace(deallocators=frozenset({"custom_free"}))
    legacy = renderer.render(rule, vocab)
    try:
        expected = legacy.read_bytes()
    finally:
        legacy.unlink()
    original = renderer.tempfile.NamedTemporaryFile
    calls = []

    def create(*a, **kw):
        calls.append(kw)
        return original(*a, **kw)

    monkeypatch.setattr(renderer.tempfile, "NamedTemporaryFile", create)
    prepared = renderer.prepare(rule, vocab)
    assert calls == []
    assert prepared.data == expected
    assert prepared.digest == hashlib.sha256(expected).hexdigest()
    path = prepared.materialize()
    try:
        assert path.read_bytes() == expected
        assert prepared.materialize() == path
        assert len(calls) == 1
    finally:
        prepared.close()
    assert not path.exists()


def test_failed_materialization_is_not_retried_by_prewarm_and_sweep(tmp_path, monkeypatch):
    prepared = renderer.PreparedRule(tmp_path / "r.cocci", "text\n")
    calls = []

    def fail(*a, **kw):
        calls.append(1)
        raise OSError("disk unavailable")

    monkeypatch.setattr(renderer.tempfile, "NamedTemporaryFile", fail)
    for _ in range(2):
        with pytest.raises(OSError, match="disk unavailable"):
            prepared.materialize()
    assert calls == [1]
    prepared.close()


def test_no_splice_needs_no_materialization(tmp_path):
    rule = tmp_path / "plain.cocci"
    rule.write_text("@r@\n@@\nfree(...);\n")
    assert renderer.prepare(rule, SimpleNamespace()) is None


@pytest.mark.parametrize("rule", sorted((Path(__file__).parents[1] / "rules").glob("*.cocci")), ids=lambda p: p.stem)
def test_all_shipped_rules_keep_legacy_bytes(rule):
    vocab = SimpleNamespace(**{
        attr: frozenset({f"project_{attr}"})
        for attr in set(renderer._BUCKET_MAP.values())
    })
    legacy = renderer.render(rule, vocab)
    prepared = renderer.prepare(rule, vocab)
    try:
        assert (legacy is None) == (prepared is None)
        if legacy is not None:
            assert prepared.data == legacy.read_bytes()
            assert prepared.digest == hashlib.sha256(legacy.read_bytes()).hexdigest()
    finally:
        if legacy is not None:
            legacy.unlink(missing_ok=True)
        if prepared is not None:
            prepared.close()
