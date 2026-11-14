"""Tier 1 source reads stay beneath the analysed root at open time."""
import json

import pytest

from core.dataflow import tier1_llm as t1


def test_directory_swap_cannot_supply_outside_source(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    line = "sentinel = 1"
    (nested / "app.py").write_text(line + "\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text(line + "\n# outside source marker\n")
    real_confine = t1.confine

    def swap_after_resolution(base, candidate):
        resolved = real_confine(base, candidate)
        nested.rename(root / "retired")
        nested.symlink_to(outside, target_is_directory=True)
        return resolved

    observed = []

    def observe_source(source, *, language):
        observed.append(source)
        return False

    monkeypatch.setattr(t1, "confine", swap_after_resolution)
    monkeypatch.setattr(t1, "java_unicode_unverified", observe_source)
    reply = json.dumps({"kind": "unsupported", "validator_source_line": line})
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=root,
        sink_uri="nested/app.py", sink_line=1, sink_class="xss",
        language="python", complete=lambda *_args: reply,
    )
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert observed == [], "outside source reached proof admission"


@pytest.mark.parametrize("suffix,profile", [
    ("# " + "😀" * 8 + "\r\n", None),
    ("# " + "π" * 40, "truncated_source"),
    ("# " + "x" * 160, "truncated_source"),
    (b"# invalid: \xff", "invalid_utf8_source"),
], ids=["exact-unicode-cr", "character-cap", "byte-cap", "invalid-utf8"])
def test_anchored_source_preserves_admission_limits(tmp_path, monkeypatch, suffix, profile):
    line = "sentinel = 1"
    raw = (line + "\n").encode() + (suffix.encode() if isinstance(suffix, str) else suffix)
    (tmp_path / "app.py").write_bytes(raw)
    monkeypatch.setattr(t1, "DEFAULT_MAX_SOURCE_CHARS", 32)
    observed = []

    def observe_source(source, *, language):
        observed.append(source)
        return False

    monkeypatch.setattr(t1, "java_unicode_unverified", observe_source)
    reply = json.dumps({"kind": "unsupported", "validator_source_line": line})
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=1, sink_class="xss",
        language="python", complete=lambda *_args: reply,
    )
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    if profile is None:
        assert observed == [raw.decode()]
        assert "unknown kind" in result.reasoning
    else:
        assert observed == []
        assert result.extras["unverified_source_profile"] == profile
