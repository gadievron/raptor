"""Tier 0 must anchor source reads before mechanical proof admission."""
import pytest

from core.dataflow import smt_barrier as sb


def test_directory_swap_cannot_supply_tier0_source(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    guard = "if not re.fullmatch(r'[a-z]+', value): return"
    source = "import re\ndef handle(value):\n    " + guard + "\n    consume(value)\n"
    (nested / "app.py").write_text(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text(source + "# outside source marker\n")
    real_confine = sb.confine

    def swap_after_resolution(base, candidate):
        resolved = real_confine(base, candidate)
        nested.rename(root / "retired")
        nested.symlink_to(outside, target_is_directory=True)
        return resolved

    observed = []

    def stop_before_proof(source, *, language):
        observed.append(source)
        return True

    def unexpected_solver(*args, **kwargs):
        raise AssertionError("source-read regression must not invoke a solver")

    monkeypatch.setattr(sb, "confine", swap_after_resolution)
    monkeypatch.setattr(sb, "_z3_available", lambda: True)
    monkeypatch.setattr(sb, "java_unicode_unverified", stop_before_proof)
    monkeypatch.setattr(sb, "prove_neutralizes", unexpected_solver)
    result = sb.try_tier0(
        fix_diff="+" + guard + "\n", repo_root=root,
        sink_uri="nested/app.py", sink_line=4, sink_class="xss", language="python",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert observed == [], "outside source reached Tier 0 proof admission"


@pytest.mark.parametrize("suffix,profile", [
    ("# " + "😀" * 8 + "\r\n", None),
    ("# " + "π" * 200, "truncated_source"),
    ("# " + "x" * 600, "truncated_source"),
    (b"# invalid: \xff", "invalid_utf8_source"),
], ids=["exact-unicode-cr", "character-cap", "byte-cap", "invalid-utf8"])
def test_tier0_anchored_source_preserves_limits(tmp_path, monkeypatch, suffix, profile):
    guard = "if not re.fullmatch(r'[a-z]+', value): return"
    prefix = "import re\ndef handle(value):\n    " + guard + "\n    consume(value)\n"
    raw = prefix.encode() + (suffix.encode() if isinstance(suffix, str) else suffix)
    (tmp_path / "app.py").write_bytes(raw)
    monkeypatch.setattr(sb, "DEFAULT_MAX_SOURCE_CHARS", 128)
    monkeypatch.setattr(sb, "_z3_available", lambda: True)
    observed = []

    def stop_before_proof(source, *, language):
        observed.append(source)
        return True

    def unexpected_solver(*args, **kwargs):
        raise AssertionError("source-read regression must not invoke a solver")

    monkeypatch.setattr(sb, "java_unicode_unverified", stop_before_proof)
    monkeypatch.setattr(sb, "prove_neutralizes", unexpected_solver)
    result = sb.try_tier0(
        fix_diff="+" + guard + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss", language="python",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    if profile is None:
        assert observed == [raw.decode()]
    else:
        assert observed == []
        assert result.extras["unverified_source_profile"] == profile
