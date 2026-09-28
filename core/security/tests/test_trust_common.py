"""
core/security/tests/test_trust_common.py

Unit coverage for the shared trust-gate helper layer
(core/security/_trust_common.py): output sanitisation, secret masking,
the Finding/FileScan shapes, the fail-closed resolve-and-stat gate,
and the scan-report renderer.

Consumer-level behavior (the cc_trust / codeql_trust gates) keeps its
own suites; this file pins the layer's contracts at their new single
home.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.security._trust_common import (
    EXTRA_STRIP,
    MAX_TRUST_CONFIG_BYTES,
    FileScan,
    Finding,
    mask,
    render_scan_report,
    resolve_supplied_target,
    safe_text,
    truncate,
)


class TestSafeText:
    """safe_text() strips Cc/Cf categories plus U+2028/U+2029 so
    attacker-chosen bytes cannot drive ANSI escapes, Trojan Source
    bidi overrides, zero-width smuggling, or output-line splitting."""

    def test_ansi_escape_stripped(self):
        assert safe_text("a\x1b[31mred\x07b") == "a?[31mred?b"

    def test_bidi_override_stripped(self):
        # U+202E RIGHT-TO-LEFT OVERRIDE (category Cf).
        assert safe_text("a\u202eb") == "a?b"

    def test_zero_width_stripped(self):
        assert safe_text("a\u200bb") == "a?b"

    def test_line_separators_stripped(self):
        _ls, _ps = chr(0x2028), chr(0x2029)
        assert EXTRA_STRIP == {_ls, _ps}
        assert safe_text(f"a{_ls}b{_ps}c") == "a?b?c"

    def test_tab_survives(self):
        assert safe_text("a\tb") == "a\tb"

    def test_ordinary_text_untouched(self):
        assert safe_text("a b — ✓") == "a b — ✓"

    def test_newline_stripped(self):
        assert safe_text("a\nb") == "a?b"


class TestSourceUsesEscapedForms:
    """The literal U+2028/U+2029 characters are invisible in an editor;
    the set must be spelled with escapes so it stays reviewable and an
    accidental 'cleanup' to real spaces can't disable the defence."""

    def test_source_uses_escaped_forms(self):
        import core.security._trust_common as mod
        src = Path(mod.__file__).read_text(encoding="utf-8")
        assert chr(0x2028) not in src and chr(0x2029) not in src, (
            "_trust_common.py contains literal U+2028/U+2029 — use "
            "the escaped spellings so the set stays reviewable")
        assert "u2028" in src and "u2029" in src


class TestTruncate:

    def test_short_string_unchanged(self):
        assert truncate("abc") == "abc"

    def test_long_string_bounded_with_marker(self):
        out = truncate("x" * 100)
        assert out == "x" * 80 + "..."

    def test_custom_limit(self):
        assert truncate("abcdef", limit=4) == "abcd..."

    def test_sanitises_before_bounding(self):
        assert truncate("a\x1bb", limit=10) == "a?b"


class TestMask:
    """Masked rendering: scan output is CI-log-retained, so values that
    can embed credentials show a short triage prefix + length only."""

    def test_empty_value(self):
        assert mask("") == "(empty)"

    def test_long_value_keeps_prefix_and_length(self):
        assert mask("secret-command --token=abc") == \
            "secret-c*** (26 chars)"

    def test_value_no_longer_than_keep_fully_redacted(self):
        # A prefix of a value no longer than ``keep`` IS the value.
        assert mask("short", keep=8) == "*** (5 chars)"
        assert mask("exactly8", keep=8) == "*** (8 chars)"

    def test_keep_zero_fully_redacts(self):
        assert mask("supersecretvalue", keep=0) == "*** (16 chars)"

    def test_control_chars_sanitised_first(self):
        out = mask("ab\x1bcdefghij")
        assert "\x1b" not in out


class TestFindingShapes:

    def test_filescan_has_blocking(self):
        fs = FileScan(path=Path("/x"))
        assert fs.has_blocking() is False
        fs.findings.append(Finding("info", "v", False))
        assert fs.has_blocking() is False
        fs.findings.append(Finding("bad", "v", True))
        assert fs.has_blocking() is True


class TestResolveSuppliedTarget:
    """Fail-closed resolve+stat: a supplied path that cannot be
    examined is refused (or downgraded to warn-and-proceed by the
    trust override) — never waved through as clean."""

    def test_existing_dir_resolves(self, tmp_path, capsys):
        resolved, refuse = resolve_supplied_target(
            str(tmp_path), False, "Claude Code config")
        assert resolved == str(tmp_path.resolve())
        assert refuse is False
        assert capsys.readouterr().out == ""

    def test_nonexistent_refuses(self, tmp_path, capsys):
        resolved, refuse = resolve_supplied_target(
            str(tmp_path / "gone"), False, "Claude Code config")
        assert resolved is None
        assert refuse is True
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "treating as dangerous" in out
        assert "Claude Code config" in out

    def test_nonexistent_with_override_proceeds(self, tmp_path, capsys):
        resolved, refuse = resolve_supplied_target(
            str(tmp_path / "gone"), True, "CodeQL pack config")
        assert resolved is None
        assert refuse is False
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "trust override active" in out
        assert "CodeQL pack config" in out

    def test_null_byte_path_refuses(self):
        resolved, refuse = resolve_supplied_target(
            "./weird\x00path", False, "x config")
        assert resolved is None
        assert refuse is True

    def test_hostile_path_bounded_and_escaped(self, tmp_path, capsys):
        hostile = str(tmp_path / ("evil\x1b]0;pwned\x07" + "x" * 400))
        resolved, refuse = resolve_supplied_target(
            hostile, False, "x config")
        assert resolved is None and refuse is True
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\x07" not in out
        # Bounded: the 400-char tail must have been elided.
        assert "..." in out


class TestRenderScanReport:

    @staticmethod
    def _one_scan(tmp_path: Path, blocking: bool) -> list[FileScan]:
        fs = FileScan(path=tmp_path / "cfg.json")
        fs.findings.append(Finding("label", "value", blocking))
        return [fs]

    def test_blocking_header(self, tmp_path, capsys):
        render_scan_report(tmp_path, self._one_scan(tmp_path, True),
                           True, False, "Claude Code config")
        out = capsys.readouterr().out
        assert out.startswith(
            f"raptor: {tmp_path} has dangerous Claude Code config:")
        assert "cfg.json" in out
        assert "label" in out and "value" in out

    def test_blocking_header_with_override(self, tmp_path, capsys):
        render_scan_report(tmp_path, self._one_scan(tmp_path, True),
                           True, True, "CodeQL pack config")
        out = capsys.readouterr().out
        assert ("has dangerous CodeQL pack config "
                "(trust override active):") in out

    def test_informational_header(self, tmp_path, capsys):
        render_scan_report(tmp_path, self._one_scan(tmp_path, False),
                           False, False, "Claude Code config")
        out = capsys.readouterr().out
        assert "has Claude Code config:" in out
        assert "dangerous" not in out

    def test_out_of_target_path_rendered_absolute(self, tmp_path, capsys):
        fs = FileScan(path=Path("/elsewhere/cfg.json"))
        fs.findings.append(Finding("label", "v", True))
        render_scan_report(tmp_path, [fs], True, False, "x config")
        assert "/elsewhere/cfg.json" in capsys.readouterr().out

    def test_hostile_target_name_escaped(self, tmp_path, capsys):
        evil = tmp_path / "e\x1bvil"
        evil.mkdir()
        render_scan_report(evil, self._one_scan(evil, True),
                           True, False, "x config")
        assert "\x1b" not in capsys.readouterr().out


class TestCapMagnitude:
    """Band pin on MAX_TRUST_CONFIG_BYTES itself. The consumer-suite
    boundary tests follow the constant (at-cap scans, one-over blocks),
    so they stay green under ANY value — only a magnitude pin catches
    the constant being moved. Both directions are regressions."""

    def test_cap_not_rewidened_past_resolved_value(self):
        # Upper bound: the shared cap resolved the twin drift to the
        # SMALLER historical value (cc_trust's 1_000_000). Re-widening
        # past it silently re-opens the 1_000_001..1_048_576 band where
        # attacker-supplied pack/config bytes scanned (and could scan
        # clean) instead of refusing — a deny-direction regression.
        assert MAX_TRUST_CONFIG_BYTES <= 1_000_000

    def test_cap_not_shrunk_below_legitimate_config_floor(self):
        # Lower bound: shrinking the cap makes the gates refuse
        # ordinary legitimate trust configs outright (an operational
        # break, recoverable only via --trust-repo). Real config/pack
        # files are <10 KiB; 64 KiB is the floor below which refusal
        # stops being oversize defence.
        assert MAX_TRUST_CONFIG_BYTES >= 65_536


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
