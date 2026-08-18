"""Tests for negative controls on dynamic per-hypothesis semgrep rules.

Covers:
  - keyword plumbing through hypothesis_to_semgrep_rule_keyed
  - static negative-control fixtures (existence + regex sanity)
  - identifier-consistency gate in run_semgrep_sweep
  - negative-control cap in run_semgrep_sweep
  - orchestrator tool-chain wiring of the rule keyword
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

import pytest

from core.audit.hypothesis_mapping import (
    _HYPOTHESIS_SEMGREP_PATTERNS,
    hypothesis_to_semgrep_rule,
    hypothesis_to_semgrep_rule_keyed,
)
from core.audit.sweep import (
    _KEYWORD_FIXTURE_STEMS,
    _NEGATIVE_CONTROLS_DIR,
    _hypothesis_identifiers,
    _negative_control_cache,
    negative_control_fixture,
    run_semgrep_sweep,
)


@pytest.fixture(autouse=True)
def _clear_negative_control_cache():
    _negative_control_cache.clear()
    yield
    _negative_control_cache.clear()


def _install_fake_semgrep(monkeypatch, run_rule):
    """Install a fake packages.semgrep.runner module."""
    fake = types.ModuleType("packages.semgrep.runner")
    fake.run_rule = run_rule
    fake.is_available = lambda: True
    monkeypatch.setitem(sys.modules, "packages.semgrep.runner", fake)


class _FakeSemgrepResult:
    def __init__(self, findings):
        self.findings = findings
        self.errors = []


def _finding(line):
    return {"start": {"line": line}}


class TestKeyedRuleGeneration:
    def test_returns_rule_and_keyword(self):
        keyed = hypothesis_to_semgrep_rule_keyed(
            "use after free of request buffer", "handler.c",
        )
        assert keyed is not None
        path, keyword = keyed
        assert keyword == "use after free"
        assert "free" in Path(path).read_text()
        Path(path).unlink()

    def test_unknown_hypothesis_returns_none(self):
        assert hypothesis_to_semgrep_rule_keyed(
            "the function is suspicious", "a.c",
        ) is None

    def test_legacy_wrapper_still_returns_path_only(self):
        path = hypothesis_to_semgrep_rule(
            "buffer overflow via unchecked strcpy", "vuln.c",
        )
        assert isinstance(path, str)
        assert "strcpy" in Path(path).read_text()
        Path(path).unlink()


# The original keyword families use PRESENCE regexes: the guarded
# fixture deliberately matches, and the sweep caps the rule at
# inconclusive (a presence detector can never confirm). The P10 web
# families instead use UNSAFE-SHAPE patterns in the cocci_flow house
# style: the guarded fixture must NOT match, so a hit on the target is
# confirmation-grade (test_web_family_channels.py pins the non-match
# side). Keep the two disciplines separate here.
_PRESENCE_STYLE_KEYWORDS = (
    "buffer overflow", "sql injection", "command injection",
    "path traversal", "format string", "use after free", "double free",
    "xss", "reflected", "cross-site",
)

_UNSAFE_SHAPE_STEMS = {
    "deserialization", "ssrf", "xxe", "open_redirect",
}


class TestFixtures:
    def test_every_keyword_has_a_fixture_stem(self):
        for keyword in _HYPOTHESIS_SEMGREP_PATTERNS:
            assert keyword in _KEYWORD_FIXTURE_STEMS, (
                f"hypothesis_mapping keyword {keyword!r} has no "
                "negative-control fixture stem"
            )

    def test_every_stem_has_a_fixture_on_disk(self):
        # Presence-style stems ship a .c fixture; unsafe-shape stems
        # ship fixtures in the languages where their pattern is
        # meaningful (at least one on disk).
        for stem in set(_KEYWORD_FIXTURE_STEMS.values()):
            if stem in _UNSAFE_SHAPE_STEMS:
                found = any(
                    (_NEGATIVE_CONTROLS_DIR / f"{stem}{ext}").is_file()
                    for ext in (".py", ".c")
                )
                assert found, f"missing any fixture for stem {stem}"
            else:
                fixture = _NEGATIVE_CONTROLS_DIR / f"{stem}.c"
                assert fixture.is_file(), f"missing fixture {fixture}"

    def test_python_relevant_families_have_py_fixtures(self):
        for stem in ("sql_injection", "command_injection", "path_traversal",
                     "deserialization", "ssrf", "xxe", "open_redirect"):
            fixture = _NEGATIVE_CONTROLS_DIR / f"{stem}.py"
            assert fixture.is_file(), f"missing fixture {fixture}"

    @pytest.mark.parametrize("keyword", sorted(_PRESENCE_STYLE_KEYWORDS))
    def test_c_fixture_matches_its_pattern(self, keyword):
        """Each presence-style fixture is a true negative control: the
        presence regex for its keyword family fires on the (guarded)
        fixture code."""
        pattern = _HYPOTHESIS_SEMGREP_PATTERNS[keyword]
        stem = _KEYWORD_FIXTURE_STEMS[keyword]
        text = (_NEGATIVE_CONTROLS_DIR / f"{stem}.c").read_text()
        assert any(re.search(pattern, line) for line in text.splitlines()), (
            f"fixture {stem}.c does not match pattern for {keyword!r}"
        )

    @pytest.mark.parametrize("keyword", sorted(
        k for k, s in _KEYWORD_FIXTURE_STEMS.items()
        if s in _UNSAFE_SHAPE_STEMS
    ))
    def test_unsafe_shape_fixture_does_not_match(self, keyword):
        """Unsafe-shape families: safe usage must NOT trip the pattern
        (in every language the family ships a fixture for)."""
        pattern = _HYPOTHESIS_SEMGREP_PATTERNS[keyword]
        stem = _KEYWORD_FIXTURE_STEMS[keyword]
        checked = 0
        for ext in (".py", ".c"):
            fixture = _NEGATIVE_CONTROLS_DIR / f"{stem}{ext}"
            if not fixture.is_file():
                continue
            checked += 1
            text = fixture.read_text()
            assert not re.search(pattern, text), (
                f"unsafe-shape pattern for {keyword!r} matches its "
                f"guarded fixture {fixture.name}"
            )
        assert checked, f"no fixture on disk for stem {stem}"

    @pytest.mark.parametrize("keyword,stem", [
        ("sql injection", "sql_injection"),
        ("command injection", "command_injection"),
        ("path traversal", "path_traversal"),
    ])
    def test_py_fixture_matches_its_pattern(self, keyword, stem):
        pattern = _HYPOTHESIS_SEMGREP_PATTERNS[keyword]
        text = (_NEGATIVE_CONTROLS_DIR / f"{stem}.py").read_text()
        assert any(re.search(pattern, line) for line in text.splitlines())

    def test_fixture_lookup_by_language(self):
        c_fix = negative_control_fixture("sql injection", "src/db.c")
        py_fix = negative_control_fixture("sql injection", "src/db.py")
        assert c_fix is not None and c_fix.suffix == ".c"
        assert py_fix is not None and py_fix.suffix == ".py"

    def test_fixture_lookup_unknown_keyword(self):
        assert negative_control_fixture("unknown keyword", "a.c") is None


class TestHypothesisIdentifiers:
    def test_backticked_names_extracted(self):
        idents = _hypothesis_identifiers(
            "use after free of `conn` released in `close_conn()`",
        )
        assert "conn" in idents
        assert "close_conn" in idents

    def test_call_syntax_extracted(self):
        idents = _hypothesis_identifiers(
            "double free when cleanup(ctx) runs twice",
        )
        assert "cleanup" in idents

    def test_snake_case_extracted(self):
        idents = _hypothesis_identifiers(
            "buffer overflow copying user_name into fixed buffer",
        )
        assert "user_name" in idents

    def test_prose_only_names_nothing(self):
        assert _hypothesis_identifiers(
            "possible use after free somewhere in this function",
        ) == frozenset()


class TestIdentifierConsistency:
    """A dynamic-rule match may only confirm when the matched line ±2
    mentions an identifier the hypothesis names."""

    SOURCE = (
        "void handler(struct conn *c) {\n"       # 1
        "  free(c->buf);\n"                       # 2
        "  c->buf = 0;\n"                         # 3
        "}\n"                                     # 4
        "\n"                                      # 5
        "static char *g_tmp;\n"                   # 6
        "void other(void) {\n"                    # 7
        "  free(g_tmp);\n"                        # 8
        "}\n"                                     # 9
    )

    def _sweep(self, tmp_path, monkeypatch, *, match_lines, hypothesis):
        (tmp_path / "a.c").write_text(self.SOURCE)

        def run_rule(target, config, **kw):
            return _FakeSemgrepResult([_finding(ln) for ln in match_lines])

        _install_fake_semgrep(monkeypatch, run_rule)
        return run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="handler",
            rule_config="dyn.yaml",
            hypothesis=hypothesis,
        )

    def test_match_near_named_identifier_confirms(self, tmp_path, monkeypatch):
        result = self._sweep(
            tmp_path, monkeypatch, match_lines=[2],
            hypothesis="use after free of `conn` buffer",
        )
        assert result.outcome == "confirmed"

    def test_match_far_from_named_identifier_inconclusive(
        self, tmp_path, monkeypatch,
    ):
        result = self._sweep(
            tmp_path, monkeypatch, match_lines=[8],
            hypothesis="use after free of `conn` buffer",
        )
        assert result.outcome == "inconclusive"
        assert result.outcome != "confirmed"
        assert "identifier mismatch" in (result.details or {})["reason"]

    def test_inconsistent_matches_filtered_not_capped(
        self, tmp_path, monkeypatch,
    ):
        """When some matches are consistent, keep those and confirm."""
        result = self._sweep(
            tmp_path, monkeypatch, match_lines=[2, 8],
            hypothesis="use after free of `conn` buffer",
        )
        assert result.outcome == "confirmed"
        assert len(result.matches) == 1

    def test_hypothesis_naming_no_identifiers_skips_check(
        self, tmp_path, monkeypatch,
    ):
        result = self._sweep(
            tmp_path, monkeypatch, match_lines=[8],
            hypothesis="possible use after free somewhere here",
        )
        assert result.outcome == "confirmed"

    def test_match_without_line_info_fails_closed(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(self.SOURCE)

        def run_rule(target, config, **kw):
            return _FakeSemgrepResult([{"no_line": True}])

        _install_fake_semgrep(monkeypatch, run_rule)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="handler",
            rule_config="dyn.yaml",
            hypothesis="use after free of `conn` buffer",
        )
        assert result.outcome == "inconclusive"


class TestNegativeControlCap:
    """A rule that also matches its keyword's guarded fixture is a
    presence detector — capped at inconclusive."""

    def _sweep(self, tmp_path, monkeypatch, *, fixture_matches):
        (tmp_path / "a.c").write_text("void f(char *p) { free(p); }\n")

        def run_rule(target, config, **kw):
            if "negative_controls" in str(target):
                return _FakeSemgrepResult(
                    [_finding(1)] if fixture_matches else [],
                )
            return _FakeSemgrepResult([_finding(1)])

        _install_fake_semgrep(monkeypatch, run_rule)
        return run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="f",
            rule_config="dyn.yaml",
            rule_keyword="use after free",
        )

    def test_rule_matching_fixture_capped(self, tmp_path, monkeypatch):
        result = self._sweep(tmp_path, monkeypatch, fixture_matches=True)
        assert result.outcome == "inconclusive"
        assert "presence detector" in (result.details or {})["reason"]

    def test_rule_not_matching_fixture_confirms(self, tmp_path, monkeypatch):
        result = self._sweep(tmp_path, monkeypatch, fixture_matches=False)
        assert result.outcome == "confirmed"

    def test_no_keyword_skips_control(self, tmp_path, monkeypatch):
        """Stock rules (no keyword) are not run against fixtures."""
        (tmp_path / "a.c").write_text("void f(char *p) { free(p); }\n")
        calls = []

        def run_rule(target, config, **kw):
            calls.append(str(target))
            return _FakeSemgrepResult([_finding(1)])

        _install_fake_semgrep(monkeypatch, run_rule)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="f",
            rule_config="stock.yaml",
        )
        assert result.outcome == "confirmed"
        assert not any("negative_controls" in c for c in calls)

    def test_control_verdict_cached(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text("void f(char *p) { free(p); }\n")
        control_runs = []

        def run_rule(target, config, **kw):
            if "negative_controls" in str(target):
                control_runs.append(str(target))
                return _FakeSemgrepResult([_finding(1)])
            return _FakeSemgrepResult([_finding(1)])

        _install_fake_semgrep(monkeypatch, run_rule)
        for _ in range(2):
            run_semgrep_sweep(
                target_path=tmp_path,
                file_path="a.c",
                function_name="f",
                rule_config="dyn.yaml",
                rule_keyword="use after free",
            )
        assert len(control_runs) == 1

    def test_log_entry_carries_reason(self, tmp_path, monkeypatch):
        result = self._sweep(tmp_path, monkeypatch, fixture_matches=True)
        entry = result.to_log_entry()
        assert "presence detector" in entry["reason"]


class TestToolChainWiring:
    def test_dynamic_semgrep_entry_carries_keyword(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "double free of `ctx` in cleanup path", "src/a.c",
        )
        semgrep_entries = [e for e in chain if e["type"] == "semgrep"]
        assert semgrep_entries
        cfg = semgrep_entries[0]["config"]
        assert cfg["keyword"] == "double free"
        Path(cfg["rule"]).unlink(missing_ok=True)
