"""Tests for the per-pack language-applicability visibility line
(QoL #16a) — ``_target_semgrep_languages``,
``_pack_rules_applicable_count``, and ``_format_pack_applicability``.

Pre-fix the scanner's per-run output told the operator how many
PACKS ran but not how many RULES in those packs targeted the
actual language. For C codebases like the c.userspace-daemon
scan that surfaced this, the visible ``6 rule-group(s)`` masked
the reality that ~16 of ~2k upstream registry rules apply to C.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCANNER_PATH = Path(__file__).resolve().parents[1] / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "_scanner_under_test_pack_applicability", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
_spec.loader.exec_module(_scanner)

_target_semgrep_languages = _scanner._target_semgrep_languages
_pack_rules_applicable_count = _scanner._pack_rules_applicable_count
_format_pack_applicability = _scanner._format_pack_applicability
_is_coverage_thin = _scanner._is_coverage_thin
_format_thin_coverage_hint = _scanner._format_thin_coverage_hint
_expand_language_aliases = _scanner._expand_language_aliases
_thin_coverage_threshold = _scanner._thin_coverage_threshold
_pack_applicable_rule_ids = _scanner._pack_applicable_rule_ids
_display_lang = _scanner._display_lang
_display_langs = _scanner._display_langs


class TestTargetSemgrepLanguages:
    """Catalog → language list. Cheap-path (extension table); no
    tree walk."""

    def test_none_target_returns_empty(self):
        assert _target_semgrep_languages(None) == []

    def test_c_userspace_daemon_returns_c(self, tmp_path):
        # Build a tree matching c.userspace-daemon detection.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("")
        langs = _target_semgrep_languages(tmp_path)
        assert "c" in langs

    def test_python_web_app_returns_python(self, tmp_path):
        (tmp_path / "manage.py").write_text("")
        (tmp_path / "settings.py").write_text("")
        (tmp_path / "urls.py").write_text("")
        langs = _target_semgrep_languages(tmp_path)
        assert "python" in langs

    def test_unknown_target_extensions_returns_empty(self, monkeypatch, tmp_path):
        # Catalog match returns an entry whose file_extensions
        # don't map to any known semgrep language → empty list
        # → applicability line omitted.
        from core.run.target_types import CatalogEntry
        import core.run.target_types as tt
        monkeypatch.setattr(
            tt, "load",
            lambda _p: CatalogEntry(
                name="exotic", file_extensions=(".exotic", ".weird"),
            ),
        )
        assert _target_semgrep_languages(tmp_path) == []

    def test_catalog_exception_returns_empty(self, monkeypatch, tmp_path):
        import core.run.target_types as tt
        def _boom(_p):
            raise RuntimeError("catalog broken")
        monkeypatch.setattr(tt, "load", _boom)
        assert _target_semgrep_languages(tmp_path) == []


class TestPackRulesApplicableCount:
    """Count rules in a cached pack JSON whose ``languages``
    intersect with ``target_langs``."""

    def _write_pack(self, tmp_path: Path, pack_id: str, rules: list) -> Path:
        """Synthesise a cached pack JSON for ``pack_id``."""
        cache = tmp_path / (
            "c." + pack_id.replace("/", ".") + ".json"
        )
        cache.write_text(json.dumps({"rules": rules}))
        return cache

    def test_missing_cache_returns_none(self, monkeypatch, tmp_path):
        # No cache file → cannot count → None (caller omits the
        # pack from the visibility line rather than fabricating a
        # zero).
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        assert _pack_rules_applicable_count(
            "p/never-cached", target_langs=["c"],
        ) is None

    def test_counts_rules_matching_target_language(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        self._write_pack(tmp_path, "p/test", [
            {"id": "rule-c-1", "languages": ["c"]},
            {"id": "rule-c-2", "languages": ["c"]},
            {"id": "rule-py-1", "languages": ["python"]},
            {"id": "rule-multi", "languages": ["c", "cpp"]},
            {"id": "rule-noisy", "languages": ["dockerfile"]},
        ])
        applicable, total = _pack_rules_applicable_count(
            "p/test", target_langs=["c"],
        )
        assert applicable == 3  # 2 c-only + 1 multi-lang c+cpp
        assert total == 5

    def test_multiple_target_langs_union(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        self._write_pack(tmp_path, "p/test", [
            {"id": "c-only", "languages": ["c"]},
            {"id": "cpp-only", "languages": ["cpp"]},
            {"id": "rust-only", "languages": ["rust"]},
        ])
        applicable, total = _pack_rules_applicable_count(
            "p/test", target_langs=["c", "cpp"],
        )
        assert applicable == 2
        assert total == 3

    def test_missing_languages_field_treated_as_no_match(
        self, monkeypatch, tmp_path,
    ):
        # A malformed / partial rule without a ``languages`` field
        # contributes to the total but not the applicable count.
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        self._write_pack(tmp_path, "p/test", [
            {"id": "good", "languages": ["c"]},
            {"id": "no-langs"},  # no languages field
        ])
        applicable, total = _pack_rules_applicable_count(
            "p/test", target_langs=["c"],
        )
        assert applicable == 1
        assert total == 2

    def test_malformed_json_returns_none(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        cache_file = tmp_path / "c.p.broken.json"
        cache_file.write_text("{not valid json}")
        assert _pack_rules_applicable_count(
            "p/broken", target_langs=["c"],
        ) is None


class TestFormatPackApplicability:
    """Rendered operator-facing line."""

    def _setup_cache(self, monkeypatch, tmp_path, packs: dict):
        """Write each ``(pack_id, rules)`` entry into a synthetic
        cache; redirect RaptorConfig to read from tmp_path."""
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        for pid, rules in packs.items():
            cache = tmp_path / ("c." + pid.replace("/", ".") + ".json")
            cache.write_text(json.dumps({"rules": rules}))

    def test_no_target_langs_returns_none(self, monkeypatch, tmp_path):
        # Renderer says nothing when language detection produced
        # no signal (better than ``applicable to (none)`` noise).
        result = _format_pack_applicability(
            [("semgrep_x", "p/x")], target_langs=[],
        )
        assert result is None

    def test_renders_per_pack_counts(self, monkeypatch, tmp_path):
        self._setup_cache(monkeypatch, tmp_path, {
            "p/security-audit": [
                {"id": "c1", "languages": ["c"]},
                {"id": "c2", "languages": ["c"]},
                {"id": "py1", "languages": ["python"]},
            ],
            "p/owasp-top-ten": [
                {"id": "java1", "languages": ["java"]},
            ],
        })
        result = _format_pack_applicability(
            [
                ("semgrep_security_audit", "p/security-audit"),
                ("semgrep_owasp_top_10", "p/owasp-top-ten"),
            ],
            target_langs=["c"],
        )
        # Operator-display: ``c`` rendered as ``C`` (conventional
        # casing — see _LANG_DISPLAY).
        assert result == (
            "Pack rules applicable to C: "
            "security-audit 2/3, owasp-top-ten 0/1"
        )

    def test_omits_uncached_pack(self, monkeypatch, tmp_path):
        # Only one pack cached; the renderer omits the uncached
        # one rather than printing a misleading ``0/0``.
        self._setup_cache(monkeypatch, tmp_path, {
            "p/cached": [{"id": "c1", "languages": ["c"]}],
        })
        result = _format_pack_applicability(
            [
                ("semgrep_cached", "p/cached"),
                ("semgrep_uncached", "p/uncached"),
            ],
            target_langs=["c"],
        )
        assert "cached 1/1" in result
        assert "uncached" not in result

    def test_no_cached_packs_at_all_returns_none(self, monkeypatch, tmp_path):
        # Every pack uncached → no line to render (vs an empty-
        # right-hand-side ``Pack rules applicable to c:`` line).
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        result = _format_pack_applicability(
            [("semgrep_x", "p/x")], target_langs=["c"],
        )
        assert result is None

    def test_multiple_target_langs_in_label(self, monkeypatch, tmp_path):
        self._setup_cache(monkeypatch, tmp_path, {
            "p/test": [{"id": "c", "languages": ["c", "cpp"]}],
        })
        result = _format_pack_applicability(
            [("semgrep_test", "p/test")], target_langs=["c", "cpp"],
        )
        # Operator-display: ``c, cpp`` → ``C, C++``.
        assert "applicable to C, C++" in result


class TestIsCoverageThin:
    """Threshold-driven escalation gate. Calibration: ~9
    applicable rules on a C scan should fire; ~200+ on a Python
    scan should not."""

    def _setup_cache(self, monkeypatch, tmp_path, packs: dict):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        for pid, rules in packs.items():
            cache = tmp_path / ("c." + pid.replace("/", ".") + ".json")
            cache.write_text(json.dumps({"rules": rules}))

    def test_empty_target_langs_returns_false(self):
        # No language signal → no judgement → no hint.
        assert _is_coverage_thin(
            [("semgrep_x", "p/x")], target_langs=[],
        ) is False

    def test_thin_c_coverage_triggers(self, monkeypatch, tmp_path):
        # ~9 applicable rules — typical c.userspace-daemon scan.
        self._setup_cache(monkeypatch, tmp_path, {
            "p/security-audit": [
                {"id": f"c{i}", "languages": ["c"]} for i in range(9)
            ] + [
                {"id": f"py{i}", "languages": ["python"]} for i in range(216)
            ],
        })
        assert _is_coverage_thin(
            [("semgrep_security_audit", "p/security-audit")],
            target_langs=["c"],
        ) is True

    def test_rich_python_coverage_does_not_trigger(
        self, monkeypatch, tmp_path,
    ):
        # 200+ applicable rules — typical python.web-app scan.
        self._setup_cache(monkeypatch, tmp_path, {
            "p/security-audit": [
                {"id": f"py{i}", "languages": ["python"]}
                for i in range(150)
            ],
            "p/owasp-top-ten": [
                {"id": f"py{i}", "languages": ["python"]}
                for i in range(100)
            ],
        })
        assert _is_coverage_thin(
            [
                ("semgrep_security_audit", "p/security-audit"),
                ("semgrep_owasp_top_10", "p/owasp-top-ten"),
            ],
            target_langs=["python"],
        ) is False

    def test_no_cached_packs_returns_false(self, monkeypatch, tmp_path):
        # Uncached packs → we don't know what they'd contribute
        # → don't fire the hint on uncertainty.
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        assert _is_coverage_thin(
            [("semgrep_x", "p/x")], target_langs=["c"],
        ) is False

    def test_at_threshold_does_not_trigger(self, monkeypatch, tmp_path):
        # Boundary: exactly 25 applicable rules (the threshold)
        # should NOT trigger (gate is strict <, not <=) — the
        # operator chose to live with this baseline.
        self._setup_cache(monkeypatch, tmp_path, {
            "p/test": [
                {"id": f"c{i}", "languages": ["c"]} for i in range(25)
            ],
        })
        assert _is_coverage_thin(
            [("semgrep_test", "p/test")], target_langs=["c"],
        ) is False


class TestFormatThinCoverageHint:
    """Operator-readable escalation guidance. CodeQL clause
    omitted when --codeql is already running."""

    def test_codeql_not_running_suggests_both(self):
        hint = _format_thin_coverage_hint(
            ["c"], codeql_already_running=False,
        )
        # Operator-display: ``c`` → ``C``.
        assert "Coverage thin for C" in hint
        assert "--codeql" in hint
        assert "/agentic" in hint

    def test_codeql_already_running_omits_codeql_clause(self):
        # Operator already escalated to CodeQL — suggesting it
        # again would be noise.
        hint = _format_thin_coverage_hint(
            ["c"], codeql_already_running=True,
        )
        assert "--codeql" not in hint
        assert "/agentic" in hint

    def test_multi_language_label(self):
        hint = _format_thin_coverage_hint(
            ["c", "cpp"], codeql_already_running=False,
        )
        assert "Coverage thin for C, C++" in hint

    def test_llm_not_configured_omits_agentic_clause(self):
        # /agentic suggestion is hollow guidance when no LLM is
        # configured — omit it.
        hint = _format_thin_coverage_hint(
            ["c"], codeql_already_running=False,
            llm_configured=False,
        )
        assert "/agentic" not in hint
        assert "--codeql" in hint

    def test_both_alternatives_unavailable_renders_bare_fact(self):
        # Pathological case: --codeql already running AND no LLM
        # configured. Honest about the thin coverage rather than
        # printing an empty trailer.
        hint = _format_thin_coverage_hint(
            ["c"], codeql_already_running=True,
            llm_configured=False,
        )
        assert "Coverage thin for C" in hint
        assert "—" not in hint  # no dangling em-dash trailer


class TestDisplayLang:
    """Operator-facing capitalisation. Internal logic continues
    to use the lowercased semgrep ids; the display mapping is
    purely for rendered text."""

    def test_c_capitalised(self):
        assert _display_lang("c") == "C"

    def test_cpp_renders_as_cplusplus(self):
        assert _display_lang("cpp") == "C++"

    def test_csharp_renders_as_csharp_symbol(self):
        assert _display_lang("csharp") == "C#"

    def test_python_titlecase(self):
        assert _display_lang("python") == "Python"

    def test_typescript_titlecase(self):
        assert _display_lang("typescript") == "TypeScript"

    def test_unknown_lang_passes_through(self):
        # No mapping → render as-is rather than guess. Operator
        # sees the raw id; not pretty but not wrong.
        assert _display_lang("future-lang") == "future-lang"

    def test_display_langs_joins_with_comma(self):
        assert _display_langs(["c", "cpp"]) == "C, C++"

    def test_display_langs_empty(self):
        assert _display_langs([]) == ""


class TestExpandLanguageAliases:
    """Semgrep ships rules using BOTH names for the same language
    (e.g. ts and typescript). Catalog declares one canonical form;
    intersection must catch both."""

    def test_typescript_expands_both_names(self):
        result = _expand_language_aliases(["typescript"])
        assert "typescript" in result
        assert "ts" in result

    def test_ts_expands_both_names(self):
        # Symmetric: if catalog declared the short form, the long
        # form is also added.
        result = _expand_language_aliases(["ts"])
        assert "typescript" in result
        assert "ts" in result

    def test_kotlin_aliases(self):
        result = _expand_language_aliases(["kotlin"])
        assert {"kotlin", "kt"} <= result

    def test_csharp_aliases_include_capitalised_form(self):
        # semgrep packs ship rules with ``C#`` (capital). Verify
        # alias expansion includes that form too.
        result = _expand_language_aliases(["csharp"])
        assert {"csharp", "cs", "C#"} <= result

    def test_javascript_aliases(self):
        result = _expand_language_aliases(["javascript"])
        assert {"javascript", "js"} <= result

    def test_no_alias_lang_unchanged(self):
        # ``c`` has no alias — set should contain just ``c``.
        result = _expand_language_aliases(["c"])
        assert result == {"c"}


class TestPackRulesApplicableCountWithAliases:
    """Verify the applicability counter uses alias expansion —
    pre-fix it intersected against the canonical name only,
    undercounting on TS/Kotlin/etc."""

    def _setup_cache(self, monkeypatch, tmp_path, pack_id, rules):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        cache = tmp_path / ("c." + pack_id.replace("/", ".") + ".json")
        cache.write_text(json.dumps({"rules": rules}))

    def test_ts_rule_counted_for_typescript_target(
        self, monkeypatch, tmp_path,
    ):
        self._setup_cache(monkeypatch, tmp_path, "p/owasp", [
            {"id": "long-form", "languages": ["typescript"]},
            {"id": "short-form", "languages": ["ts"]},
            {"id": "py-only", "languages": ["python"]},
        ])
        applicable, total = _pack_rules_applicable_count(
            "p/owasp", target_langs=["typescript"],
        )
        # Both ``ts`` and ``typescript`` rules count for a
        # typescript target.
        assert applicable == 2
        assert total == 3


class TestPackJsonSchemaDefence:
    """Defensive guards against malformed / future cache shapes."""

    def _write(self, monkeypatch, tmp_path, pack_id, body):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        cache = tmp_path / ("c." + pack_id.replace("/", ".") + ".json")
        cache.write_text(json.dumps(body))
        return cache

    def test_rules_as_dict_returns_none(self, monkeypatch, tmp_path):
        # Future / corrupted cache file with ``rules`` as a dict
        # rather than a list. Pre-fix would iterate dict keys
        # (strings) and crash on ``r.get("languages")``.
        self._write(monkeypatch, tmp_path, "p/bad", {"rules": {"a": "b"}})
        assert _pack_rules_applicable_count(
            "p/bad", target_langs=["c"],
        ) is None

    def test_rule_entry_as_string_skipped(self, monkeypatch, tmp_path):
        # Individual non-dict entries skipped (don't crash).
        self._write(monkeypatch, tmp_path, "p/mixed", {
            "rules": [
                "spurious-string",
                {"id": "good", "languages": ["c"]},
                None,
                42,
                {"id": "also-good", "languages": ["c"]},
            ],
        })
        applicable, total = _pack_rules_applicable_count(
            "p/mixed", target_langs=["c"],
        )
        # Only the 2 dict entries count toward total; both apply.
        assert applicable == 2
        assert total == 2

    def test_rule_languages_as_string_treated_as_no_match(
        self, monkeypatch, tmp_path,
    ):
        # ``languages`` field as a scalar (shouldn't happen but
        # defensive). Counted toward total but not applicable.
        self._write(monkeypatch, tmp_path, "p/odd", {
            "rules": [
                {"id": "weird", "languages": "c"},  # str, not list
                {"id": "ok", "languages": ["c"]},
            ],
        })
        applicable, total = _pack_rules_applicable_count(
            "p/odd", target_langs=["c"],
        )
        assert applicable == 1
        assert total == 2


class TestThresholdEnvOverride:
    """Operator-tunable threshold via env var."""

    def test_default_when_env_unset(self, monkeypatch):
        monkeypatch.delenv(
            "RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD", raising=False,
        )
        assert _thin_coverage_threshold() == 25

    def test_env_override_used_when_valid_int(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD", "50")
        assert _thin_coverage_threshold() == 50

    def test_env_zero_disables_threshold_effectively(self, monkeypatch):
        # 0 = nothing triggers (always >= 0). Documents the
        # "I don't want this hint" escape hatch.
        monkeypatch.setenv("RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD", "0")
        assert _thin_coverage_threshold() == 0

    def test_env_malformed_falls_back_to_default(self, monkeypatch):
        # Contract: malformed value falls back to default rather
        # than crashing or silently disabling the gate. The
        # warning emitted on the side is operator UX, not part
        # of the contract — and the scanner's StreamHandler binds
        # sys.stderr at module-import time so capsys/capfd
        # can't see it from the test either way.
        monkeypatch.setenv("RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD", "lots")
        assert _thin_coverage_threshold() == 25

    def test_env_negative_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD", "-5")
        assert _thin_coverage_threshold() == 25


class TestIsCoverageThinDedupe:
    """Verify ``_is_coverage_thin`` counts UNIQUE rule ids across
    packs, not the sum of per-pack counts. Packs share rules —
    naive summing would inflate the count past the threshold for
    genuinely thin coverage."""

    def _setup_two_packs_with_overlap(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        # Both packs ship the same 10 c rules — dedupe yields 10,
        # naive sum yields 20.
        shared = [
            {"id": f"c-rule-{i}", "languages": ["c"]} for i in range(10)
        ]
        (tmp_path / "c.p.security-audit.json").write_text(
            json.dumps({"rules": shared}),
        )
        (tmp_path / "c.p.default.json").write_text(
            json.dumps({"rules": shared}),
        )

    def test_dedupe_keeps_thin_coverage_thin(self, monkeypatch, tmp_path):
        # 10 unique rules across 2 packs = under threshold 25.
        # Without dedupe, naive sum would be 20 (still under,
        # but the principle is what matters — see next test for
        # the failure case dedupe prevents).
        self._setup_two_packs_with_overlap(monkeypatch, tmp_path)
        assert _is_coverage_thin(
            [
                ("semgrep_security_audit", "p/security-audit"),
                ("semgrep_default", "p/default"),
            ],
            target_langs=["c"],
        ) is True  # 10 unique < 25

    def test_dedupe_with_partial_overlap(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        # Pack A: 20 rules. Pack B: same 20 + 10 unique = 30.
        # Naive sum: 50 → above 25 threshold (would not trigger).
        # Unique: 30 → above 25 threshold (also wouldn't trigger).
        # Test calibrates around the threshold boundary.
        a_rules = [
            {"id": f"shared-{i}", "languages": ["c"]} for i in range(20)
        ]
        b_extra = [
            {"id": f"b-unique-{i}", "languages": ["c"]} for i in range(10)
        ]
        (tmp_path / "c.p.a.json").write_text(
            json.dumps({"rules": a_rules}),
        )
        (tmp_path / "c.p.b.json").write_text(
            json.dumps({"rules": a_rules + b_extra}),
        )
        # Unique = 30; threshold = 25; 30 >= 25 → NOT thin.
        assert _is_coverage_thin(
            [("a", "p/a"), ("b", "p/b")],
            target_langs=["c"],
        ) is False
        # If we had not deduped, sum would be 20 + 30 = 50,
        # still not thin — both verdicts match here. The dedupe
        # win is when sum > threshold > unique, exercised in the
        # ``test_dedupe_flips_verdict_at_threshold`` case below.

    def test_dedupe_flips_verdict_at_threshold(
        self, monkeypatch, tmp_path, caplog,
    ):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        # Two packs ship the same 20 rules. Unique = 20 (thin);
        # naive sum = 40 (not thin). Verdict must use unique.
        shared = [
            {"id": f"shared-{i}", "languages": ["c"]} for i in range(20)
        ]
        (tmp_path / "c.p.a.json").write_text(
            json.dumps({"rules": shared}),
        )
        (tmp_path / "c.p.b.json").write_text(
            json.dumps({"rules": shared}),
        )
        # 20 unique < 25 threshold → IS thin (correct).
        assert _is_coverage_thin(
            [("a", "p/a"), ("b", "p/b")],
            target_langs=["c"],
        ) is True


class TestPackApplicableRuleIds:
    """The dedupe helper — returns the set of rule ids
    (intersected with alias-expanded target_langs)."""

    def _write(self, monkeypatch, tmp_path, pack_id, rules):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        cache = tmp_path / ("c." + pack_id.replace("/", ".") + ".json")
        cache.write_text(json.dumps({"rules": rules}))

    def test_returns_set_of_applicable_ids(self, monkeypatch, tmp_path):
        self._write(monkeypatch, tmp_path, "p/test", [
            {"id": "c-1", "languages": ["c"]},
            {"id": "c-2", "languages": ["c"]},
            {"id": "py-1", "languages": ["python"]},
        ])
        ids = _pack_applicable_rule_ids("p/test", target_langs=["c"])
        assert ids == {"c-1", "c-2"}

    def test_uses_alias_expansion(self, monkeypatch, tmp_path):
        self._write(monkeypatch, tmp_path, "p/test", [
            {"id": "ts-form", "languages": ["ts"]},
            {"id": "long-form", "languages": ["typescript"]},
        ])
        ids = _pack_applicable_rule_ids(
            "p/test", target_langs=["typescript"],
        )
        assert ids == {"ts-form", "long-form"}

    def test_skips_non_string_ids(self, monkeypatch, tmp_path):
        # Rule with no id / numeric id: skipped from set
        # (no name to dedupe by). Doesn't crash.
        self._write(monkeypatch, tmp_path, "p/odd", [
            {"languages": ["c"]},                      # no id
            {"id": 42, "languages": ["c"]},            # numeric id
            {"id": "", "languages": ["c"]},            # empty id
            {"id": "good", "languages": ["c"]},
        ])
        ids = _pack_applicable_rule_ids("p/odd", target_langs=["c"])
        assert ids == {"good"}

    def test_missing_cache_returns_none(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", tmp_path,
        )
        assert _pack_applicable_rule_ids(
            "p/never-cached", target_langs=["c"],
        ) is None
