"""Tests for language alias normalisation and small-target retry.

Both behaviours close ergonomic footguns in the CodeQL agent:

* Alias map: `--languages c` (the obvious operator string) used to
  fall through every detector branch and end in no-build mode →
  autobuild.sh exit 1 → "no usable CodeQL DB" with no actionable
  diagnostic.
* Small-target retry: `detect_languages` defaults to min_files=3 as
  a noise floor for monorepos, but on single-file fixtures the
  detector saw the file, classified it, then silently filtered it
  out — same opaque "no languages detected" failure.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock


# packages/codeql/tests/test_language_normalisation.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.agent import _normalise_language, _LANGUAGE_ALIASES


class TestNormaliseLanguage:
    """Cases for _normalise_language — the alias resolver."""

    def test_c_to_cpp(self):
        assert _normalise_language("c") == "cpp"

    def test_cpp_passthrough(self):
        assert _normalise_language("cpp") == "cpp"

    def test_c_plus_plus_to_cpp(self):
        assert _normalise_language("c++") == "cpp"

    def test_js_to_javascript(self):
        assert _normalise_language("js") == "javascript"

    def test_ts_to_typescript(self):
        assert _normalise_language("ts") == "typescript"

    def test_csharp_aliases(self):
        assert _normalise_language("c#") == "csharp"
        assert _normalise_language("cs") == "csharp"

    def test_kotlin_alias(self):
        assert _normalise_language("kt") == "kotlin"

    def test_python_alias(self):
        assert _normalise_language("py") == "python"

    def test_case_insensitive(self):
        assert _normalise_language("C") == "cpp"
        assert _normalise_language("JS") == "javascript"
        assert _normalise_language("CPP") == "cpp"

    def test_whitespace_stripped(self):
        assert _normalise_language("  c  ") == "cpp"
        assert _normalise_language("\tjavascript\n") == "javascript"

    def test_unknown_passes_through(self):
        # Unknown names should pass through (lowercased) so the
        # downstream "unsupported language" diagnostic still fires
        # cleanly rather than being masked by silent rewrite.
        assert _normalise_language("rust") == "rust"
        assert _normalise_language("zig") == "zig"

    def test_alias_map_targets_are_canonical(self):
        # Every alias target must be a CodeQL-supported canonical
        # name. Guards against typos in the map.
        from packages.codeql.language_detector import LanguageDetector
        for alias, canonical in _LANGUAGE_ALIASES.items():
            assert canonical in LanguageDetector.CODEQL_SUPPORTED, (
                f"alias {alias!r} maps to {canonical!r} which is not a "
                f"CodeQL canonical name"
            )


class TestExplicitLanguagesNormalised:
    """Run-workflow accepts aliases when the operator passes
    --languages c."""

    def test_languages_c_normalised_to_cpp(self, tmp_path):
        """Smoke test: invoking run_autonomous_analysis(languages=
        ['c']) should propagate 'cpp' to downstream phases, not
        'c'."""
        from packages.codeql.agent import CodeQLAgent

        # Mock the heavy machinery — we only care that the agent
        # passes the canonical name through to build_detector.
        agent = CodeQLAgent.__new__(CodeQLAgent)
        agent.repo_path = tmp_path
        agent.out_dir = tmp_path / "out"
        agent.start_time = 0.0
        agent.language_detector = MagicMock()
        agent.build_detector = MagicMock()
        agent.database_manager = MagicMock()
        agent.query_runner = MagicMock()

        # Stub build_detector to record what languages it sees and
        # short-circuit the rest of the workflow with a controlled
        # failure (so we don't actually try to run codeql).
        seen_languages = []
        def fake_detect(lang):
            seen_languages.append(lang)
            return None
        def fake_synthesise(lang):
            seen_languages.append(lang)
            return None
        def fake_no_build(lang):
            # cpp routes through the buildless default, whose
            # no-build config call is the canonical-name witness.
            seen_languages.append(lang)
            from core.build.build_detector import BuildSystem
            return BuildSystem(
                type="no-build", command="", working_dir=tmp_path,
                env_vars={}, confidence=1.0, detected_files=[],
            )
        agent.build_detector.detect_build_system.side_effect = fake_detect
        agent.build_detector.synthesise_build_command.side_effect = fake_synthesise
        agent.build_detector.generate_no_build_config.side_effect = fake_no_build

        # database_manager returns empty so workflow exits cleanly;
        # buildless probe reports a modern CLI.
        agent.database_manager.create_databases_parallel.return_value = {}
        agent.database_manager.supports_buildless.return_value = (
            True, "2.26.0",
        )

        agent.run_autonomous_analysis(languages=["c"])

        # The agent should have passed "cpp" (canonical) to the
        # detector chain, NEVER the raw "c" string.
        assert "cpp" in seen_languages, (
            f"build_detector never saw canonical 'cpp'; saw: {seen_languages}"
        )
        assert "c" not in seen_languages, (
            f"build_detector saw raw 'c' — normalisation didn't fire; "
            f"saw: {seen_languages}"
        )


class TestSmallTargetRetry:
    """Agent delegates to detect_languages_tiered for the retry cascade."""

    def test_agent_calls_tiered_detection(self, tmp_path):
        """The agent calls detect_languages_tiered (not the individual
        tiers) so every caller gets the cascade automatically."""
        from packages.codeql.agent import CodeQLAgent

        agent = CodeQLAgent.__new__(CodeQLAgent)
        agent.repo_path = tmp_path
        agent.out_dir = tmp_path / "out"
        agent.start_time = 0.0
        agent.language_detector = MagicMock()
        agent.build_detector = MagicMock()
        agent.database_manager = MagicMock()
        agent.query_runner = MagicMock()

        from packages.codeql.language_detector import LanguageInfo
        cpp_info = LanguageInfo(
            language="cpp", confidence=0.5, file_count=1,
            extensions_found={".c"}, build_files_found=[],
            indicators_found=[],
        )
        agent.language_detector.detect_languages_tiered.return_value = {
            "cpp": cpp_info,
        }
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        from core.build.build_detector import BuildSystem
        agent.build_detector.generate_no_build_config.return_value = (
            BuildSystem(
                type="no-build", command="", working_dir=tmp_path,
                env_vars={}, confidence=1.0, detected_files=[],
            )
        )
        agent.database_manager.create_databases_parallel.return_value = {}

        agent.run_autonomous_analysis()

        agent.language_detector.detect_languages_tiered.assert_called_once_with(
            min_files=3, codeql_filter=True,
        )
