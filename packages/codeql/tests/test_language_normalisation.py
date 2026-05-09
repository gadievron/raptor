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
from unittest.mock import MagicMock, patch

import pytest

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
            from packages.codeql.build_detector import BuildSystem
            return BuildSystem(
                type="no-build", command="", working_dir=tmp_path,
                env_vars={}, confidence=1.0, detected_files=[],
            )
        agent.build_detector.detect_build_system.side_effect = fake_detect
        agent.build_detector.synthesise_build_command.side_effect = fake_synthesise
        agent.build_detector.generate_no_build_config.side_effect = fake_no_build

        # database_manager returns empty so workflow exits cleanly
        agent.database_manager.create_databases_parallel.return_value = {}

        result = agent.run_autonomous_analysis(languages=["c"])

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
    """Auto-detect on small targets retries with min_files=1."""

    def test_retry_widens_when_first_pass_empty(self, tmp_path):
        """If detect_languages(min_files=3) returns empty, the agent
        retries with min_files=1 before giving up."""
        from packages.codeql.agent import CodeQLAgent

        agent = CodeQLAgent.__new__(CodeQLAgent)
        agent.repo_path = tmp_path
        agent.out_dir = tmp_path / "out"
        agent.start_time = 0.0
        agent.language_detector = MagicMock()
        agent.build_detector = MagicMock()
        agent.database_manager = MagicMock()
        agent.query_runner = MagicMock()

        # First pass returns empty; second pass (min_files=1)
        # returns a single language. The agent must call detect
        # twice and consume the second result.
        from packages.codeql.language_detector import LanguageInfo
        cpp_info = LanguageInfo(
            language="cpp", confidence=0.5, file_count=1,
            extensions_found={".c"}, build_files_found=[],
            indicators_found=[],
        )
        agent.language_detector.detect_languages.side_effect = [
            {},  # first call: min_files=3, nothing found
            {"cpp": cpp_info},  # second call: min_files=1, found
        ]
        agent.language_detector.filter_codeql_supported.side_effect = (
            lambda d: d
        )

        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        from packages.codeql.build_detector import BuildSystem
        agent.build_detector.generate_no_build_config.return_value = (
            BuildSystem(
                type="no-build", command="", working_dir=tmp_path,
                env_vars={}, confidence=1.0, detected_files=[],
            )
        )
        agent.database_manager.create_databases_parallel.return_value = {}

        agent.run_autonomous_analysis()

        # Two calls: first with min_files=3, second with min_files=1.
        assert agent.language_detector.detect_languages.call_count == 2
        first_call_kwargs = (
            agent.language_detector.detect_languages.call_args_list[0].kwargs
        )
        second_call_kwargs = (
            agent.language_detector.detect_languages.call_args_list[1].kwargs
        )
        assert first_call_kwargs.get("min_files") == 3
        assert second_call_kwargs.get("min_files") == 1

    def test_no_retry_when_first_pass_succeeds(self, tmp_path):
        """If the first pass already finds languages, no retry."""
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
            language="cpp", confidence=0.8, file_count=10,
            extensions_found={".c"}, build_files_found=[],
            indicators_found=[],
        )
        agent.language_detector.detect_languages.return_value = {
            "cpp": cpp_info
        }
        agent.language_detector.filter_codeql_supported.side_effect = (
            lambda d: d
        )
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        from packages.codeql.build_detector import BuildSystem
        agent.build_detector.generate_no_build_config.return_value = (
            BuildSystem(
                type="no-build", command="", working_dir=tmp_path,
                env_vars={}, confidence=1.0, detected_files=[],
            )
        )
        agent.database_manager.create_databases_parallel.return_value = {}

        agent.run_autonomous_analysis()

        assert agent.language_detector.detect_languages.call_count == 1
