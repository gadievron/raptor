"""Tests for the cwe_strategies wire-in to ``build_analysis_prompt_bundle``.

The picker should fire when context is supplied (especially ``cwe_id``)
and the rendered strategy block should appear in the system message.
Empty / unknown context produces no strategy block (or just the
generic ``general`` strategy, which is still useful).
"""

from __future__ import annotations

from unittest.mock import patch


from packages.llm_analysis.prompts.analysis import (
    build_analysis_prompt_bundle,
    build_analysis_prompt_bundle_from_finding,
)


def _system_message(bundle):
    return next(m.content for m in bundle.messages if m.role == "system")


# ---------------------------------------------------------------------------
# CWE pin produces strategy block
# ---------------------------------------------------------------------------


class TestCweTriggersStrategy:
    def test_cwe_78_picks_input_handling(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="py/command-injection",
            level="warning",
            file_path="src/runner.py",
            start_line=10, end_line=15,
            message="subprocess.call with user input",
            cwe_id="CWE-78",
        )
        sys = _system_message(bundle)
        # Strategy block header.
        assert "Bug-class lenses" in sys
        # input_handling strategy renders as a section.
        assert "## Strategy: input_handling" in sys
        # general always pinned first.
        assert sys.find("## Strategy: general") < sys.find(
            "## Strategy: input_handling"
        )

    def test_cwe_362_picks_concurrency(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="cpp/race-condition",
            level="warning",
            file_path="src/locks.c",
            start_line=1, end_line=20,
            message="potential race",
            cwe_id="CWE-362",
        )
        sys = _system_message(bundle)
        assert "## Strategy: concurrency" in sys

    def test_cwe_416_picks_memory_management(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="cpp/use-after-free",
            level="error",
            file_path="src/free.c",
            start_line=1, end_line=20,
            message="use-after-free",
            cwe_id="CWE-416",
        )
        sys = _system_message(bundle)
        assert "## Strategy: memory_management" in sys


# ---------------------------------------------------------------------------
# Path / function / call signals also fire
# ---------------------------------------------------------------------------


class TestNonCweSignals:
    def test_path_signal_fires_without_cwe(self):
        """File under ``net/`` matches input_handling's path signal."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="net/parser.c",
            start_line=1, end_line=10,
            message="m",
        )
        sys = _system_message(bundle)
        assert "## Strategy: input_handling" in sys

    def test_function_calls_signal(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.c",
            start_line=1, end_line=10,
            message="m",
            function_calls_made=["mutex_lock", "mutex_unlock"],
        )
        sys = _system_message(bundle)
        assert "## Strategy: concurrency" in sys

    def test_function_name_keyword(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.c",
            start_line=1, end_line=10,
            message="m",
            function_name="parse_request",
        )
        sys = _system_message(bundle)
        assert "## Strategy: input_handling" in sys

    def test_no_signal_still_includes_general(self):
        """When nothing specific matches, ``general`` always fires —
        the LLM still gets the trust/assumption baseline lens."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="data/blob.unknown",
            start_line=1, end_line=10,
            message="m",
        )
        sys = _system_message(bundle)
        # Strategy block present, general included.
        assert "## Strategy: general" in sys


# ---------------------------------------------------------------------------
# from_finding plumbs all signal dimensions
# ---------------------------------------------------------------------------


class TestFromFinding:
    def test_finding_cwe_id_plumbed(self):
        finding = {
            "rule_id": "py/sql-injection",
            "level": "warning",
            "file_path": "src/db.py",
            "start_line": 1, "end_line": 5,
            "message": "tainted query",
            "cwe_id": "CWE-89",
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        sys = _system_message(bundle)
        assert "## Strategy: input_handling" in sys

    def test_finding_metadata_function_name(self):
        finding = {
            "rule_id": "x",
            "level": "warning",
            "file_path": "src/foo.c",
            "start_line": 1, "end_line": 5,
            "message": "m",
            "metadata": {
                "name": "parse_request",
                "calls": ["mutex_lock"],
            },
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        sys = _system_message(bundle)
        assert "## Strategy: input_handling" in sys
        assert "## Strategy: concurrency" in sys

    def test_finding_with_no_extra_context(self):
        """Bare finding (no cwe, no metadata) still produces a system
        prompt — strategy block falls back to general or omits cleanly."""
        finding = {
            "rule_id": "x",
            "level": "warning",
            "file_path": "src/foo.unknown_ext",
            "start_line": 1, "end_line": 5,
            "message": "m",
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        # No crash; bundle is well-formed.
        assert bundle.messages
        sys = _system_message(bundle)
        # Existing system content is preserved.
        assert "ASSUME-EXPLOIT" in sys


# ---------------------------------------------------------------------------
# Adversarial / robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_picker_failure_doesnt_break_prompt(self, monkeypatch):
        """If the picker raises for any reason, the prompt builder
        must still produce a usable bundle — strategy block is
        best-effort."""

        def boom(**kwargs):
            raise RuntimeError("simulated picker failure")

        # Patch the symbol the helper imports lazily.
        with patch("core.llm.cwe_strategies.pick_strategies", boom):
            bundle = build_analysis_prompt_bundle(
                rule_id="x", level="warning",
                file_path="src/foo.py",
                start_line=1, end_line=5,
                message="m",
                cwe_id="CWE-78",
            )
            sys = _system_message(bundle)
            # No crash, strategy block omitted, base prompt intact.
            assert "Bug-class lenses" not in sys
            assert "ASSUME-EXPLOIT" in sys

    def test_substrate_missing_doesnt_break(self, monkeypatch):
        """If the cwe_strategies package can't be imported (older
        deployments), prompt building still works."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            bundle = build_analysis_prompt_bundle(
                rule_id="x", level="warning",
                file_path="src/foo.py",
                start_line=1, end_line=5,
                message="m",
                cwe_id="CWE-78",
            )
            sys = _system_message(bundle)
            # Base prompt intact.
            assert "ASSUME-EXPLOIT" in sys


# ---------------------------------------------------------------------------
# Strategy block goes to system message, not user (operator-curated)
# ---------------------------------------------------------------------------


class TestStrategyInSystemPrompt:
    def test_strategy_in_system_not_user(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="net/parser.c",
            start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-78",
        )
        sys = _system_message(bundle)
        user = next(m.content for m in bundle.messages if m.role == "user")
        # Strategy lenses live in the system message.
        assert "Bug-class lenses" in sys
        # NOT in the user message (which carries untrusted content).
        assert "Bug-class lenses" not in user
