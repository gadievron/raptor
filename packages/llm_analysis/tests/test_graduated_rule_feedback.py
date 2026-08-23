"""Tests for the P7 precision feedback on graduated-rule findings.

``_record_graduated_rule_feedback`` keys off the
``synthesized:<library_rule_id>`` ruleId the scanner's graduated stage
stamps, and feeds the analysis verdict into RuleLibrary.record_match.
The library is stubbed — no filesystem manifest involved.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from typing import ClassVar  # noqa: E402

from packages.llm_analysis.agent import AutonomousSecurityAgentV2  # noqa: E402


class _FakeLibrary:
    calls: ClassVar[list] = []

    def __init__(self, *a, **kw):
        pass

    def record_match(self, rule_id, is_tp):
        _FakeLibrary.calls.append((rule_id, is_tp))


def _agent_stub():
    agent = SimpleNamespace(
        _SYNTHESIZED_RULE_PREFIX=(
            AutonomousSecurityAgentV2._SYNTHESIZED_RULE_PREFIX
        ),
    )
    agent._record_graduated_rule_feedback = (
        AutonomousSecurityAgentV2._record_graduated_rule_feedback.__get__(
            agent, type(agent)
        )
    )
    return agent


def _vuln(rule_id, analysis):
    return SimpleNamespace(rule_id=rule_id, analysis=analysis)


def _patch_library(monkeypatch):
    _FakeLibrary.calls = []
    import packages.checker_synthesis.library as lib_mod
    monkeypatch.setattr(lib_mod, "RuleLibrary", _FakeLibrary)
    return _FakeLibrary.calls


class TestGraduatedRuleFeedback:
    def test_fp_verdict_records_is_tp_false(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {"is_true_positive": False}),
        )
        assert calls == [("uaf-variant-3", False)]

    def test_tp_verdict_records_is_tp_true(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {"is_true_positive": True}),
        )
        assert calls == [("uaf-variant-3", True)]

    def test_non_synthesized_rule_ignored(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("cpp/overflow-buffer", {"is_true_positive": False}),
        )
        assert calls == []

    def test_no_verdict_records_nothing(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {}),
        )
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", None),
        )
        assert calls == []

    def test_missing_checker_synthesis_package_is_suppressed(
        self, monkeypatch,
    ):
        """The process_findings call site wraps the helper in
        ``suppress(OSError, ImportError)`` — an env without
        packages.checker_synthesis must degrade to "no feedback
        recorded", not crash the analysis loop on the first
        synthesized: finding. Pin the call-site contract by
        exercising the same suppression the loop uses."""
        import builtins
        import contextlib

        real_import = builtins.__import__

        def _no_checker_synthesis(name, *args, **kwargs):
            if name.startswith("packages.checker_synthesis"):
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *args, **kwargs)

        monkeypatch.delitem(
            sys.modules, "packages.checker_synthesis.library",
            raising=False,
        )
        monkeypatch.setattr(builtins, "__import__", _no_checker_synthesis)
        agent = _agent_stub()
        vuln = _vuln("synthesized:uaf-variant-3",
                     {"is_true_positive": True})
        # Bare call raises ImportError...
        try:
            agent._record_graduated_rule_feedback(vuln)
            raised = False
        except ImportError:
            raised = True
        assert raised
        # ...and the loop's suppression absorbs it.
        with contextlib.suppress(OSError, ImportError):
            agent._record_graduated_rule_feedback(vuln)

    def test_call_site_suppresses_import_error(self):
        """Source pin: the process_findings call site must include
        ImportError in its suppress (a synthesized: finding in an env
        without packages.checker_synthesis crashed the loop)."""
        src = (REPO / "packages" / "llm_analysis" / "agent.py").read_text(
            encoding="utf-8",
        )
        idx = src.index("self._record_graduated_rule_feedback(vuln)")
        window = src[max(0, idx - 700):idx]
        assert "contextlib.suppress(OSError, ImportError)" in window
