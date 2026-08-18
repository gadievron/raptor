"""Tests for the /agentic guard-dominance pre-LLM chokepoint (P23).

Server acquisition and the dominance query are stubbed — no JVM, no
CPG, no LLM.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import core.orchestration.guard_dominance as gd
from packages.llm_analysis.agent import AutonomousSecurityAgentV2


def _agent(tmp_path):
    return AutonomousSecurityAgentV2(
        tmp_path, tmp_path / "out", prep_only=True,
    )


def _finding(reasoning="missing bounds check on `len` before memcpy"):
    return {
        "finding_id": "FIND-0001",
        "rule_id": "missing-check",
        "file": "src/parse.c",
        "function": "parse_header",
        "line": 40,
        "cwe_id": "CWE-120",
        "message": reasoning,
        "candidate_reasoning": reasoning,
    }


class TestGuardDominanceRefute:
    def test_unbindable_finding_never_probes_server(
        self, tmp_path, monkeypatch,
    ):
        agent = _agent(tmp_path)
        probes = []
        monkeypatch.setattr(
            gd, "acquire_warm_server",
            lambda *a, **kw: probes.append(a) or None,
        )
        out = agent._guard_dominance_refute(
            _finding(reasoning="integer overflow in size calc"),
        )
        assert out is None
        assert probes == []
        assert agent._gd_server_probed is False

    def test_cold_cache_returns_none_and_probes_once(
        self, tmp_path, monkeypatch,
    ):
        agent = _agent(tmp_path)
        probes = []
        monkeypatch.setattr(
            gd, "acquire_warm_server",
            lambda *a, **kw: probes.append(a) or None,
        )
        assert agent._guard_dominance_refute(_finding()) is None
        assert agent._guard_dominance_refute(_finding()) is None
        assert len(probes) == 1  # probed exactly once per run

    def test_refuted_claim_returns_receipt(self, tmp_path, monkeypatch):
        agent = _agent(tmp_path)
        fake_server = object()
        monkeypatch.setattr(
            gd, "acquire_warm_server", lambda *a, **kw: fake_server,
        )
        receipt = {"outcome": "refuted", "reason": "dominating check",
                   "dominators": []}
        seen = {}

        def fake_refute(finding, target, server, **kw):
            seen["server"] = server
            seen["target"] = target
            return receipt

        monkeypatch.setattr(gd, "refute_finding", fake_refute)
        out = agent._guard_dominance_refute(_finding())
        assert out == receipt
        assert seen["server"] is fake_server
        assert seen["target"] == Path(tmp_path)

    def test_stop_resets_probe_state(self, tmp_path, monkeypatch):
        agent = _agent(tmp_path)

        class FakeServer:
            stopped = False

            def stop(self):
                FakeServer.stopped = True

        agent._gd_server = FakeServer()
        agent._gd_server_probed = True
        agent._stop_guard_dominance_server()
        assert FakeServer.stopped
        assert agent._gd_server is None
        assert agent._gd_server_probed is False


class TestProcessFindingsWiring:
    def test_step_0d_present_with_receipt_semantics(self):
        import inspect

        import packages.llm_analysis.agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousSecurityAgentV2)
        # The chokepoint records an explicit disqualifier, feeds the
        # suppression audit trail, and skips the LLM call.
        assert "guard_dominance_refutation" in src
        assert 'verdict="guard_dominance_refuted"' in src
        assert "guard_dominance_skipped_llm_calls += 1" in src
