"""Acceptance test: the /analyze classification loop replays a frozen
LLM transcript end-to-end.

Phase 1 records a real ``process_findings`` run against a stub
provider (existing fake-client pattern — no live LLM anywhere) into a
transcript. Phase 2 rebuilds the agent with NO provider configured and
replays the same loop from the transcript, asserting the verdicts come
back identical and deterministic, with zero providers constructed and
zero cost. This is the hermetic-CI eval contract for
``core.llm.transcript``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.agent as agent_mod  # noqa: E402
from core.json.jsonl import load_jsonl  # noqa: E402
from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.llm.transcript import (  # noqa: E402
    TranscriptLLMClient,
    TranscriptRecorder,
    TranscriptReplayer,
    build_llm_client,
    reset_active_transcript,
)


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch, tmp_path_factory):
    """Ambient-state isolation: no inherited transcript session, no
    LLM response cache (and its HMAC key confined to a tmp
    XDG_DATA_HOME), no scorecard sidecar writes — same conventions as
    core/llm/tests/conftest.py, local here because this is the one
    module in this tree that constructs real LLMClients."""
    from core.llm.client import LLMClient

    monkeypatch.delenv("RAPTOR_LLM_TRANSCRIPT", raising=False)
    monkeypatch.setenv("RAPTOR_LLM_CACHE", "off")
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )
    monkeypatch.setattr(
        LLMClient, "flush_usage_to_scorecard",
        lambda self, **kwargs: None,
    )
    reset_active_transcript()
    yield
    reset_active_transcript()


# ---------------------------------------------------------------------------
# Fixtures: repo, findings, stub provider
# ---------------------------------------------------------------------------

def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "auth.c").write_text(
        "".join(f"int line{i};\n" for i in range(1, 60))
    )
    (repo / "src" / "db.c").write_text(
        "".join(f"int dbline{i};\n" for i in range(1, 60))
    )
    return repo


def _findings() -> list[dict]:
    return [
        {
            "finding_id": "F1",
            "rule_id": "c.lang.security.strcpy",
            "message": "strcpy into fixed buffer",
            "file": "src/auth.c",
            "startLine": 42,
            "endLine": 42,
            "snippet": "strcpy(buf, input);",
            "level": "error",
            "cwe_id": "CWE-120",
            "tool": "semgrep",
            "has_dataflow": False,
            "dataflow_path": None,
            "metadata": {"name": "check_pw"},
        },
        {
            "finding_id": "F2",
            "rule_id": "c.lang.security.sprintf",
            "message": "sprintf with external format",
            "file": "src/db.c",
            "startLine": 30,
            "endLine": 30,
            "snippet": "sprintf(q, fmt);",
            "level": "warning",
            "cwe_id": "CWE-134",
            "tool": "semgrep",
            "has_dataflow": False,
            "dataflow_path": None,
            "metadata": {"name": "run_query"},
        },
    ]


# Both verdicts non-exploitable so the loop stops at classification
# (no exploit/patch stages — those are out of this test's scope).
_F1_ANALYSIS = {
    "is_true_positive": True,
    "is_exploitable": False,
    "exploitability_score": 0.2,
    "confidence": "high",
    "severity_assessment": "medium",
    "reasoning": "real bug, bounded caller makes it unexploitable",
    "attack_scenario": "none identified",
    "vuln_type": "buffer overflow",
}
_F2_ANALYSIS = {
    "is_true_positive": False,
    "is_exploitable": False,
    "exploitability_score": 0.0,
    "confidence": "high",
    "severity_assessment": "low",
    "reasoning": "format string is a compile-time constant",
    "attack_scenario": "none identified",
    "vuln_type": "format string",
}


class _StubProvider:
    """Deterministic canned-verdict provider (record phase only)."""

    def __init__(self) -> None:
        self.calls = 0
        # Counter surface get_stats/telemetry read off any provider.
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.total_duration = 0.0
        self.call_count = 0

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **kwargs):
        self.calls += 1
        if "strcpy" in prompt:
            return (dict(_F1_ANALYSIS), "raw-f1")
        return (dict(_F2_ANALYSIS), "raw-f2")


def _stub_config() -> LLMConfig:
    return LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model-stub", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=False,
        max_retries=1,
    )


def _make_agent(tmp_path: Path, repo: Path, out_name: str):
    mock_availability = MagicMock()
    mock_availability.external_llm = False
    mock_availability.claude_code = True
    with patch(
        "packages.llm_analysis.agent.detect_llm_availability",
        return_value=mock_availability,
    ):
        return agent_mod.AutonomousSecurityAgentV2(
            repo_path=repo,
            out_dir=tmp_path / out_name,
            prep_only=True,
            synthesise_checkers=False,
            generate_exploits=False,
            generate_patches=False,
            verify_exploits=False,
            use_verified_exemplars=False,
        )


def _run_loop(agent, monkeypatch, findings: list[dict]) -> dict:
    """Drive process_findings with hermetic collaborators."""
    import core.sage.hooks as hooks
    import packages.llm_analysis.source_intel_inject as sii

    # Source-intel priming shells out to coccinelle/spatch across the
    # fixture repo (~7s of subprocesses) and is orthogonal to the
    # transcript seam under test; evidence_blocks_for_finding
    # degrades to () on an unprimed cache by contract. Mocked so the
    # acceptance test stays under the CI per-test duration guard.
    monkeypatch.setattr(sii, "prepare_source_intel", lambda *a, **k: None)
    monkeypatch.setattr(
        hooks, "recall_prior_finding_verdict", lambda *a, **k: None,
    )
    monkeypatch.setattr(
        hooks, "store_finding_verdict", lambda *a, **k: False,
    )
    monkeypatch.setattr(
        agent_mod, "parse_sarif_findings", lambda _p: list(findings),
    )
    monkeypatch.setattr(agent_mod, "deduplicate_findings", lambda fs: fs)
    return agent.process_findings(
        sarif_paths=["fake.sarif"], checklist=None, emit_journal=False,
    )


def _verdicts(report: dict) -> dict[str, tuple]:
    out = {}
    for rec in report["results"]:
        analysis = rec.get("analysis") or {}
        out[rec["finding_id"]] = (
            analysis.get("is_true_positive"),
            analysis.get("is_exploitable"),
            analysis.get("reasoning"),
            rec.get("exploitable"),
            rec.get("status"),
        )
    return out


# ---------------------------------------------------------------------------
# The acceptance test
# ---------------------------------------------------------------------------

class TestAnalyzeReplayEndToEnd:
    def test_record_then_replay_is_hermetic_and_deterministic(
        self, tmp_path, monkeypatch,
    ):
        repo = _make_repo(tmp_path)
        transcript = tmp_path / "llm-transcript.jsonl"

        # ---- Phase 1: RECORD a real run against the stub provider.
        record_agent = _make_agent(tmp_path, repo, "out-record")
        record_client = TranscriptLLMClient(
            _stub_config(), session=TranscriptRecorder(transcript),
        )
        provider = _StubProvider()
        record_client._get_provider = lambda model_config: provider
        record_client.providers["anthropic:test-model-stub"] = provider
        record_agent.llm = record_client
        record_agent.llm_config = record_client.config

        record_report = _run_loop(record_agent, monkeypatch, _findings())
        record_verdicts = _verdicts(record_report)
        assert record_verdicts["F1"][0] is True     # true positive
        assert record_verdicts["F2"][0] is False    # false positive
        assert provider.calls == 2

        entries = load_jsonl(transcript)
        assert [e["method"] for e in entries] == ["generate_structured"] * 2
        assert {e["subject"] for e in entries} == {"F1", "F2"}

        # ---- Phase 2: REPLAY through a fresh agent with NO provider
        # configured (the hermetic-CI shape: no credentials at all).
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{transcript}")
        reset_active_transcript()
        for run_idx in (1, 2):  # twice: determinism
            replay_agent = _make_agent(tmp_path, repo, f"out-replay{run_idx}")
            replay_client = build_llm_client(
                LLMConfig(primary_model=None, fallback_models=[]),
            )
            assert isinstance(replay_client, TranscriptLLMClient)
            replay_agent.llm = replay_client
            replay_agent.llm_config = replay_client.config

            # Reversed queue order: subject-keyed matching must not
            # depend on the recorded sequence.
            replay_report = _run_loop(
                replay_agent, monkeypatch, list(reversed(_findings())),
            )
            assert _verdicts(replay_report) == record_verdicts
            # Incapable of network/cost: no provider ever constructed,
            # nothing spent, nothing missed.
            assert replay_client.providers == {}
            assert replay_client.total_cost == 0.0
            assert replay_client.transcript_session.misses == []
            reset_active_transcript()
            monkeypatch.setenv(
                "RAPTOR_LLM_TRANSCRIPT", f"replay:{transcript}",
            )

    def test_replay_miss_is_loud_and_never_dispatches(
        self, tmp_path, monkeypatch,
    ):
        """A finding with no recorded entry lands as an error-status
        record carrying the miss report (the loop's uniform error
        contract) — and the replayer's miss ledger lets a harness
        fail the whole eval. No provider exists to fall back to."""
        repo = _make_repo(tmp_path)
        transcript = tmp_path / "llm-transcript.jsonl"

        record_agent = _make_agent(tmp_path, repo, "out-record")
        record_client = TranscriptLLMClient(
            _stub_config(), session=TranscriptRecorder(transcript),
        )
        provider = _StubProvider()
        record_client._get_provider = lambda model_config: provider
        record_client.providers["anthropic:test-model-stub"] = provider
        record_agent.llm = record_client
        record_agent.llm_config = record_client.config
        _run_loop(record_agent, monkeypatch, _findings()[:1])  # F1 only

        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{transcript}")
        reset_active_transcript()
        replay_agent = _make_agent(tmp_path, repo, "out-replay")
        replay_client = build_llm_client(
            LLMConfig(primary_model=None, fallback_models=[]),
        )
        replay_agent.llm = replay_client
        replay_agent.llm_config = replay_client.config

        report = _run_loop(replay_agent, monkeypatch, _findings())  # F1+F2
        verdicts = _verdicts(report)
        assert verdicts["F1"][0] is True
        f2 = next(r for r in report["results"] if r["finding_id"] == "F2")
        assert f2.get("status") == "error"
        assert "transcript replay miss" in (f2.get("error") or "")
        session = replay_client.transcript_session
        assert isinstance(session, TranscriptReplayer)
        assert len(session.misses) == 1
        assert replay_client.providers == {}

    def test_agent_constructor_takes_llm_branch_in_replay_mode(
        self, tmp_path, monkeypatch,
    ):
        """With replay active and NO external LLM available, the agent
        constructor builds a replay TranscriptLLMClient instead of
        degrading to prep-only — the constructor-path contract the
        eval harness relies on."""
        repo = _make_repo(tmp_path)
        transcript = tmp_path / "llm-transcript.jsonl"
        TranscriptRecorder(transcript)
        from core.llm.providers import LLMResponse
        TranscriptRecorder(transcript).record_generate(
            "p", None, "analyse", {},
            LLMResponse(
                content="x", model="m", provider="anthropic",
                tokens_used=1, cost=0.0, finish_reason="stop",
            ),
        )
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{transcript}")
        reset_active_transcript()

        mock_availability = MagicMock()
        mock_availability.external_llm = False
        mock_availability.claude_code = False
        with patch(
            "packages.llm_analysis.agent.detect_llm_availability",
            return_value=mock_availability,
        ):
            agent = agent_mod.AutonomousSecurityAgentV2(
                repo_path=repo,
                out_dir=tmp_path / "out",
                synthesise_checkers=False,
            )
        assert isinstance(agent.llm, TranscriptLLMClient)
        assert agent.llm.transcript_session.mode == "replay"
        assert agent.llm_config is agent.llm.config
        # A primary model always exists — the autodetected transport
        # when the host has one, else the inert "replay" placeholder —
        # so the constructor's banner/budget paths keep working. Either
        # way replay intercepts before model resolution: the recorded
        # answer is served and no provider is ever constructed.
        assert agent.llm_config.primary_model is not None
        assert agent.llm.generate("p", task_type="analyse").content == "x"
        assert agent.llm.providers == {}
