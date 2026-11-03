"""Transcript adoption on the /audit surface — behaviour-neutrality
and record/replay end-to-end.

Three contracts:

1. **Record-off differential**: with no ``RAPTOR_LLM_TRANSCRIPT`` in
   the environment, the seam-constructed clients are functionally
   identical to the pre-adoption bare constructions — exact
   ``LLMClient`` type (never the transcript subclass), same config /
   pinning / budget wiring, and an injected budget client still wins.
2. **Record-on neutrality**: with recording active, the corpus
   phase-2 classification produces byte-identical verdicts to the
   same run without recording — the transcript is a side trail, never
   a behaviour input.
3. **Record → replay e2e**: a phase-2 run under record mode
   materialises the transcript with one subject-tagged entry per
   finding; replaying it through the same code path with NO stub
   transport reproduces the exact verdicts (work-queue order reversed,
   so subject matching is exercised), at zero cost and with provider
   dispatch structurally impossible.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from core.audit.corpus import run_corpus
from core.json.jsonl import load_jsonl
from core.llm.client import LLMClient
from core.llm.providers import StructuredResponse
from core.llm.transcript import (
    TranscriptLLMClient,
    reset_active_transcript,
)


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch):
    """Every test starts with no ambient transcript session."""
    monkeypatch.delenv("RAPTOR_LLM_TRANSCRIPT", raising=False)
    reset_active_transcript()
    yield
    reset_active_transcript()


def _finding(fid: str) -> dict:
    return {
        "function_id": fid,
        "expected": "finding",
        "actual": "suspicious",
        "hypothesis": f"bounds check missing in {fid}",
        "match": False,
    }


def _stub_generate_structured(self, prompt, schema, *, system_prompt=None,
                              task_type=None, **kwargs):
    """Deterministic transport stub, keyed on prompt content so a
    replay that served the WRONG finding's response would flip a
    verdict instead of passing silently."""
    security = "sec.c" in prompt
    result = {
        "classification": (
            "security_finding" if security else "quality_finding"
        ),
        "is_security": security,
        "primitive": "write" if security else "none",
        "rationale": "stub verdict",
    }
    return StructuredResponse(
        result=result, raw=json.dumps(result), cost=0.0125,
        tokens_used=64, model="stub-model", provider="stub",
        duration=0.0,
    )


def _run_phase2(findings):
    run_corpus._run_phase2_classify(findings)
    return [
        (
            r["function_id"],
            r["phase2_classification"],
            r["phase2_is_security"],
            r["phase2_primitive"],
        )
        for r in findings
    ]


# ---------------------------------------------------------------------------
# 1. Record-off differential
# ---------------------------------------------------------------------------

class TestRecordOffIdentity:
    def test_pipeline_builder_returns_plain_client(self, monkeypatch):
        # Route self-serve is orthogonal (own test file); keep it a
        # no-op so this pin is hermetic.
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/stub-route.sock")
        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        client, _models, _primary = _make_llm_client(
            AuditPipelineOpts(max_cost_usd=7.5),
        )
        assert type(client) is LLMClient
        assert client.config.max_cost_per_scan == 7.5

    def test_orchestrator_fallback_returns_plain_client(self):
        from core.audit.orchestrator import _run_llm_client

        client = _run_llm_client(
            SimpleNamespace(llm_budget_client=None, models=[]),
        )
        assert type(client) is LLMClient

    def test_orchestrator_budget_client_still_wins(self):
        from core.audit.orchestrator import _run_llm_client

        budget = object()
        client = _run_llm_client(
            SimpleNamespace(llm_budget_client=budget, models=[]),
        )
        assert client is budget

    def test_phase2_constructs_plain_client(self, monkeypatch):
        seen: list[object] = []
        real = LLMClient.generate_structured

        def spy(self, *a, **kw):
            seen.append(self)
            return _stub_generate_structured(self, *a, **kw)

        monkeypatch.setattr(LLMClient, "generate_structured", spy)
        assert real is not spy
        _run_phase2([_finding("src/sec.c:parse")])
        assert seen and type(seen[0]) is LLMClient


# ---------------------------------------------------------------------------
# 2 + 3. Record-on neutrality and record → replay e2e
# ---------------------------------------------------------------------------

class TestRecordReplayE2E:
    FINDINGS = [
        _finding("src/sec.c:parse"),
        _finding("src/util.c:fmt"),
        _finding("src/sec.c:decode"),
    ]

    def test_recording_is_behaviour_neutral_and_replay_is_hermetic(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(
            LLMClient, "generate_structured", _stub_generate_structured,
        )

        # --- record OFF: the before-adoption behaviour baseline ---
        baseline = _run_phase2(copy.deepcopy(self.FINDINGS))

        # --- record ON: same stub, recording active ---
        path = tmp_path / "llm-transcript.jsonl"
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"record:{path}")
        reset_active_transcript()
        recorded_run = _run_phase2(copy.deepcopy(self.FINDINGS))
        assert recorded_run == baseline, (
            "recording changed phase-2 verdicts — the transcript must "
            "be a side trail, never a behaviour input"
        )

        # The transcript materialised: one subject-tagged
        # generate_structured entry per finding.
        assert path.is_file()
        entries = load_jsonl(path)
        assert len(entries) == len(self.FINDINGS)
        assert {e["method"] for e in entries} == {"generate_structured"}
        assert [e["subject"] for e in entries] == [
            f["function_id"] for f in self.FINDINGS
        ]

        # --- replay: no stub, no provider, queue reversed ---
        monkeypatch.setattr(
            LLMClient, "generate_structured",
            _boom_generate_structured,
        )
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
        reset_active_transcript()
        replay_findings = list(reversed(copy.deepcopy(self.FINDINGS)))
        run_corpus._run_phase2_classify(replay_findings)
        by_fid = {
            r["function_id"]: (
                r["function_id"],
                r["phase2_classification"],
                r["phase2_is_security"],
                r["phase2_primitive"],
            )
            for r in replay_findings
        }
        assert [by_fid[fid] for fid, *_ in baseline] == baseline, (
            "replay verdicts diverged from the recorded run"
        )
        # Zero errors: every call was served from the transcript.
        assert not any(r.get("phase2_error") for r in replay_findings)

    def test_replay_provider_dispatch_is_structurally_blocked(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(
            LLMClient, "generate_structured", _stub_generate_structured,
        )
        path = tmp_path / "llm-transcript.jsonl"
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"record:{path}")
        reset_active_transcript()
        _run_phase2(copy.deepcopy(self.FINDINGS))

        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
        reset_active_transcript()
        from core.llm.transcript import TranscriptError, build_llm_client

        client = build_llm_client()
        assert isinstance(client, TranscriptLLMClient)
        with pytest.raises(TranscriptError, match="forbidden"):
            client._get_provider(client.config.primary_model)


def _boom_generate_structured(self, *a, **kw):  # pragma: no cover - guard
    raise AssertionError(
        "live dispatch attempted during transcript replay"
    )
