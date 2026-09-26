"""--context-toolloop on the sequential classifier path.

End-to-end through ``analyze_vulnerability`` on a namespace agent
(the sibling pattern of test_context_expansion_agent): the trigger →
request-loop → join pipeline, per-turn transcript subjects, the
forced base-schema verdict on the final turn, the shared budget with
--context-expansion (parsed-count probes in both directions), the
flag-off / no-trigger differentials (byte-identical finding records,
exactly one LLM call), served results reaching the next turn's
prompt, the degenerate always-requesting model, honest performed
semantics, and a record→replay transcript round trip.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.agent as agent_mod  # noqa: E402
from core.llm.transcript import current_subject  # noqa: E402
from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)
from packages.llm_analysis.context_toolloop import (  # noqa: E402
    CONTEXT_REQUESTS_FIELD,
    MAX_TOOLLOOP_TURNS,
)

_N_LINES = 260
_FINDING_LINE = 130


class _QueueLLM:
    """External-LLM stand-in returning queued responses; records the
    prompt, schema and transcript subject in effect for each call."""

    def __init__(self, responses: list[dict]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    def generate_structured(self, **kwargs):
        if not self._responses:
            raise AssertionError("unexpected extra LLM call")
        self.calls.append({
            "prompt": kwargs.get("prompt", ""),
            "schema": kwargs.get("schema", {}),
            "subject": current_subject(),
        })
        return dict(self._responses.pop(0)), "raw response"


def _analysis(confidence: str = "high", exploitable: bool = False,
              tp: bool = True) -> dict:
    return {
        "is_true_positive": tp,
        "is_exploitable": exploitable,
        "exploitability_score": 0.8 if exploitable else 0.2,
        "reasoning": "solid reasoning",
        "severity_assessment": "high",
        "confidence": confidence,
    }


def _requesting(requests: list[dict]) -> dict:
    # A request turn: verdict fields absent (the model is asking, not
    # answering), the request list riding the augmented schema field.
    return {
        "reasoning": "need the caller context to decide",
        "confidence": "low",
        CONTEXT_REQUESTS_FIELD: requests,
    }


def _span(start: int, end: int, file: str = "vuln.c") -> dict:
    return {"tool": "read_span", "file": file, "start": start, "end": end}


def _write_target(repo: Path) -> None:
    lines = [f"int marker_line_{i:04d};" for i in range(1, _N_LINES + 1)]
    lines[_FINDING_LINE - 1] = "strcpy(buf, s); /* finding */"
    (repo / "vuln.c").write_text("\n".join(lines) + "\n")


def _make_vuln(repo: Path, fid: str = "F1") -> VulnerabilityContext:
    finding = {
        "finding_id": fid,
        "rule_id": "cpp/unbounded-write",
        "file": "vuln.c",
        "startLine": _FINDING_LINE,
        "endLine": _FINDING_LINE,
        "message": "strcpy into fixed buffer",
        "level": "error",
        "has_dataflow": False,
        "metadata": {"name": "target_fn"},
    }
    return VulnerabilityContext(finding, repo)


def _agent(tmp_path: Path, llm, *, context_toolloop: bool,
           context_expansion: bool = False):
    agent = SimpleNamespace(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        llm=llm,
        llm_config=None,
        use_verified_exemplars=False,
        deep_validate=False,
        deep_validate_disabled=False,
        context_expansion=context_expansion,
        context_toolloop=context_toolloop,
        _expansion_stats={
            "expansions_triggered": 0,
            "expansions_performed": 0,
            "expansions_changed_verdict": 0,
            "skipped_cap": 0,
            "errors": 0,
        },
        _toolloop_stats={
            "loops_triggered": 0,
            "loops_performed": 0,
            "loops_changed_verdict": 0,
            "skipped_cap": 0,
            "errors": 0,
            "turns_performed": 0,
            "tool_calls_served": 0,
            "tool_calls_refused": 0,
            "turn_cap_hits": 0,
            "byte_cap_hits": 0,
        },
    )
    agent.out_dir.mkdir(exist_ok=True)
    agent._prompt_budget = lambda: 0
    agent._get_verified_outcomes = lambda: ()
    agent._tier1_pre_flight = lambda _v: "no_check"
    agent.validate_dataflow = lambda _v: {}
    for name in (
        "analyze_vulnerability",
        "_toolloop_and_rerun",
        "_expand_context_and_rerun",
    ):
        setattr(agent, name, getattr(
            AutonomousSecurityAgentV2, name,
        ).__get__(agent, type(agent)))
    return agent


class TestToolLoopRerun:
    def test_request_then_verdict_replaces_when_more_confident(
        self, tmp_path,
    ):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low", exploitable=False),          # base pass
            _requesting([_span(1, 20)]),                  # turn 1
            _analysis("high", exploitable=True),          # turn 2 verdict
        ])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path, "F42")
        assert agent.analyze_vulnerability(vuln) is True

        assert len(llm.calls) == 3
        # Per-turn transcript subjects.
        assert llm.calls[0]["subject"] == "F42"
        assert llm.calls[1]["subject"] == "F42::toolloop::turn1"
        assert llm.calls[2]["subject"] == "F42::toolloop::turn2"
        # The served span reaches the NEXT turn's prompt.
        assert "marker_line_0007" not in llm.calls[1]["prompt"]
        assert "7: int marker_line_0007;" in llm.calls[2]["prompt"]
        # Request turns carry the augmented schema; the model asked
        # and the loop continued.
        assert CONTEXT_REQUESTS_FIELD in llm.calls[1]["schema"]

        record = vuln.analysis["context_toolloop"]
        assert record["triggered"] is True
        assert record["reason"] == "low_confidence"
        assert record["end_reason"] == "verdict"
        assert record["replaced"] is True
        assert record["first_verdict"]["confidence"] == "low"
        assert record["final_verdict"]["confidence"] == "high"
        assert record["turns"] == [{
            "turn": 1,
            "requests": [{
                "tool": "read_span", "status": "served",
                "target": "vuln.c:1-20",
                "result_bytes": record["turns"][0]["requests"][0][
                    "result_bytes"
                ],
            }],
        }]
        assert record["total_result_bytes"] > 0
        # The request field never rides the persisted analysis.
        assert CONTEXT_REQUESTS_FIELD not in vuln.analysis
        assert vuln.exploitable is True
        assert agent._toolloop_stats == {
            "loops_triggered": 1,
            "loops_performed": 1,
            "loops_changed_verdict": 1,
            "skipped_cap": 0,
            "errors": 0,
            "turns_performed": 2,
            "tool_calls_served": 1,
            "tool_calls_refused": 0,
            "turn_cap_hits": 0,
            "byte_cap_hits": 0,
        }

    def test_immediate_verdict_uses_one_turn(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low"),
            _analysis("high"),  # turn 1: verdict straight away
        ])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)
        assert len(llm.calls) == 2
        record = vuln.analysis["context_toolloop"]
        assert record["end_reason"] == "verdict"
        assert record["turns"] == []
        assert agent._toolloop_stats["turns_performed"] == 1

    def test_degenerate_requester_hits_turn_cap_and_dedup(self, tmp_path):
        # A model that requests the SAME span every turn: the second
        # request is refused as a duplicate, the final turn forces the
        # base schema (no context_requests field), and the loop ends
        # in a verdict at the turn cap.
        _write_target(tmp_path)
        responses = [_analysis("low")]
        responses += [
            _requesting([_span(1, 10)])
            for _ in range(MAX_TOOLLOOP_TURNS - 1)
        ]
        responses.append(_analysis("medium", exploitable=False))
        llm = _QueueLLM(responses)
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)

        assert len(llm.calls) == 1 + MAX_TOOLLOOP_TURNS
        final = llm.calls[-1]
        assert CONTEXT_REQUESTS_FIELD not in final["schema"]
        assert final["subject"] == f"F1::toolloop::turn{MAX_TOOLLOOP_TURNS}"
        record = vuln.analysis["context_toolloop"]
        assert record["end_reason"] == "turn_cap"
        stats = agent._toolloop_stats
        assert stats["turn_cap_hits"] == 1
        assert stats["tool_calls_served"] == 1
        assert stats["tool_calls_refused"] == MAX_TOOLLOOP_TURNS - 2
        refusals = [
            r for t in record["turns"] for r in t["requests"]
            if r["status"] == "refused"
        ]
        assert all(r["reason"] == "duplicate_request" for r in refusals)
        # The duplicate refusal note reaches the next prompt so the
        # model can course-correct.
        assert "duplicate_request" in llm.calls[-1]["prompt"]

    def test_byte_budget_exhaustion_forces_the_verdict(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low"),
            _requesting([_span(1, 20)]),   # turn 1: serve, budget gone
            _analysis("high"),             # turn 2: forced verdict
        ])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        with patch(
            "packages.llm_analysis.context_toolloop."
            "TOOLLOOP_MAX_TOTAL_BYTES", 1,
        ):
            agent.analyze_vulnerability(vuln)
        assert len(llm.calls) == 3
        # Turn 2 closed the request channel: base schema.
        assert CONTEXT_REQUESTS_FIELD not in llm.calls[2]["schema"]
        record = vuln.analysis["context_toolloop"]
        assert record["end_reason"] == "byte_cap"
        assert agent._toolloop_stats["byte_cap_hits"] == 1

    def test_not_more_confident_final_keeps_first_verdict(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low", exploitable=True),
            _requesting([_span(1, 5)]),
            _analysis("low", exploitable=False),
        ])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        original_context = None
        agent.analyze_vulnerability(vuln)
        record = vuln.analysis["context_toolloop"]
        assert record["replaced"] is False
        assert vuln.exploitable is True
        assert vuln.analysis["confidence"] == "low"
        assert agent._toolloop_stats["loops_changed_verdict"] == 0
        # The standing verdict's window is restored (rendered on the
        # ORIGINAL context, so the persisted context matches it).
        del original_context
        marker = f"marker_line_{_FINDING_LINE + 60:04d}"
        assert marker not in (vuln.surrounding_context or "")

    def test_transport_failure_keeps_first_verdict_and_counts(
        self, tmp_path,
    ):
        _write_target(tmp_path)

        class _FailsSecond(_QueueLLM):
            def generate_structured(self, **kwargs):
                if self.calls:
                    self.calls.append({"subject": current_subject()})
                    raise RuntimeError("transport down")
                return super().generate_structured(**kwargs)

        llm = _FailsSecond([_analysis("low", exploitable=True)])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        assert agent.analyze_vulnerability(vuln) is True
        assert vuln.exploitable is True
        assert vuln.error is None
        record = vuln.analysis["context_toolloop"]
        # The failed call WAS issued — performed is honest-True.
        assert record["performed"] is True
        assert "error" in record
        stats = agent._toolloop_stats
        assert stats["errors"] == 1
        assert stats["loops_performed"] == 1
        assert stats["loops_changed_verdict"] == 0

    def test_precall_failure_is_not_performed(self, tmp_path):
        # Same honest-counter contract as the expansion: a failure
        # BEFORE any loop LLM call (the expanded re-read) is counted
        # as an error, never as a performed loop.
        _write_target(tmp_path)
        llm = _QueueLLM([_analysis("low", exploitable=True)])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        original = vuln.read_vulnerable_code

        def _failing_reread(*args, **kwargs):
            if kwargs.get("context_lines"):
                return False
            return original(*args, **kwargs)

        vuln.read_vulnerable_code = _failing_reread
        assert agent.analyze_vulnerability(vuln) is True
        record = vuln.analysis["context_toolloop"]
        assert record["performed"] is False
        assert "error" in record
        stats = agent._toolloop_stats
        assert stats["loops_performed"] == 0
        assert stats["turns_performed"] == 0
        assert stats["errors"] == 1
        assert len(llm.calls) == 1

    def test_late_failure_folds_served_exactly_once(self, tmp_path):
        # A failure AFTER the verdict turn (post-serve, e.g. the CVSS
        # derivation) must not fold state.served/refused into the run
        # stats twice: the fold lives in a finally block and runs
        # exactly once on every exit path, success and failure alike.
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low", exploitable=True),
            _requesting([_span(120, 140)]),
            _analysis("high", exploitable=True),
        ])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        import packages.cvss as cvss
        real = cvss.score_finding
        calls = {"n": 0}

        def _flaky(d):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("late failure after the serve")
            return real(d)

        with patch("packages.cvss.score_finding", new=_flaky):
            assert agent.analyze_vulnerability(vuln) is True
        stats = agent._toolloop_stats
        assert stats["tool_calls_served"] == 1
        assert stats["tool_calls_refused"] == 0
        assert stats["errors"] == 1
        # First verdict stands, annotated with the counted failure.
        record = vuln.analysis["context_toolloop"]
        assert record["performed"] is True
        assert "error" in record


class TestSupersedesExpansion:
    def test_both_flags_on_runs_the_loop_not_the_expansion(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low"),
            _analysis("high"),
        ])
        agent = _agent(
            tmp_path, llm, context_toolloop=True, context_expansion=True,
        )
        vuln = _make_vuln(tmp_path, "F9")
        agent.analyze_vulnerability(vuln)
        assert "context_toolloop" in vuln.analysis
        assert "context_expansion" not in vuln.analysis
        subjects = [c["subject"] for c in llm.calls]
        assert subjects == ["F9", "F9::toolloop::turn1"]
        assert agent._expansion_stats["expansions_triggered"] == 0

    def test_loop_flag_alone_triggers_without_expansion_flag(
        self, tmp_path,
    ):
        _write_target(tmp_path)
        llm = _QueueLLM([_analysis("low"), _analysis("high")])
        agent = _agent(tmp_path, llm, context_toolloop=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)
        assert "context_toolloop" in vuln.analysis


class TestSharedBudget:
    def _run_two_uncertain(self, tmp_path, cap: int,
                           pre_spent_expansions: int = 0) -> SimpleNamespace:
        _write_target(tmp_path)
        responses = [_analysis("low")]
        if cap - pre_spent_expansions >= 1:
            responses.append(_analysis("high"))
        responses.append(_analysis("low"))
        if cap - pre_spent_expansions >= 2:
            responses.append(_analysis("high"))
        llm = _QueueLLM(responses)
        agent = _agent(tmp_path, llm, context_toolloop=True)
        agent._expansion_stats["expansions_performed"] = pre_spent_expansions
        with patch(
            "packages.llm_analysis.context_expansion."
            "MAX_EXPANSIONS_PER_RUN", cap,
        ):
            agent.analyze_vulnerability(_make_vuln(tmp_path, "F1"))
            self._second = _make_vuln(tmp_path, "F2")
            agent.analyze_vulnerability(self._second)
        return agent

    def test_at_cap_second_trigger_is_counted_not_looped(self, tmp_path):
        agent = self._run_two_uncertain(tmp_path, cap=1)
        stats = agent._toolloop_stats
        assert stats["loops_triggered"] == 2
        assert stats["loops_performed"] == 1
        assert stats["skipped_cap"] == 1
        record = self._second.analysis["context_toolloop"]
        assert record["performed"] is False
        assert record["skipped"] == "expansion_cap"

    def test_one_above_cap_both_loop(self, tmp_path):
        # Revert probe: raising the cap by one flips the parsed
        # counts — the rail is live, not decorative.
        agent = self._run_two_uncertain(tmp_path, cap=2)
        stats = agent._toolloop_stats
        assert stats["loops_performed"] == 2
        assert stats["skipped_cap"] == 0

    def test_expansion_spend_consumes_the_shared_budget(self, tmp_path):
        # Slots already burned by --context-expansion count against
        # the loop: the budget is SHARED, not additive.
        agent = self._run_two_uncertain(
            tmp_path, cap=1, pre_spent_expansions=1,
        )
        stats = agent._toolloop_stats
        assert stats["loops_performed"] == 0
        assert stats["skipped_cap"] == 2

    def test_loop_spend_consumes_the_expansion_budget(self, tmp_path):
        # Symmetric direction: slots burned by the tool loop count
        # against --context-expansion too. Trigger-site supersession
        # keeps the features from co-running on one finding today,
        # but the cap check is the same on both sides so a future
        # loop→expansion fallback can never double-spend the budget.
        _write_target(tmp_path)
        llm = _QueueLLM([_analysis("low")])
        agent = _agent(
            tmp_path, llm, context_toolloop=False, context_expansion=True,
        )
        agent._toolloop_stats["loops_performed"] = 1
        with patch(
            "packages.llm_analysis.context_expansion."
            "MAX_EXPANSIONS_PER_RUN", 1,
        ):
            vuln = _make_vuln(tmp_path)
            agent.analyze_vulnerability(vuln)
        stats = agent._expansion_stats
        assert stats["expansions_triggered"] == 1
        assert stats["expansions_performed"] == 0
        assert stats["skipped_cap"] == 1
        record = vuln.analysis["context_expansion"]
        assert record["performed"] is False
        assert record["skipped"] == "expansion_cap"


class TestDifferentials:
    def _run(self, tmp_path, subdir: str, *, flag: bool) -> tuple:
        repo = tmp_path / subdir
        repo.mkdir()
        _write_target(repo)
        llm = _QueueLLM([_analysis("high", exploitable=True)])
        agent = _agent(repo, llm, context_toolloop=flag)
        vuln = _make_vuln(repo)
        assert agent.analyze_vulnerability(vuln) is True
        return llm, vuln, agent

    def test_confident_verdict_is_byte_identical_flag_on_vs_off(
        self, tmp_path,
    ):
        llm_off, vuln_off, _ = self._run(tmp_path, "off", flag=False)
        llm_on, vuln_on, agent_on = self._run(tmp_path, "on", flag=True)
        # Exactly one LLM call either way — zero added cost.
        assert len(llm_off.calls) == 1
        assert len(llm_on.calls) == 1
        d_off = json.dumps(vuln_off.to_dict(), sort_keys=True)
        d_on = json.dumps(vuln_on.to_dict(), sort_keys=True)
        assert d_off == d_on
        assert "context_toolloop" not in vuln_on.analysis
        # Counted-never-silent: the flag-on run reports all zeros.
        assert all(v == 0 for v in agent_on._toolloop_stats.values())

    def test_flag_off_never_loops_even_when_uncertain(self, tmp_path):
        repo = tmp_path / "u"
        repo.mkdir()
        _write_target(repo)
        llm = _QueueLLM([_analysis("low")])
        agent = _agent(repo, llm, context_toolloop=False)
        vuln = _make_vuln(repo)
        agent.analyze_vulnerability(vuln)
        assert len(llm.calls) == 1
        assert "context_toolloop" not in vuln.analysis


class TestRunReportStats:
    def _prep_agent(self, tmp_path, *, context_toolloop: bool):
        mock_availability = MagicMock()
        mock_availability.external_llm = False
        mock_availability.claude_code = True
        with patch(
            "packages.llm_analysis.agent.detect_llm_availability",
            return_value=mock_availability,
        ):
            return agent_mod.AutonomousSecurityAgentV2(
                repo_path=tmp_path,
                out_dir=tmp_path / "out",
                prep_only=True,
                synthesise_checkers=False,
                context_toolloop=context_toolloop,
            )

    def test_report_block_present_iff_flag_on(self, tmp_path):
        report_on = self._prep_agent(
            tmp_path, context_toolloop=True,
        ).process_findings(sarif_paths=[], emit_journal=False)
        assert report_on["context_toolloop"] == {
            "loops_triggered": 0,
            "loops_performed": 0,
            "loops_changed_verdict": 0,
            "skipped_cap": 0,
            "errors": 0,
            "turns_performed": 0,
            "tool_calls_served": 0,
            "tool_calls_refused": 0,
            "turn_cap_hits": 0,
            "byte_cap_hits": 0,
        }
        report_off = self._prep_agent(
            tmp_path, context_toolloop=False,
        ).process_findings(sarif_paths=[], emit_journal=False)
        assert "context_toolloop" not in report_off

    def test_constructor_stores_flag(self, tmp_path):
        agent = self._prep_agent(tmp_path, context_toolloop=True)
        assert agent.context_toolloop is True
        assert self._prep_agent(
            tmp_path, context_toolloop=False,
        ).context_toolloop is False


class TestTranscriptRoundTrip:
    """The loop's per-turn subjects make record/replay deterministic:
    a recorded multi-turn loop replays byte-for-byte with no provider
    constructed and zero cost."""

    @pytest.fixture(autouse=True)
    def _fresh_session(self, monkeypatch, tmp_path_factory):
        from core.llm.client import LLMClient
        from core.llm.transcript import reset_active_transcript

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

    def test_record_then_replay_multi_turn_loop(self, tmp_path, monkeypatch):
        from core.json.jsonl import load_jsonl
        from core.llm.config import LLMConfig, ModelConfig
        from core.llm.transcript import (
            TranscriptLLMClient,
            TranscriptRecorder,
            build_llm_client,
            reset_active_transcript,
        )

        _write_target(tmp_path)
        transcript = tmp_path / "llm-transcript.jsonl"

        queue = [
            _analysis("low", exploitable=False),
            _requesting([_span(1, 10)]),
            _analysis("high", exploitable=True),
        ]

        class _StubProvider:
            def __init__(self) -> None:
                self.total_cost = 0.0
                self.total_tokens = 0
                self.total_input_tokens = 0
                self.total_output_tokens = 0
                self.total_cache_read_tokens = 0
                self.total_cache_write_tokens = 0
                self.total_duration = 0.0
                self.call_count = 0

            def generate_structured(self, prompt, schema,
                                    system_prompt=None, **kwargs):
                return dict(queue.pop(0)), "raw"

        config = LLMConfig(
            primary_model=ModelConfig(
                provider="anthropic", model_name="test-model-stub",
                api_key="k",
            ),
            enable_caching=False,
            enable_fallback=False,
            enable_cost_tracking=False,
            max_retries=1,
        )

        # ---- Phase 1: RECORD the loop against the stub provider.
        record_client = TranscriptLLMClient(
            config, session=TranscriptRecorder(transcript),
        )
        provider = _StubProvider()
        record_client._get_provider = lambda model_config: provider
        record_client.providers["anthropic:test-model-stub"] = provider
        agent = _agent(tmp_path, record_client, context_toolloop=True)
        vuln = _make_vuln(tmp_path, "F7")
        assert agent.analyze_vulnerability(vuln) is True
        record_verdict = (
            vuln.exploitable,
            vuln.analysis["confidence"],
            vuln.analysis["context_toolloop"]["end_reason"],
        )
        assert record_verdict == (True, "high", "verdict")

        entries = load_jsonl(transcript)
        assert [e["subject"] for e in entries] == [
            "F7", "F7::toolloop::turn1", "F7::toolloop::turn2",
        ]

        # ---- Phase 2: REPLAY with NO provider configured.
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{transcript}")
        reset_active_transcript()
        replay_client = build_llm_client(
            LLMConfig(primary_model=None, fallback_models=[]),
        )
        assert isinstance(replay_client, TranscriptLLMClient)
        replay_agent = _agent(
            tmp_path, replay_client, context_toolloop=True,
        )
        replay_vuln = _make_vuln(tmp_path, "F7")
        assert replay_agent.analyze_vulnerability(replay_vuln) is True
        assert (
            replay_vuln.exploitable,
            replay_vuln.analysis["confidence"],
            replay_vuln.analysis["context_toolloop"]["end_reason"],
        ) == record_verdict
        assert replay_client.providers == {}
        assert replay_client.total_cost == 0.0
        assert replay_client.transcript_session.misses == []


class TestCliWiring:
    def test_analyze_cli_defines_and_threads_the_flag(self):
        import inspect
        src = inspect.getsource(agent_mod.main)
        assert '"--context-toolloop"' in src
        assert "context_toolloop=args.context_toolloop" in src
        # The /analyze console summary surfaces the loop counters
        # (the eval protocol reads them).
        assert 'report.get("context_toolloop")' in src

    def test_agentic_forwards_only_on_sequential(self):
        root = Path(__file__).resolve().parents[3]
        src = (root / "raptor_agentic.py").read_text(encoding="utf-8")
        assert '"--context-toolloop"' in src
        # Forwarding is gated on --sequential (the orchestrated path
        # does not consume the flag).
        gate = src.split('analysis_cmd.append("--context-toolloop")')[0]
        assert gate.rstrip().endswith("if args.sequential:")
