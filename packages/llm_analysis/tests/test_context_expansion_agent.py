"""--context-expansion on the sequential classifier path.

End-to-end through ``analyze_vulnerability`` on a namespace agent
(the sibling pattern of test_deep_validate_sequential): the trigger →
expanded re-run → join pipeline, the per-run rails with honest
parsed-count probes in both directions, the flag-off / no-trigger
differentials (byte-identical finding records, exactly one LLM
call), the distinct transcript subject on the second call, the
expanded window actually reaching the second prompt, and hostile
bytes in expansion content staying escaped at the prompt egress.
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
from packages.llm_analysis.context_expansion import (  # noqa: E402
    EXPANDED_FINDING_CONTEXT_LINES,
)

_N_LINES = 260
_FINDING_LINE = 130


class _QueueLLM:
    """External-LLM stand-in returning queued responses; records the
    prompt and the transcript subject in effect for each call."""

    def __init__(self, responses: list[dict]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    def generate_structured(self, **kwargs):
        if not self._responses:
            raise AssertionError("unexpected extra LLM call")
        self.calls.append({
            "prompt": kwargs.get("prompt", ""),
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


def _abstained() -> dict:
    # A well-formed response whose verdict bools are missing:
    # response validation nulls them (read_verdict -> None) — the
    # real "abstention" shape the agent stores. Prose fields are
    # populated so the response clears the quality-retry threshold
    # (a SPARSE degraded response belongs to that seam, not to
    # expansion).
    return {
        "reasoning": "cannot tell without more context",
        "attack_scenario": "unclear",
        "prerequisites": ["unknown"],
        "impact": "unclear",
        "vuln_type": "buffer_overflow",
        "cwe_id": "CWE-120",
        "dataflow_summary": "unclear",
        "remediation": "bounds check",
        "severity_assessment": "medium",
        "exploitability_score": 0.5,
        "confidence": "medium",
    }


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


def _agent(tmp_path: Path, llm: _QueueLLM, *, context_expansion: bool):
    agent = SimpleNamespace(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        llm=llm,
        llm_config=None,
        use_verified_exemplars=False,
        deep_validate=False,
        deep_validate_disabled=False,
        context_expansion=context_expansion,
        _expansion_stats={
            "expansions_triggered": 0,
            "expansions_performed": 0,
            "expansions_changed_verdict": 0,
            "skipped_cap": 0,
            "errors": 0,
        },
    )
    agent.out_dir.mkdir(exist_ok=True)
    agent._prompt_budget = lambda: 0
    agent._get_verified_outcomes = lambda: ()
    agent._tier1_pre_flight = lambda _v: "no_check"
    agent.validate_dataflow = lambda _v: {}
    agent.analyze_vulnerability = (
        AutonomousSecurityAgentV2.analyze_vulnerability.__get__(
            agent, type(agent),
        )
    )
    agent._expand_context_and_rerun = (
        AutonomousSecurityAgentV2._expand_context_and_rerun.__get__(
            agent, type(agent),
        )
    )
    return agent


class TestExpansionRerun:
    def test_low_confidence_expands_and_more_confident_replaces(
        self, tmp_path,
    ):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low", exploitable=False),
            _analysis("high", exploitable=True),
        ])
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path)
        assert agent.analyze_vulnerability(vuln) is True

        assert len(llm.calls) == 2
        record = vuln.analysis["context_expansion"]
        assert record["triggered"] is True
        assert record["reason"] == "low_confidence"
        assert record["replaced"] is True
        assert record["window_lines"] == EXPANDED_FINDING_CONTEXT_LINES
        assert record["first_verdict"]["is_exploitable"] is False
        assert record["first_verdict"]["confidence"] == "low"
        assert record["second_verdict"]["is_exploitable"] is True
        assert record["second_verdict"]["confidence"] == "high"
        # The settled verdict is the second's.
        assert vuln.exploitable is True
        assert vuln.exploitability_score == pytest.approx(0.8)
        # Parsed counts.
        assert agent._expansion_stats == {
            "expansions_triggered": 1,
            "expansions_performed": 1,
            "expansions_changed_verdict": 1,
            "skipped_cap": 0,
            "errors": 0,
        }

    def test_abstained_first_verdict_expands(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _abstained(),
            _analysis("low", exploitable=True),
        ])
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)
        record = vuln.analysis["context_expansion"]
        assert record["reason"] == "verdict_abstained"
        # A full verdict at any stated confidence replaces an
        # abstention.
        assert record["replaced"] is True
        assert vuln.exploitable is True

    def test_not_more_confident_second_keeps_first_verdict(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low", exploitable=True),
            _analysis("low", exploitable=False),
        ])
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)
        record = vuln.analysis["context_expansion"]
        assert record["replaced"] is False
        # First verdict stands, with the expansion recorded as
        # evidence.
        assert vuln.exploitable is True
        assert vuln.analysis["confidence"] == "low"
        assert agent._expansion_stats["expansions_changed_verdict"] == 0
        assert agent._expansion_stats["expansions_performed"] == 1

    def test_second_prompt_carries_expanded_window(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low"),
            _analysis("high"),
        ])
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path)
        agent.analyze_vulnerability(vuln)
        # A marker outside the base window but inside the expanded
        # one: base shows +-FINDING_CONTEXT_LINES, the re-run twice
        # that.
        just_outside = _FINDING_LINE + (
            EXPANDED_FINDING_CONTEXT_LINES // 2 + 10
        )
        marker = f"marker_line_{just_outside:04d}"
        assert marker not in llm.calls[0]["prompt"]
        assert marker in llm.calls[1]["prompt"]

    def test_distinct_transcript_subject_on_expansion_call(self, tmp_path):
        _write_target(tmp_path)
        llm = _QueueLLM([
            _analysis("low"),
            _analysis("high"),
        ])
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path, fid="F42")
        agent.analyze_vulnerability(vuln)
        assert llm.calls[0]["subject"] == "F42"
        assert llm.calls[1]["subject"] == "F42::context-expansion"

    def test_expansion_failure_keeps_first_verdict_and_counts(
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
        agent = _agent(tmp_path, llm, context_expansion=True)
        vuln = _make_vuln(tmp_path)
        assert agent.analyze_vulnerability(vuln) is True
        # First verdict stands; the failure is recorded, never silent.
        assert vuln.exploitable is True
        assert vuln.error is None
        record = vuln.analysis["context_expansion"]
        assert record["performed"] is True
        assert "error" in record
        assert agent._expansion_stats["errors"] == 1
        assert agent._expansion_stats["expansions_changed_verdict"] == 0


class TestRails:
    def _run_two_uncertain(self, tmp_path, cap: int) -> SimpleNamespace:
        _write_target(tmp_path)
        responses = [_analysis("low")]
        if cap >= 1:
            responses.append(_analysis("high"))
        responses.append(_analysis("low"))
        if cap >= 2:
            responses.append(_analysis("high"))
        llm = _QueueLLM(responses)
        agent = _agent(tmp_path, llm, context_expansion=True)
        with patch(
            "packages.llm_analysis.context_expansion."
            "MAX_EXPANSIONS_PER_RUN", cap,
        ):
            agent.analyze_vulnerability(_make_vuln(tmp_path, "F1"))
            self._second = _make_vuln(tmp_path, "F2")
            agent.analyze_vulnerability(self._second)
        return agent

    def test_at_cap_second_trigger_is_counted_not_expanded(self, tmp_path):
        agent = self._run_two_uncertain(tmp_path, cap=1)
        stats = agent._expansion_stats
        assert stats["expansions_triggered"] == 2
        assert stats["expansions_performed"] == 1
        assert stats["skipped_cap"] == 1
        # The capped finding carries an explicit skip record.
        record = self._second.analysis["context_expansion"]
        assert record["performed"] is False
        assert record["skipped"] == "expansion_cap"

    def test_one_above_cap_both_expand(self, tmp_path):
        # Revert probe: raising the cap by one flips the parsed
        # counts — the rail is live, not decorative.
        agent = self._run_two_uncertain(tmp_path, cap=2)
        stats = agent._expansion_stats
        assert stats["expansions_triggered"] == 2
        assert stats["expansions_performed"] == 2
        assert stats["skipped_cap"] == 0

    def test_cap_zero_disables_all_expansions(self, tmp_path):
        agent = self._run_two_uncertain(tmp_path, cap=0)
        stats = agent._expansion_stats
        assert stats["expansions_performed"] == 0
        assert stats["skipped_cap"] == 2


class TestDifferentials:
    def _run(self, tmp_path, subdir: str, *, flag: bool) -> tuple:
        repo = tmp_path / subdir
        repo.mkdir()
        _write_target(repo)
        llm = _QueueLLM([_analysis("high", exploitable=True)])
        agent = _agent(repo, llm, context_expansion=flag)
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
        # The persisted finding record is byte-identical.
        d_off = json.dumps(vuln_off.to_dict(), sort_keys=True)
        d_on = json.dumps(vuln_on.to_dict(), sort_keys=True)
        assert d_off == d_on
        assert "context_expansion" not in vuln_on.analysis
        # Counted-never-silent: the flag-on run reports all zeros.
        assert all(v == 0 for v in agent_on._expansion_stats.values())

    def test_flag_off_never_expands_even_when_uncertain(self, tmp_path):
        repo = tmp_path / "u"
        repo.mkdir()
        _write_target(repo)
        llm = _QueueLLM([_analysis("low")])
        agent = _agent(repo, llm, context_expansion=False)
        vuln = _make_vuln(repo)
        agent.analyze_vulnerability(vuln)
        assert len(llm.calls) == 1
        assert "context_expansion" not in vuln.analysis


class TestHostileBytesAtPromptEgress:
    def test_expansion_content_is_escaped_in_the_bundle(self, tmp_path):
        # Expanded re-runs carry MORE target text: a wider window and
        # 1-hop callee bodies. Both must pass the existing envelope
        # chokepoint — raw ESC / C1 / bidi bytes never reach the
        # prompt.
        from packages.llm_analysis.context_expansion import (
            expansion_context_blocks,
        )
        from packages.llm_analysis.prompts import (
            build_analysis_prompt_bundle,
        )
        hostile = "\x1b]0;pwned\x07 ‮evil‬ \x9b31m"
        (tmp_path / "callee.c").write_text(
            f"int helper_0(void) {{ /* {hostile} */ return 0; }}\n"
        )
        context_map = {
            "call_edges": [
                {
                    "caller": "entry",
                    "caller_file": "vuln.c",
                    "callee": "target_fn",
                    "callee_file": "vuln.c",
                },
                {
                    "caller": "target_fn",
                    "caller_file": "vuln.c",
                    "callee": "helper_0",
                    "callee_file": "callee.c",
                },
            ],
        }
        (tmp_path / "vuln.c").write_text(
            f"void entry(void) {{ target_fn(s); /* {hostile} */ }}\n"
            "void target_fn(char *s) { strcpy(buf, s); }\n"
        )
        blocks = expansion_context_blocks(
            None, "vuln.c", "target_fn", tmp_path,
            context_map=context_map,
        )
        assert blocks, "expansion blocks must resolve for this probe"
        assert any(hostile_part in b.content
                   for b in blocks for hostile_part in ("\x1b", "‮"))

        bundle = build_analysis_prompt_bundle(
            rule_id="cpp/unbounded-write",
            level="error",
            file_path="vuln.c",
            start_line=2,
            end_line=2,
            message="strcpy into fixed buffer",
            code="strcpy(buf, s);",
            surrounding_context=f"context {hostile} context",
            extra_blocks=blocks,
        )
        user = next(m.content for m in bundle.messages if m.role == "user")
        for raw in ("\x1b", "\x07", "\x9b", "‮", "‬"):
            assert raw not in user
        # The content survives in escaped form rather than being
        # dropped.
        assert "\\x1b" in user


class TestRunReportStats:
    def _prep_agent(self, tmp_path, *, context_expansion: bool):
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
                context_expansion=context_expansion,
            )

    def test_report_block_present_iff_flag_on(self, tmp_path):
        report_on = self._prep_agent(
            tmp_path, context_expansion=True,
        ).process_findings(sarif_paths=[], emit_journal=False)
        assert report_on["context_expansion"] == {
            "expansions_triggered": 0,
            "expansions_performed": 0,
            "expansions_changed_verdict": 0,
            "skipped_cap": 0,
            "errors": 0,
        }
        report_off = self._prep_agent(
            tmp_path, context_expansion=False,
        ).process_findings(sarif_paths=[], emit_journal=False)
        assert "context_expansion" not in report_off

    def test_constructor_stores_flag(self, tmp_path):
        agent = self._prep_agent(tmp_path, context_expansion=True)
        assert agent.context_expansion is True
        assert self._prep_agent(
            tmp_path, context_expansion=False,
        ).context_expansion is False


class TestCliWiring:
    def test_analyze_cli_defines_and_threads_the_flag(self):
        import inspect
        src = inspect.getsource(agent_mod.main)
        assert '"--context-expansion"' in src
        assert "context_expansion=args.context_expansion" in src

    def test_agentic_forwards_only_on_sequential(self):
        root = Path(__file__).resolve().parents[3]
        src = (root / "raptor_agentic.py").read_text(encoding="utf-8")
        assert '"--context-expansion"' in src
        # Forwarding is gated on --sequential (the orchestrated path
        # does not consume the flag).
        gate = src.split('analysis_cmd.append("--context-expansion")')[0]
        assert gate.rstrip().endswith("if args.sequential:")
