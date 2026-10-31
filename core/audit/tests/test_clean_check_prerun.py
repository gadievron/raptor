"""Clean-check pre-run: the rescue's mechanical flow sweep runs at
context-assembly time for the clean-check population, surfacing the
flows in the FIRST review prompt — a clean verdict then needs no
second full review call. The rescue keeps its behaviour when the
pre-run could not run (CPG pending at dispatch, blind first pass)."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    review_one_function,
)
from core.audit.refinement import (
    MIN_SLOC_CLEAN_CHECK,
    build_flow_preview_prompt,
    clean_check_applicable,
    should_clean_check,
)
from core.audit.shared_state import SharedState
from core.evidence import EvidenceRecord

_SOURCE_LINES = ["int acl_worker(char *buf, size_t len) {"] + [
    f"    slot[{i}] = buf[{i}];" for i in range(24)
] + ["    memcpy(out, buf, len);", "    return 0;", "}"]
_SOURCE = "\n".join(_SOURCE_LINES) + "\n"
_SLOC = len(_SOURCE_LINES)


class _FakeFlow:
    source_param = "buf"
    sink_call = "memcpy"


def _outcome(status: str = "clean") -> ReviewOutcome:
    return ReviewOutcome(file="a.c", function="f", status=status, body="b")


class TestGateShape:
    """The qualification gate is the rescue's, verbatim — the pre-run
    shares it minus the verdict."""

    def test_deep_dive_qualifies(self):
        assert clean_check_applicable("deep_dive", False, False, sloc=50)

    def test_entry_point_qualifies(self):
        assert clean_check_applicable("investigate", True, False, sloc=50)

    def test_sink_qualifies(self):
        assert clean_check_applicable("investigate", False, True, sloc=50)

    def test_plain_investigate_does_not_qualify(self):
        assert not clean_check_applicable("investigate", False, False, sloc=50)

    def test_sloc_floor(self):
        assert not clean_check_applicable(
            "deep_dive", True, True, sloc=MIN_SLOC_CLEAN_CHECK - 1,
        )
        assert clean_check_applicable(
            "deep_dive", False, False, sloc=MIN_SLOC_CLEAN_CHECK,
        )

    def test_zero_sloc_passes_floor(self):
        assert clean_check_applicable("deep_dive", False, False, sloc=0)

    def test_should_clean_check_still_requires_clean(self):
        assert should_clean_check(_outcome("clean"), "deep_dive",
                                  False, False, sloc=50)
        assert not should_clean_check(_outcome("suspicious"), "deep_dive",
                                      False, False, sloc=50)
        assert not should_clean_check(_outcome("clean"), "investigate",
                                      False, False, sloc=50)


class TestFlowPreviewPrompt:
    def test_carries_flows_with_first_call_framing(self):
        text = build_flow_preview_prompt("- Joern CPG: `buf` flows to `memcpy()`")
        assert "Mechanical flow sweep" in text
        assert "buf" in text and "memcpy" in text
        assert "Address each flow explicitly" in text
        # The rescue's post-verdict framing must not leak into the
        # first prompt — no clean verdict exists yet.
        assert "You marked this function clean" not in text

    def test_renders_as_prompt_section(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.c", "function": "acl_worker",
            "line_start": 1, "line_end": _SLOC, "source": _SOURCE,
            "flow_preview": build_flow_preview_prompt("- flow x"),
        }
        prompt = format_context_for_prompt(ctx)
        assert "## Mechanical flow sweep" in prompt
        assert "- flow x" in prompt


def _setup_target(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text(_SOURCE)
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "a.c",
                "items": [{
                    "name": "acl_worker", "line_start": 1,
                    "line_end": _SLOC,
                }],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _gap(**kw):
    g = {
        "file": "a.c",
        "name": "acl_worker",
        "line_start": 1,
        "line_end": _SLOC,
        "sloc": _SLOC,
        "kind": "function",
    }
    g.update(kw)
    return g


class TestReviewLoopPrerun:
    """End-to-end through review_one_function with a stub review_fn."""

    def _run(self, tmp_path, gap, *, with_flows=True, blind=False,
             monkeypatch=None):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            prefilter=False, max_refinements=0,
            blind_first_pass=blind,
        )
        evidence_index: dict[str, EvidenceRecord] = {}
        if with_flows:
            rec = EvidenceRecord(file="a.c", function="acl_worker")
            rec.joern_flows = [_FakeFlow()]
            evidence_index["a.c:acl_worker"] = rec
        shared = SharedState(
            checklist={"files": [{
                "path": "a.c",
                "items": [{
                    "name": "acl_worker", "line_start": 1,
                    "line_end": _SLOC,
                }],
            }]},
            evidence_index=evidence_index,
            entry_points={"a.c:acl_worker"},
        )
        result = OrchestratorResult()
        seen: list[dict] = []

        sweep_calls: list[str] = []
        if monkeypatch is not None:
            import core.audit.orchestrator as orch
            real = orch._clean_check_flows

            def counting(file_path, function_name, index=None):
                sweep_calls.append(f"{file_path}:{function_name}")
                return real(file_path, function_name, index)

            monkeypatch.setattr(orch, "_clean_check_flows", counting)

        def review_fn(ctx, cfg):
            seen.append(dict(ctx))
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="reviewed",
            )

        outcome = review_one_function(gap, shared, config, review_fn, result)
        return outcome, seen, result, sweep_calls

    def test_prerun_injects_flows_and_suppresses_rescue(
        self, tmp_path, monkeypatch,
    ):
        outcome, seen, result, sweep_calls = self._run(
            tmp_path, _gap(), monkeypatch=monkeypatch,
        )
        assert outcome.status == "clean"
        # One review call only: the flows were in the first prompt.
        assert len(seen) == 1
        assert "flow_preview" in seen[0]
        assert "memcpy" in seen[0]["flow_preview"]
        assert result.clean_check_preruns == 1
        assert result.clean_checks == 1
        assert result.clean_check_rescues == 0
        # No duplicate sweep on the clean path: the rescue consumed
        # the pre-run's result instead of re-reading the index.
        assert sweep_calls == ["a.c:acl_worker"]

    def test_rescue_fires_when_cpg_was_pending(self, tmp_path):
        outcome, seen, result, _ = self._run(
            tmp_path, _gap(_joern_pending=True),
        )
        # Pre-run skipped; the post-verdict rescue runs the sweep and
        # fires the second review call, exactly as before.
        assert len(seen) == 2
        assert "flow_preview" not in seen[0]
        assert "clean_check" in seen[1]
        assert "memcpy" in seen[1]["clean_check"]
        assert result.clean_check_preruns == 0
        assert result.clean_checks == 1

    def test_blind_first_pass_keeps_rescue(self, tmp_path):
        outcome, seen, result, _ = self._run(
            tmp_path, _gap(), blind=True,
        )
        # Blind passes withhold mechanical evidence from the first
        # prompt — the pre-run must not leak it there.
        assert len(seen) == 2
        assert "flow_preview" not in seen[0]
        assert "clean_check" in seen[1]
        assert result.clean_check_preruns == 0

    def test_prerun_without_flows_skips_rescue_call(self, tmp_path):
        outcome, seen, result, _ = self._run(
            tmp_path, _gap(), with_flows=False,
        )
        # Sweep ran pre-review and found nothing; the rescue re-read
        # would find the same nothing — one call either way.
        assert len(seen) == 1
        assert "flow_preview" not in seen[0]
        assert result.clean_check_preruns == 0
        assert result.clean_checks == 1

    def test_non_qualifying_function_gets_no_prerun(self, tmp_path):
        gap = _gap(sloc=MIN_SLOC_CLEAN_CHECK - 1)
        outcome, seen, result, _ = self._run(tmp_path, gap)
        assert len(seen) == 1
        assert "flow_preview" not in seen[0]
        assert result.clean_check_preruns == 0
        assert result.clean_checks == 0

    def test_rescue_merge_still_promotes(self, tmp_path):
        """When the rescue fires (CPG was pending) and the second call
        revises the verdict, the merge behaves as before."""
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            prefilter=False, max_refinements=0,
            immediate_verify=False,
        )
        rec = EvidenceRecord(file="a.c", function="acl_worker")
        rec.joern_flows = [_FakeFlow()]
        shared = SharedState(
            checklist={"files": [{
                "path": "a.c",
                "items": [{
                    "name": "acl_worker", "line_start": 1,
                    "line_end": _SLOC,
                }],
            }]},
            evidence_index={"a.c:acl_worker": rec},
            entry_points={"a.c:acl_worker"},
        )
        result = OrchestratorResult()
        calls: list[dict] = []

        def review_fn(ctx, cfg):
            calls.append(dict(ctx))
            status = "suspicious" if "clean_check" in ctx else "clean"
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status=status, body="reviewed",
                hypothesis="unbounded memcpy of buf" if status != "clean" else "",
            )

        outcome = review_one_function(
            _gap(_joern_pending=True), shared, config, review_fn, result,
        )
        assert len(calls) == 2
        assert outcome.status == "suspicious"
        assert result.clean_check_rescues == 1
