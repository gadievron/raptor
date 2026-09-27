"""Deepen-selection stranding is named in the run's output.

The deepen selection skips sub-floor-SLOC functions without tool
evidence and dedups identical repeat hypotheses per function; a
withheld all-refuted outcome on a tiny function can therefore stay
suspicious-unverified for the whole run. Each stranded verdict is
stamped (``review_result["deepen_stranded"]`` plus an appended body
marker) and the stamp rides into the graded findings export.
"""

import time
from typing import Any

import core.audit.orchestrator as _orch
from core.audit.orchestrator import (
    _MIN_SLOC_FOR_DEEPEN,
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _deepen_suspicious,
)

MARKER = "[deepen stranded:"


def _outcome(
    file: str, func: str, status: str = "suspicious",
    body: str = "review prose", hypothesis: str = "hyp",
    evidence_tool: str = "",
) -> ReviewOutcome:
    return ReviewOutcome(
        file=file,
        function=func,
        status=status,
        body=body,
        hypothesis=hypothesis,
        evidence_tool=evidence_tool,
        review_result={"body": body},
    )


def _checklist(*entries: tuple[str, str, int]) -> dict[str, Any]:
    files: dict[str, list[dict[str, Any]]] = {}
    for file, func, sloc in entries:
        files.setdefault(file, []).append(
            {"name": func, "line_start": 1, "line_end": 1 + sloc},
        )
    return {
        "files": [
            {"path": f, "functions": funcs} for f, funcs in files.items()
        ],
    }


def _config(tmp_path: Any) -> OrchestratorConfig:
    return OrchestratorConfig(
        target_path=tmp_path,
        out_dir=tmp_path,
        sweep_validate_findings=False,
        deepen_suspicious=True,
        enable_session_context=False,
        blind_first_pass=False,
    )


def _run_deepen(
    monkeypatch: Any,
    tmp_path: Any,
    result: OrchestratorResult,
    checklist: dict[str, Any],
) -> list[str]:
    monkeypatch.setattr(
        _orch, "_build_context",
        lambda cfg, gap, *a, **kw: {
            "file": gap["file"], "function": gap["name"],
        },
    )
    monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)
    calls: list[str] = []

    def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
        calls.append(ctx["function"])
        return _outcome(ctx["file"], ctx["function"], "suspicious")

    _deepen_suspicious(
        result, _config(tmp_path), review, checklist,
        None, None, [], None, set(), time.time(), None,
        max_workers=1,
    )
    return calls


class TestSlocFloorStranding:
    def test_tiny_function_without_evidence_is_stamped(
        self, monkeypatch, tmp_path,
    ):
        tiny = _outcome("a.c", "foo")
        result = OrchestratorResult(outcomes=[tiny], suspicious=1)
        calls = _run_deepen(
            monkeypatch, tmp_path, result,
            _checklist(("a.c", "foo", _MIN_SLOC_FOR_DEEPEN - 5)),
        )

        assert calls == []
        assert tiny.review_result is not None
        assert tiny.review_result["deepen_stranded"] == "below_sloc_floor"
        assert MARKER in tiny.body
        # Appended, never prepended: body prefixes are load-bearing.
        assert tiny.body.startswith("review prose")
        assert tiny.status == "suspicious"
        assert tiny in result.outcomes

    def test_tiny_function_with_tool_evidence_still_deepens(
        self, monkeypatch, tmp_path,
    ):
        backed = _outcome(
            "a.c", "foo", evidence_tool="smt:check-overflow",
        )
        result = OrchestratorResult(outcomes=[backed], suspicious=1)
        calls = _run_deepen(
            monkeypatch, tmp_path, result,
            _checklist(("a.c", "foo", _MIN_SLOC_FOR_DEEPEN - 5)),
        )

        assert calls == ["foo"]
        assert "deepen_stranded" not in (backed.review_result or {})
        assert MARKER not in backed.body

    def test_large_function_is_not_stamped(self, monkeypatch, tmp_path):
        big = _outcome("a.c", "foo")
        result = OrchestratorResult(outcomes=[big], suspicious=1)
        calls = _run_deepen(
            monkeypatch, tmp_path, result,
            _checklist(("a.c", "foo", _MIN_SLOC_FOR_DEEPEN + 30)),
        )

        assert calls == ["foo"]
        assert "deepen_stranded" not in (big.review_result or {})
        assert MARKER not in big.body


class TestDuplicateHypothesisStranding:
    def test_repeat_hypothesis_is_stamped(self, monkeypatch, tmp_path):
        first = _outcome("a.c", "foo", hypothesis="overflow in copy")
        repeat = _outcome("a.c", "foo", hypothesis="overflow in copy")
        result = OrchestratorResult(
            outcomes=[first, repeat], suspicious=2,
        )
        calls = _run_deepen(
            monkeypatch, tmp_path, result,
            _checklist(("a.c", "foo", _MIN_SLOC_FOR_DEEPEN + 30)),
        )

        # One deepen call for the function; the repeat is dedup'd.
        assert calls == ["foo"]
        assert repeat.review_result is not None
        assert (
            repeat.review_result["deepen_stranded"]
            == "duplicate_hypothesis"
        )
        assert MARKER in repeat.body
        assert repeat in result.outcomes

    def test_distinct_hypotheses_both_deepen(self, monkeypatch, tmp_path):
        first = _outcome("a.c", "foo", hypothesis="overflow in copy")
        second = _outcome("a.c", "foo", hypothesis="use after free")
        result = OrchestratorResult(
            outcomes=[first, second], suspicious=2,
        )
        calls = _run_deepen(
            monkeypatch, tmp_path, result,
            _checklist(("a.c", "foo", _MIN_SLOC_FOR_DEEPEN + 30)),
        )

        assert calls == ["foo", "foo"]
        for o in (first, second):
            assert "deepen_stranded" not in (o.review_result or {})
            assert MARKER not in (o.body or "")


class TestStrandingSummaryLog:
    def test_summary_info_names_exact_per_reason_counts(
        self, monkeypatch, tmp_path, caplog,
    ):
        # Asymmetric per-reason counts (2 tiny + 1 duplicate), so a
        # swap of the per-reason arguments in the log call cannot
        # render the same line.
        tiny = _outcome("a.c", "foo")
        tiny2 = _outcome("c.c", "quux")
        first = _outcome("b.c", "bar", hypothesis="overflow in copy")
        repeat = _outcome("b.c", "bar", hypothesis="overflow in copy")
        result = OrchestratorResult(
            outcomes=[tiny, tiny2, first, repeat], suspicious=4,
        )

        with caplog.at_level("INFO", logger="core.audit.orchestrator"):
            calls = _run_deepen(
                monkeypatch, tmp_path, result,
                _checklist(
                    ("a.c", "foo", _MIN_SLOC_FOR_DEEPEN - 5),
                    ("c.c", "quux", _MIN_SLOC_FOR_DEEPEN - 5),
                    ("b.c", "bar", _MIN_SLOC_FOR_DEEPEN + 30),
                ),
            )

        assert calls == ["bar"]
        summaries = [
            r.getMessage() for r in caplog.records
            if "stranded outside the deepen pass" in r.getMessage()
        ]
        assert summaries == [
            "deepen: 3 verdict(s) stranded outside the deepen pass "
            f"(2 below the {_MIN_SLOC_FOR_DEEPEN}-SLOC floor without "
            "tool evidence, 1 duplicate hypotheses) — they finish the "
            "run without a deepen re-review",
        ]


class TestStampMechanics:
    def test_marker_is_idempotent_across_resumed_passes(self):
        from core.audit.orchestrator import _mark_deepen_stranded

        o = _outcome("a.c", "foo")
        _mark_deepen_stranded(o, "below_sloc_floor")
        once = o.body
        _mark_deepen_stranded(o, "below_sloc_floor")
        assert o.body == once
        assert o.body.count(MARKER) == 1

    def test_marker_names_the_floor(self):
        from core.audit.orchestrator import _mark_deepen_stranded

        o = _outcome("a.c", "foo")
        _mark_deepen_stranded(o, "below_sloc_floor")
        assert f"{_MIN_SLOC_FOR_DEEPEN}-SLOC" in o.body


class TestExportPassthrough:
    def test_stamp_rides_the_graded_finding(self):
        from core.audit.findings_export import build_graded_finding
        from core.audit.orchestrator import _mark_deepen_stranded

        o = _outcome("a.c", "foo")
        _mark_deepen_stranded(o, "below_sloc_floor")
        finding = build_graded_finding(o)
        assert finding["deepen_stranded"] == "below_sloc_floor"

    def test_unstamped_finding_exports_no_key(self):
        from core.audit.findings_export import build_graded_finding

        finding = build_graded_finding(_outcome("a.c", "foo"))
        assert "deepen_stranded" not in finding
