"""Deepen budget stranding is named in the run's output.

The withheld all-refuted demotions rely on the deepen pass as their
verification lane, and deepen is budget-bounded. When the stop rails
fire mid-phase — or a dispatched re-review dies on an error — the
announced re-reviews never adjudicate and the prior verdicts stand.
That stranding must be named: each stranded
verdict is stamped (``review_result["deepen_unadjudicated"]`` plus an
appended body marker) and the stamp rides into the graded findings
export.
"""

import time
from typing import Any

import core.audit.orchestrator as _orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _deepen_suspicious,
)

MARKER = "[deepen unadjudicated:"


def _outcome(
    file: str, func: str, status: str = "suspicious",
    body: str = "review prose", hypothesis: str = "hyp",
    evidence_tool: str = "",
    review_result: dict[str, Any] | None = None,
) -> ReviewOutcome:
    return ReviewOutcome(
        file=file,
        function=func,
        status=status,
        body=body,
        hypothesis=hypothesis,
        evidence_tool=evidence_tool,
        review_result=(
            {"body": body} if review_result is None else review_result
        ),
    )


def _checklist(*entries: tuple[str, str]) -> dict[str, Any]:
    files: dict[str, list[dict[str, Any]]] = {}
    for file, func in entries:
        files.setdefault(file, []).append(
            {"name": func, "line_start": 1, "line_end": 100},
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


def _fake_build_context(
    cfg: Any, gap: dict[str, Any], *a: Any, **kw: Any,
) -> dict[str, Any]:
    return {"file": gap["file"], "function": gap["name"]}


class TestDeepenUnadjudicatedStamp:
    def test_rails_exhausted_before_dispatch_stamps_every_target(
        self, monkeypatch, tmp_path,
    ):
        outcomes = [
            _outcome("a.c", "foo", hypothesis="alpha"),
            _outcome("b.c", "bar", hypothesis="beta"),
        ]
        result = OrchestratorResult(outcomes=list(outcomes), suspicious=2)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: True)

        calls: list[str] = []

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            calls.append(ctx["function"])
            return _outcome(ctx["file"], ctx["function"], "clean")

        _deepen_suspicious(
            result, _config(tmp_path), review,
            _checklist(("a.c", "foo"), ("b.c", "bar")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        assert calls == []
        for prior in outcomes:
            assert prior.review_result is not None
            assert (
                prior.review_result["deepen_unadjudicated"]
                == "budget_exhausted"
            )
            assert MARKER in prior.body
            # Appended, never prepended: body prefixes are
            # load-bearing provenance.
            assert prior.body.startswith("review prose")
            assert prior.status == "suspicious"

    def test_rails_fire_mid_phase_stamps_only_the_stranded_tail(
        self, monkeypatch, tmp_path,
    ):
        first = _outcome("a.c", "foo", hypothesis="alpha")
        second = _outcome("b.c", "bar", hypothesis="beta")
        result = OrchestratorResult(
            outcomes=[first, second], suspicious=2,
        )
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        rails = iter([False, True, True, True, True])
        monkeypatch.setattr(
            _orch, "_check_budget",
            lambda *a, **kw: next(rails, True),
        )

        calls: list[str] = []

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            calls.append(ctx["function"])
            return _outcome(ctx["file"], ctx["function"], "suspicious")

        _deepen_suspicious(
            result, _config(tmp_path), review,
            _checklist(("a.c", "foo"), ("b.c", "bar")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        assert calls == ["foo"]
        # The reviewed target was adjudicated — no stamp anywhere on
        # its replacement outcome.
        replaced = [
            o for o in result.outcomes
            if (o.file, o.function) == ("a.c", "foo")
        ]
        assert len(replaced) == 1
        assert MARKER not in (replaced[0].body or "")
        assert "deepen_unadjudicated" not in (
            replaced[0].review_result or {}
        )
        # The stranded tail is stamped.
        assert second.review_result is not None
        assert (
            second.review_result["deepen_unadjudicated"]
            == "budget_exhausted"
        )
        assert MARKER in second.body

    def test_booked_rail_reason_rides_the_stamp(
        self, monkeypatch, tmp_path,
    ):
        prior = _outcome("a.c", "foo")
        result = OrchestratorResult(outcomes=[prior], suspicious=1)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)

        def rails(
            cfg: Any, start: float, res: OrchestratorResult, **kw: Any,
        ) -> bool:
            res.terminated_by = "llm_budget_exceeded"
            return True

        monkeypatch.setattr(_orch, "_check_budget", rails)

        _deepen_suspicious(
            result, _config(tmp_path),
            lambda ctx, cfg: _outcome(ctx["file"], ctx["function"]),
            _checklist(("a.c", "foo")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        assert prior.review_result is not None
        assert (
            prior.review_result["deepen_unadjudicated"]
            == "llm_budget_exceeded"
        )
        assert "llm_budget_exceeded" in prior.body

    def test_budget_exceeded_dispatch_error_stamps_the_target(
        self, monkeypatch, tmp_path,
    ):
        from core.llm.client import LLMBudgetExceededError

        prior = _outcome("a.c", "foo")
        result = OrchestratorResult(outcomes=[prior], suspicious=1)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            raise LLMBudgetExceededError("cap reached")

        _deepen_suspicious(
            result, _config(tmp_path), review,
            _checklist(("a.c", "foo")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        assert prior.review_result is not None
        assert (
            prior.review_result["deepen_unadjudicated"]
            == "budget_exhausted"
        )
        assert MARKER in prior.body

    def test_generic_dispatch_error_stamps_dispatch_error(
        self, monkeypatch, tmp_path,
    ):
        from core.audit.findings_export import build_graded_finding

        prior = _outcome("a.c", "foo")
        result = OrchestratorResult(outcomes=[prior], suspicious=1)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            raise RuntimeError("transport reset")

        _deepen_suspicious(
            result, _config(tmp_path), review,
            _checklist(("a.c", "foo")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        assert prior.review_result is not None
        assert (
            prior.review_result["deepen_unadjudicated"]
            == "dispatch_error"
        )
        assert MARKER in prior.body
        # The stamp reason is a constant class — never the exception's
        # own text.
        assert "transport reset" not in prior.body
        assert (
            build_graded_finding(prior)["deepen_unadjudicated"]
            == "dispatch_error"
        )

    def test_completed_phase_leaves_no_stamp(self, monkeypatch, tmp_path):
        outcomes = [
            _outcome("a.c", "foo", hypothesis="alpha"),
            _outcome("b.c", "bar", hypothesis="beta"),
        ]
        result = OrchestratorResult(outcomes=list(outcomes), suspicious=2)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)

        _deepen_suspicious(
            result, _config(tmp_path),
            lambda ctx, cfg: _outcome(
                ctx["file"], ctx["function"], "suspicious",
            ),
            _checklist(("a.c", "foo"), ("b.c", "bar")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        for o in result.outcomes:
            assert "deepen_unadjudicated" not in (o.review_result or {})
            assert MARKER not in (o.body or "")

    def test_marker_is_idempotent_across_resumed_passes(self):
        from core.audit.orchestrator import _mark_deepen_unadjudicated

        prior = _outcome("a.c", "foo")
        _mark_deepen_unadjudicated(prior, "budget_exhausted")
        once = prior.body
        _mark_deepen_unadjudicated(prior, "budget_exhausted")
        assert prior.body == once
        assert prior.body.count(MARKER) == 1


class TestKeptPriorNeverStamped:
    """Adjudicated targets whose PRIOR outcome is retained stay unstamped.

    Two deepen paths keep the prior object in ``result.outcomes``
    after the re-review RAN: a bare clean flip-flop (dominated — clean
    without structured basis) and the demotion referee (probe-backed
    suspicious vs an LLM-only refutation). Both were adjudicated, so
    no unadjudicated stamp may land on them or ride the export.
    """

    def _run(
        self,
        monkeypatch: Any,
        tmp_path: Any,
        prior: ReviewOutcome,
        review: Any,
    ) -> OrchestratorResult:
        result = OrchestratorResult(outcomes=[prior], suspicious=1)
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)
        _deepen_suspicious(
            result, _config(tmp_path), review,
            _checklist(("a.c", "foo")),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )
        return result

    def test_dominated_bare_clean_keeps_prior_unstamped(
        self, monkeypatch, tmp_path,
    ):
        from core.audit.findings_export import build_graded_finding

        prior = _outcome("a.c", "foo")

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            # Bare clean flip-flop — no structured demotion basis, so
            # the prior verdict is KEPT (dominated path).
            return _outcome(ctx["file"], ctx["function"], "clean")

        result = self._run(monkeypatch, tmp_path, prior, review)

        kept = [
            o for o in result.outcomes
            if (o.file, o.function) == ("a.c", "foo")
        ]
        assert len(kept) == 1
        assert kept[0] is prior
        assert prior.status == "suspicious"
        assert "deepen_unadjudicated" not in (prior.review_result or {})
        assert MARKER not in (prior.body or "")
        assert prior.body == "review prose"
        assert "deepen_unadjudicated" not in build_graded_finding(prior)

    def test_referee_held_prior_is_unstamped(self, monkeypatch, tmp_path):
        from core.audit.findings_export import build_graded_finding

        prior = _outcome(
            "a.c", "foo", evidence_tool="smt:check-overflow",
        )

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            # LLM-only all-refuted demotion against a probe-backed
            # suspicious — the demotion referee retains the prior.
            return _outcome(
                ctx["file"], ctx["function"], "clean",
                body="all refuted",
                review_result={"all_refuted_demotion": True},
            )

        result = self._run(monkeypatch, tmp_path, prior, review)

        kept = [
            o for o in result.outcomes
            if (o.file, o.function) == ("a.c", "foo")
        ]
        assert len(kept) == 1
        assert kept[0] is prior
        assert prior.status == "suspicious"
        assert prior.review_result is not None
        # The referee path was actually taken...
        assert "demotion_referee" in prior.review_result
        # ...and an adjudicated retained prior carries no stamp.
        assert "deepen_unadjudicated" not in prior.review_result
        assert MARKER not in (prior.body or "")
        assert "deepen_unadjudicated" not in build_graded_finding(prior)


class TestSummaryLog:
    def test_summary_warning_names_exact_counts(
        self, monkeypatch, tmp_path, caplog,
    ):
        # Mixed-reason scenario: one adjudicated, one dispatched call
        # that dies on a generic error, and a rail-stranded tail — the
        # summary line must render the exact counts AND every distinct
        # reason (sorted), not just the phase stop cause.
        first = _outcome("a.c", "foo", hypothesis="alpha")
        second = _outcome("b.c", "bar", hypothesis="beta")
        third = _outcome("c.c", "baz", hypothesis="gamma")
        fourth = _outcome("d.c", "qux", hypothesis="delta")
        result = OrchestratorResult(
            outcomes=[first, second, third, fourth], suspicious=4,
        )
        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)
        rails = iter([False, False, True])
        monkeypatch.setattr(
            _orch, "_check_budget",
            lambda *a, **kw: next(rails, True),
        )

        def review(ctx: dict[str, Any], cfg: Any) -> ReviewOutcome:
            if ctx["function"] == "bar":
                raise RuntimeError("transport reset")
            return _outcome(ctx["file"], ctx["function"], "suspicious")

        with caplog.at_level("WARNING", logger="core.audit.orchestrator"):
            _deepen_suspicious(
                result, _config(tmp_path), review,
                _checklist(
                    ("a.c", "foo"), ("b.c", "bar"), ("c.c", "baz"),
                    ("d.c", "qux"),
                ),
                None, None, [], None, set(), time.time(), None,
                max_workers=1,
            )

        summaries = [
            r.getMessage() for r in caplog.records
            if "announced re-review(s) unadjudicated" in r.getMessage()
        ]
        assert summaries == [
            "deepen: 3 of 4 announced re-review(s) unadjudicated "
            "(budget_exhausted, dispatch_error) — the prior verdicts "
            "stand, with any withhold markers unresolved",
        ]


class TestDeepenStopReason:
    def test_booked_rail_wins(self):
        from core.audit.orchestrator import _deepen_stop_reason

        result = OrchestratorResult(terminated_by="max_seconds")
        assert _deepen_stop_reason(result) == "max_seconds"

    def test_unbooked_stop_is_budget_exhaustion(self):
        from core.audit.orchestrator import _deepen_stop_reason

        result = OrchestratorResult()
        assert _deepen_stop_reason(result) == "budget_exhausted"


class TestExportPassthrough:
    def test_stamp_rides_the_graded_finding(self):
        from core.audit.findings_export import build_graded_finding
        from core.audit.orchestrator import _mark_deepen_unadjudicated

        prior = _outcome("a.c", "foo")
        _mark_deepen_unadjudicated(prior, "budget_exhausted")
        finding = build_graded_finding(prior)
        assert finding["deepen_unadjudicated"] == "budget_exhausted"

    def test_unstamped_finding_exports_no_key(self):
        from core.audit.findings_export import build_graded_finding

        finding = build_graded_finding(_outcome("a.c", "foo"))
        assert "deepen_unadjudicated" not in finding
