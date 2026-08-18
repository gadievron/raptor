"""Cross-run verdict reuse: fold eligibility + $0 outcome import.

Zero LLM calls. The fold side reuses the hash-verification fixtures
from the gap-folding tests; the import side drives
``import_reused_verdicts`` with fake collectors and stubbed sweeps.
"""

from __future__ import annotations

from core.audit.gaps import compute_gaps
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult
from core.audit.strategy import strategies_from_item
from core.audit.verdict_reuse import import_reused_verdicts, outcome_from_entry
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 1,
    "line_end": 5,
}


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_ITEM)],
        }],
    }


def _current_strategies():
    return sorted(strategies_from_item(dict(_ITEM), "auth.c"))


def _entry(target, **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": hash_span(target / "auth.c", 1, 5),
        "line_start": 1,
        "line_end": 5,
        "strategies": _current_strategies(),
        "model": "model-a",
        "body": "prior review body",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _project_with(tmp_path, entry):
    project = tmp_path / "project"
    run_dir = project / entry.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    append_entry(run_dir, entry)
    merge_into_index(project, run_dir)
    return project


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestFoldReuseEligibility:
    def test_eligible_entry_lands_in_sink_and_stays_covered(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].verdict == "clean"

    def test_findings_are_reusable_too(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, verdict="finding"),
        )
        sink: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink["auth.c:check_pw"].verdict == "finding"

    def test_hash_mismatch_never_in_sink(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, source_hash="0" * 16),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_legacy_entry_without_hash_suppressed_not_reused(self, tmp_path):
        # No hash evidence → historical silent suppression, no import.
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, source_hash=""))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_context_reduced_verdict_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, context_reduced=True),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps), (
            "a reduced-context verdict is lower-confidence — with "
            "reuse enabled it must re-review, not stay suppressed"
        )

    def test_error_verdict_never_reused(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, verdict="error"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_model_change_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, model="model-a"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-b",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_default_model_run_cannot_compare_and_reuses(self, tmp_path):
        # Current run on the default/session model: no stable name to
        # compare against — the model gate is skipped (documented).
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, model="model-a"))
        sink: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model=None,
        )
        assert "auth.c:check_pw" in sink

    def test_strategy_change_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path,
            _entry(target, strategies=["some_retired_strategy"]),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_reuse_disabled_keeps_plain_fold(self, tmp_path):
        # reuse_sink=None (--no-verdict-reuse): hash-verified entries
        # suppress silently, exactly the pre-reuse behaviour — even
        # ones reuse would have screened out (context_reduced).
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, context_reduced=True),
        )
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestOutcomeFromEntry:
    def test_fields(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(
            target, verdict="finding", cwe="CWE-787",
            hypotheses=[{"mechanism": "unchecked memcpy", "confidence": "high"}],
            evidence_tools=["semgrep:rule-x"],
        )
        outcome = outcome_from_entry(entry)
        assert outcome.status == "finding"
        assert outcome.reused is True
        assert outcome.reused_from_run == "run1"
        assert outcome.cost_usd == 0.0
        assert outcome.evidence_tool == "journal:recall:run1"
        assert outcome.hypothesis == "unchecked memcpy"
        assert outcome.review_result["reused"] is True
        assert outcome.review_result["cwe"] == "CWE-787"
        assert outcome.review_result["prior_evidence_tools"] == ["semgrep:rule-x"]
        assert "reused: verdict imported from run run1" in outcome.body
        assert "prior review body" in outcome.body

    def test_origin_propagates_through_reuse_chains(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(
            target, run_id="run3", reused=True, reused_from_run="run1",
        )
        outcome = outcome_from_entry(entry)
        assert outcome.reused_from_run == "run1", (
            "a reused entry re-imported later must keep pointing at "
            "the run that actually reviewed"
        )

    def test_reused_finding_is_not_tool_backed(self, tmp_path):
        # No live tool receipt: tools_dispatched is empty and the
        # evidence is journal:recall — compute_tier must cap at
        # llm_only, never inherit TOOL_BACKED from the dead receipt.
        target = _write_target(tmp_path)
        entry = _entry(
            target, verdict="finding",
            evidence_tools=["semgrep:rule-x"],
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        outcome = outcome_from_entry(entry)
        assert outcome.compute_tier() == "llm_only"


class _Collector:
    def __init__(self):
        self.submitted = []

    def submit(self, outcome, gap, **kwargs):
        self.submitted.append((outcome, gap))


def _config(tmp_path, **over) -> OrchestratorConfig:
    defaults = {
        "target_path": tmp_path / "target",
        "out_dir": tmp_path / "out",
        "sweep_validate_findings": False,
        "validate": False,
        "prefilter": False,
    }
    defaults.update(over)
    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(**defaults)


class TestImportReusedVerdicts:
    def test_imports_tally_and_journal(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )
        target = _write_target(tmp_path)
        clean = _entry(target)
        finding = _entry(
            target, function="other_fn", verdict="finding",
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        collector = _Collector()
        result = OrchestratorResult()
        reviewed_outcomes: dict = {}

        n = import_reused_verdicts(
            {"auth.c:check_pw": clean, "auth.c:other_fn": finding},
            _config(tmp_path),
            result,
            collector=collector,
            reviewed_outcomes=reviewed_outcomes,
        )

        assert n == 2
        assert result.reused_from_prior == 2
        assert result.reviewed == 0, "imports are not reviews"
        assert result.clean == 1
        assert result.findings == 1
        assert result.total_cost_usd == 0.0
        assert len(result.outcomes) == 2
        assert len(collector.submitted) == 2
        assert reviewed_outcomes["auth.c:check_pw"].status == "clean"
        gap = collector.submitted[0][1]
        assert gap["line_start"] == 1
        assert gap["line_end"] == 5

    def test_reused_finding_reenters_sweeps(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch

        swept = []

        def _fake_sweep(outcome, config, sarif_cache=None, **kwargs):
            swept.append(outcome.function)
            outcome.status = "suspicious"  # tools no longer confirm
            return outcome

        monkeypatch.setattr(orch, "_sweep_validate", _fake_sweep)
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )

        target = _write_target(tmp_path)
        finding = _entry(
            target, verdict="finding",
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": finding},
            _config(tmp_path, sweep_validate_findings=True),
            result,
            collector=_Collector(),
        )
        assert n == 1
        assert swept == ["check_pw"]
        assert result.sweep_demoted == 1
        assert result.findings == 0
        assert result.suspicious == 1

    def test_clean_does_not_enter_sweeps(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch

        def _boom(*a, **k):
            raise AssertionError("sweep must not run for clean reuse")

        monkeypatch.setattr(orch, "_sweep_validate", _boom)
        target = _write_target(tmp_path)
        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": _entry(target)},
            _config(tmp_path, sweep_validate_findings=True),
            result,
            collector=_Collector(),
        )
        assert n == 1
        assert result.clean == 1

    def test_journal_records_reuse_provenance(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )
        from core.audit.collector import Collector
        from core.coverage.journal import load_entries

        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        collector = Collector(
            out_dir=out_dir, target_path=target, run_id="run9",
        )
        result = OrchestratorResult()
        import_reused_verdicts(
            {"auth.c:check_pw": _entry(target)},
            _config(tmp_path, target_path=target, out_dir=out_dir),
            result,
            collector=collector,
        )
        entries = load_entries(out_dir)
        assert len(entries) == 1
        e = entries[0]
        assert e.reused is True
        assert e.reused_from_run == "run1"
        assert e.run_id == "run9"
        assert e.verdict == "clean"
        assert e.cost_usd is None or e.cost_usd == 0.0

    def test_empty_candidates_noop(self, tmp_path):
        result = OrchestratorResult()
        assert import_reused_verdicts({}, _config(tmp_path), result) == 0
        assert result.reused_from_prior == 0


class TestContextReducedJournalled:
    def test_collector_records_context_reduced(self, tmp_path):
        from core.audit.collector import Collector
        from core.audit.orchestrator import ReviewOutcome
        from core.coverage.journal import load_entries

        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        collector = Collector(
            out_dir=out_dir, target_path=target, run_id="runX",
        )
        outcome = ReviewOutcome(
            file="auth.c", function="check_pw", status="clean",
            body="ok", context_reduced=True,
        )
        collector.submit(outcome, {"line_start": 1, "line_end": 5})
        entry = load_entries(out_dir)[0]
        assert entry.context_reduced is True
        assert entry.reused is None


class TestFoldDriftFailClosed:
    """Deleted files and unverifiable spans are DRIFT, not coverage.

    Pre-fix: a deleted source file folded its entries to covered (the
    verdicts stood as coverage), and a span that no longer exists in
    the file (current hash "") slipped the prefix-compare so the
    stale verdict was reused as hash-verified at $0 — while
    compute_drift flags the identical cases as drift."""

    def test_deleted_file_resurfaces_as_gap(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(target)
        project = _project_with(tmp_path, entry)
        (target / "auth.c").unlink()
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert "auth.c:check_pw" not in sink

    def test_out_of_range_span_resurfaces_as_gap(self, tmp_path):
        """The recorded span is beyond the current file's end — the
        current hash is '' and must read as drift, never verified."""
        target = _write_target(tmp_path)
        entry = _entry(target, line_start=100, line_end=120,
                       source_hash="abcdef123456")
        project = _project_with(tmp_path, entry)
        sink: dict = {}
        checklist = _checklist(target)
        checklist["files"][0]["items"][0]["line_start"] = 100
        checklist["files"][0]["items"][0]["line_end"] = 120
        gaps = compute_gaps(
            checklist, [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert "auth.c:check_pw" not in sink

    def test_intact_file_still_folds_covered(self, tmp_path):
        """Positive control: verification still passes when nothing
        drifted."""
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
