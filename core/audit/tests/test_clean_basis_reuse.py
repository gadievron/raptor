"""clean_basis: a clean minted from tool SILENCE carries that fact.

A gate-resolved clean ("covering channel ran silent") and a
propagated clean (another function's clean, inherited) are verdicts
about tool silence, not reviews. Before this field the journal could
not tell them from a reviewed clean, so:

* cross-run verdict reuse re-imported them at $0 on every later run of
  unchanged source — permanently, and across an upgrade that fixed the
  producer (a body-prefix screen is blind on the
  DEFAULT project-index path, whose write boundary blanks long bodies);
* evidence grading could call them tool_backed.

Pinned here: the producers stamp the basis; the journal carries it
through the index slim; reuse refuses the silence-derived bases (new
reason class, fall back to re-review) and keeps reusing reviewed and
dark-verify cleans; legacy rows without the field re-review when they
show any trace and are otherwise imported at most once per completed
run (never laundered into ``verdict``; see the interrupted-run
cell); and a silence-derived clean never grades tool_backed.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
from core.audit.collector import append_journal_for_outcome
from core.audit.gaps import compute_gaps
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _resolve_gate_demoted,
)
from core.audit.strategy import strategies_from_item
from core.audit.verdict_reuse import outcome_from_entry
from core.coverage.journal import load_entries, load_index, merge_run_into_index

_PHP = (
    "<?php\nfunction getUser($pdo, $id) {\n"
    "  return $pdo->query(\"SELECT * FROM users WHERE id = \" . $id);\n"
    "}\n"
)
_KEY = "app.php:getUser"
_ITEM = {"name": "getUser", "kind": "function", "line_start": 2,
         "line_end": 4}
_GAP = {"file": "app.php", "name": "getUser", "line_start": 2,
        "line_end": 4,
        "strategies": sorted(strategies_from_item(dict(_ITEM), "app.php"))}
# Realistic model prose: long enough that the project-index write
# boundary offloads the body (>= the slim threshold).
_PROSE = (
    "The id parameter flows from the request into the SQL string by "
    "concatenation; no prepared statement or casting is applied on any "
    "path, so an attacker can inject arbitrary SQL. "
) * 6


def _basis(obj) -> str | None:
    return getattr(obj, "clean_basis", None) or None


def _checklist(target):
    return {"target_path": str(target), "files": [{
        "path": "app.php", "language": "php", "items": [dict(_ITEM)],
    }]}


def _target(tmp_path: Path) -> Path:
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "app.php").write_text(_PHP)
    return tgt


def _clean(body, *, basis=None, dispatched=None):
    outcome = ReviewOutcome(
        file="app.php", function="getUser", status="clean", body=body,
        hypothesis="SQL injection", evidence_tool="", line=2,
    )
    if dispatched is not None:
        outcome.tools_dispatched = set(dispatched)
    if basis is not None:
        outcome.clean_basis = basis
    return outcome


def _journal_then_fold(tmp_path, outcome):
    """Real journal writer → real project-index merge (the default
    cross-run path, whose write boundary slims long clean rows) →
    real gap fold with verdict reuse on."""
    tgt = _target(tmp_path)
    project = tmp_path / "proj"
    run_dir = project / "run1"
    run_dir.mkdir(parents=True)
    append_journal_for_outcome(
        out_dir=run_dir, target_path=tgt, run_id="run1",
        outcome=outcome, gap=dict(_GAP),
    )
    merge_run_into_index(project, run_dir)
    row = load_index(project).get(_KEY)
    sink: dict = {}
    stats: dict = {}
    gaps = compute_gaps(
        _checklist(tgt), [], project_dir=project,
        reuse_sink=sink, reuse_stats=stats,
    )
    resurfaced = _KEY in {f"{g['file']}:{g['name']}" for g in gaps}
    return row, sink.get(_KEY), stats.get(_KEY), resurfaced


# ------------------------------------------------------------ producers


class TestProducersStampTheBasis:

    def _resolve(self, tmp_path, dispatched):
        tgt = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        outcome = ReviewOutcome(
            file="app.php", function="getUser", status="suspicious",
            body="[gate violation: G2: finding emitted without "
                 "tool-grounded evidence]\n\nmodel claim",
            hypothesis="user id concatenated into SQL", line=2,
            review_result={"cwe": "CWE-89", "mechanism": "SQL injection"},
        )
        outcome.tools_dispatched = set(dispatched)
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        ck = {"files": [{"path": "app.php", "items": [
            {"name": "getUser", "line_start": 2, "line_end": 4}]}]}
        # Hermetic: a prefilter hit on the SQL sink would count as
        # mechanical corroboration and keep the claim suspicious, so it
        # is stubbed out; only the dispatch record decides.
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                orch, "run_prefilter",
                lambda **kw: SimpleNamespace(
                    hits=[], skip_llm=False, skip_reason="", language="",
                    sloc=10),
            )
            _resolve_gate_demoted(
                result, OrchestratorConfig(target_path=tgt, out_dir=out),
                None, ck,
                available_tools={"joern": False, "semgrep": True},
                mechanical_findings={},
            )
        return result.outcomes[0]

    def test_gate_resolved_clean_is_stamped(self, tmp_path):
        final = self._resolve(tmp_path, {"semgrep"})
        assert final.status == "clean"
        assert _basis(final) == "gate_resolved"

    def test_gate_resolved_dark_carries_no_clean_basis(self, tmp_path):
        final = self._resolve(tmp_path, set())
        assert final.status == "dark"
        assert _basis(final) is None

    def test_propagated_clean_is_stamped(self):
        from core.audit.propagation import propagate_confidence

        callee = ReviewOutcome(
            file="p.c", function="parse_hdr", status="clean", body="ok")
        callee.verification_tier = "tool_backed"
        caller = ReviewOutcome(
            file="p.c", function="handle", status="suspicious", body="m",
            hypotheses=[{"mechanism": "if parse_hdr() returns NULL the "
                                      "deref of h->len crashes",
                         "counter": ""}],
        )
        demotions = propagate_confidence(
            [callee, caller],
            {"p.c:handle": [{"callee_file": "p.c", "callee": "parse_hdr"}]},
        )
        assert demotions and caller.status == "clean"
        assert _basis(caller) == "propagated"
        # The trusted source keeps its own (reviewed) basis.
        assert _basis(callee) is None

    def test_dark_verify_refuted_clean_is_stamped(self, tmp_path,
                                                  monkeypatch):
        """Additive provenance only: the single-witness policy itself is
        unchanged (the row still resolves clean and stays reusable)."""
        import core.audit.dark_verify as dv

        (tmp_path / "math_util.py").write_text(
            "def add(a, b):\n    return a + b\n")
        monkeypatch.setattr(
            dv, "execute_witness",
            lambda spec, target, **kw: SimpleNamespace(
                verdict="refuted", match_detail="no exception"),
        )
        outcome = ReviewOutcome(
            file="math_util.py", function="add", status="dark",
            body="b", hypothesis="integer overflow",
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.dormant = 1
        orch._run_dark_verification(
            result, OrchestratorConfig(target_path=tmp_path,
                                       out_dir=tmp_path),
            llm_client=lambda s, u: json.dumps({
                "module_path": "math_util", "function": "add",
                "args": [1, 2], "expected_exception": "OverflowError",
                "rationale": "overflow"}),
        )
        assert result.outcomes[0].status == "clean"
        assert _basis(result.outcomes[0]) == "dark_verify_refuted"


# ------------------------------------------------------------- journal


class TestJournalCarriesTheBasis:

    def test_basis_journaled_and_survives_index_slim(self, tmp_path):
        row, _, _, _ = _journal_then_fold(
            tmp_path,
            _clean("[gate violation: G2: x]\n\n" + _PROSE,
                   basis="gate_resolved", dispatched={"semgrep"}),
        )
        # Anti-vacuity: the default index path DID blank the body.
        assert row is not None and not row.body and row.body_offload
        assert _basis(row) == "gate_resolved"

    def test_reviewed_clean_is_journaled_as_verdict(self, tmp_path):
        tgt = _target(tmp_path)
        out = tmp_path / "run"
        out.mkdir()
        append_journal_for_outcome(
            out_dir=out, target_path=tgt, run_id="run",
            outcome=_clean("reviewed: the id is cast with (int)"),
            gap=dict(_GAP),
        )
        (entry,) = load_entries(out)
        assert _basis(entry) == "verdict"

    def test_non_clean_rows_carry_no_basis(self, tmp_path):
        tgt = _target(tmp_path)
        out = tmp_path / "run"
        out.mkdir()
        dark = _clean("x")
        dark.status = "dark"
        append_journal_for_outcome(
            out_dir=out, target_path=tgt, run_id="run",
            outcome=dark, gap=dict(_GAP),
        )
        (entry,) = load_entries(out)
        assert _basis(entry) is None
        raw = json.loads((out / "review-journal.jsonl").read_text()
                         .splitlines()[0])
        assert "clean_basis" not in raw or raw["clean_basis"] is None


# --------------------------------------------------------------- reuse


class TestReuseRefusesSilenceDerivedCleans:

    @pytest.mark.parametrize("basis, body", [
        ("gate_resolved", "[gate violation: G2: x]\n\n" + _PROSE),
        ("gate_resolved", "[suspicious-resolution: no verification "
                          "evidence]\n\n" + _PROSE),
        ("propagated", _PROSE),
        ("gate_resolved", "short"),
    ], ids=["gate_long", "suspicious_resolution_long", "propagated",
            "gate_short"])
    def test_silence_derived_clean_resurfaces(self, tmp_path, basis, body):
        _, reused, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(body, basis=basis, dispatched={"semgrep"}))
        assert reused is None
        assert why == "silence_derived_clean"
        assert resurfaced

    @pytest.mark.parametrize("basis", ["verdict", "dark_verify_refuted"])
    def test_control_reviewed_and_witness_cleans_still_reused(
        self, tmp_path, basis,
    ):
        _, reused, why, resurfaced = _journal_then_fold(
            tmp_path,
            _clean("Reviewed: the id is cast with (int) before use. "
                   + _PROSE, basis=basis),
        )
        assert reused is not None and reused.verdict == "clean"
        assert why is None and not resurfaced

    def test_reused_row_keeps_its_basis(self, tmp_path):
        """outcome_from_entry carries the basis, so the reused row's
        own re-journal never launders it into a fresh 'verdict'."""
        _, reused, _, _ = _journal_then_fold(
            tmp_path, _clean("witness", basis="dark_verify_refuted"))
        assert _basis(outcome_from_entry(reused)) == "dark_verify_refuted"


class TestLegacyRowsFailClosed:
    """Rows journaled before the field carry no basis. One showing any
    trace of silence derivation or a hidden basis re-reviews; a
    traceless one is imported at most once per completed run (its
    re-journal carries ``unknown``, refused once merged; see the
    interrupted-run cell for the disclosed limitation)."""

    def _legacy(self, tmp_path, outcome):
        # Journal with the field suppressed: exactly the pre-field
        # row shape, MAC-stamped by the real writer.
        import core.audit.collector as collector

        real = collector.ReviewJournalEntry

        def _no_basis(**kw):
            kw.pop("clean_basis", None)
            return real(**kw)

        mp = pytest.MonkeyPatch()
        mp.setattr(collector, "ReviewJournalEntry", _no_basis)
        try:
            return _journal_then_fold(tmp_path, outcome)
        finally:
            mp.undo()

    @pytest.mark.parametrize("body, dispatched", [
        ("[gate violation: G2: x]\n\nshort", None),
        ("[self-contradiction: the description asserts the code is "
         "safe]\n\nshort", None),
        ("[sarif-clean gate] File has zero CodeQL alerts, function has "
         "no mechanical findings, SLOC <= 20. Resolved without LLM "
         "review.", None),
        # The removed in-loop suspicious-demotion gate's body,
        # verbatim: journals written before its removal hold such
        # cleans.
        ("[suspicious-demotion: no verification evidence with Joern "
         "available]\n\nmodel prose", None),
        ("[suspicious-resolution: no verification evidence]\n\nshort",
         None),
        ("If parse_hdr() returns NULL the deref crashes", {"smt"}),
        ("[gate violation: G2: x]\n\n" + _PROSE, None),
        ("Reviewed: the id is cast with (int). " + _PROSE, None),
    ], ids=["gate_prefix", "self_contradiction_prefix",
            "sarif_clean_gate_prefix", "suspicious_demotion_prefix",
            "resolution_prefix", "dispatched_record",
            "offloaded_gate", "offloaded_unknown"])
    def test_legacy_silence_trace_resurfaces(self, tmp_path, body,
                                             dispatched):
        row, reused, why, resurfaced = self._legacy(
            tmp_path, _clean(body, dispatched=dispatched))
        assert _basis(row) is None  # precondition: legacy shape
        assert reused is None
        assert why == "silence_derived_clean"
        assert resurfaced

    def test_traceless_legacy_clean_imported_once_then_refused(
        self, tmp_path,
    ):
        """A pre-field clean with no trace (a reviewed clean — or a
        propagated one that kept the caller's short prose) is imported
        ONCE; the import carries basis ``unknown`` into its re-journal,
        so the next run re-reviews it. Never laundered into
        ``verdict``."""
        row, reused, why, resurfaced = self._legacy(
            tmp_path, _clean("Reviewed: the id is cast with (int)."))
        assert _basis(row) is None and row.body  # not offloaded
        assert reused is not None and why is None and not resurfaced
        reimport = outcome_from_entry(reused)
        assert _basis(reimport) == "unknown"
        run2 = tmp_path / "run2"
        run2.mkdir()
        _, again, why2, resurfaced2 = _journal_then_fold(run2, reimport)
        assert again is None and why2 == "silence_derived_clean"
        assert resurfaced2

    def test_marker_quoted_mid_body_is_not_a_trace(self, tmp_path):
        """The screen reads pipeline-written PREFIXES: a reviewed clean
        whose prose merely quotes a marker mid-body is not refused on
        that account (it is still imported at most once per completed
        run, as ``unknown``)."""
        row, reused, why, resurfaced = self._legacy(
            tmp_path, _clean("Reviewed: the earlier [gate violation: G2] "
                             "note no longer applies; id is cast."))
        assert _basis(row) is None and row.body.startswith("Reviewed")
        assert reused is not None and why is None and not resurfaced

    def test_interrupted_import_reimports_but_never_launders(
        self, tmp_path,
    ):
        """Disclosed limitation: "imported at most once" holds per
        COMPLETED (index-merged) run. A run that imports a traceless
        pre-field clean and is interrupted before the merge leaves the
        index row in place, so the next run imports it again — but
        both imports, and the interrupted run's own journal row, carry
        basis ``unknown``; nothing is ever stamped ``verdict``."""
        row, reused, why, _ = self._legacy(
            tmp_path, _clean("Reviewed: the id is cast with (int)."))
        assert _basis(row) is None and reused is not None
        first = outcome_from_entry(reused)
        assert _basis(first) == "unknown"
        # The interrupted run journals its import but never merges.
        tgt = tmp_path / "tgt"
        interrupted = tmp_path / "proj" / "run2"
        interrupted.mkdir()
        append_journal_for_outcome(
            out_dir=interrupted, target_path=tgt, run_id="run2",
            outcome=first, gap=dict(_GAP))
        (own,) = load_entries(interrupted)
        assert _basis(own) == "unknown"
        # Next run folds the unchanged index: imported again ...
        sink: dict = {}
        compute_gaps(_checklist(tgt), [], project_dir=tmp_path / "proj",
                     reuse_sink=sink, reuse_stats={})
        assert _KEY in sink
        # ... still as "unknown", never laundered.
        assert _basis(outcome_from_entry(sink[_KEY])) == "unknown"

    @pytest.mark.parametrize("inner", [
        "[gate violation: G2: finding emitted without tool-grounded "
        "evidence]\n\nmodel claim",
        "[body and hypotheses offloaded at the index write boundary — "
        "the full row stays in the journal of run run1]",
    ], ids=["short_gate_body", "offload_marker"])
    @pytest.mark.parametrize("flagged", [True, False],
                             ids=["reused_flag", "prefix_only"])
    def test_pre_field_reuse_rejournal_resurfaces(self, tmp_path, inner,
                                                  flagged):
        """The base-era shape: a gate-resolved clean a pre-field run
        already re-imported once. Its re-journal row hides the
        original behind outcome_from_entry's ``[reused: ...]`` prefix
        (or the index offload marker) and has no dispatch record."""
        outcome = _clean(
            "[reused: verdict imported from run run1; source hash "
            "unchanged]\n\n" + inner)
        if flagged:
            outcome.reused = True
            outcome.reused_from_run = "run1"
        row, reused, why, resurfaced = self._legacy(tmp_path, outcome)
        assert _basis(row) is None and row.body  # precondition
        assert reused is None
        assert why == "silence_derived_clean"
        assert resurfaced


# ------------------------------------------------------------- grading


class TestSilenceDerivedCleanNeverToolBacked:

    @pytest.mark.parametrize("basis, tier", [
        ("gate_resolved", "speculative"),
        ("propagated", "speculative"),
        ("verdict", "tool_backed"),
        (None, "tool_backed"),
    ])
    def test_tier_reads_the_basis(self, basis, tier):
        clean = _clean("b", basis=basis, dispatched={"semgrep"})
        assert clean.compute_tier() == tier


class TestSarifCleanLaneIsSilenceDerived:
    """The sarif-clean gate resolves a function from file-level SARIF
    silence without review: stamped ``sarif_clean`` — refused by reuse
    (the $0 gate re-runs instead), never tool_backed."""

    def test_sarif_clean_row_resurfaces(self, tmp_path):
        _, reused, why, resurfaced = _journal_then_fold(
            tmp_path, _clean("[sarif-clean gate] File has zero CodeQL "
                             "alerts ...", basis="sarif_clean"))
        assert reused is None and why == "silence_derived_clean"
        assert resurfaced

    def test_sarif_clean_never_tool_backed(self):
        clean = _clean("b", basis="sarif_clean", dispatched={"semgrep"})
        assert clean.compute_tier() == "speculative"


class TestValidateCorrectionStampsVerdict:

    def test_validate_downgrade_to_clean_is_verdict(self, tmp_path):
        from core.audit.feedback import import_validation_results
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            latest_entries,
            now_iso,
        )

        ann = tmp_path / "annotations"
        ann.mkdir()
        out = tmp_path / "audit-out"
        out.mkdir()
        append_entry(out, ReviewJournalEntry(
            ts=now_iso(), run_id="test", file="src/vuln.c",
            function="vuln_fn", verdict="finding", source_hash="",
            body="Confirmed format string"))
        report = tmp_path / "findings.json"
        report.write_text(json.dumps([{
            "file": "src/vuln.c", "function": "vuln_fn",
            "ruling": {"status": "ruled_out", "reason": "test code",
                       "disqualifier": "D-1"},
        }]))
        import_validation_results(
            validation_report=report, annotations_dir=ann,
            audit_out_dir=out)
        entry = latest_entries(out)["src/vuln.c:vuln_fn"]
        assert entry.verdict == "clean"
        assert _basis(entry) == "verdict"
