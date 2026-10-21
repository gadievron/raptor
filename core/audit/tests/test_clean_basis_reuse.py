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
    """Each producer that mints a clean from tool silence must record that
    origin on the outcome itself. Without the stamp, later stages cannot tell a
    silence-derived clean from a reviewed one."""

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
        """A clean reached by end-of-run gate resolution, because the covering
        scanner ran silent, must carry the gate_resolved basis. If the stamp
        were missing, cross-run reuse would treat it as a reviewed clean and
        import it for free forever."""
        final = self._resolve(tmp_path, {"semgrep"})
        assert final.status == "clean"
        assert _basis(final) == "gate_resolved"

    def test_gate_resolved_dark_carries_no_clean_basis(self, tmp_path):
        """When no covering tool ran, gate resolution yields dark rather than
        clean, and a non-clean row must not carry a clean basis. A stray basis
        on a dark row would confuse reuse and grading, which read the field
        only for cleans."""
        final = self._resolve(tmp_path, set())
        assert final.status == "dark"
        assert _basis(final) is None

    def test_propagated_clean_is_stamped(self):
        """A caller made clean by inheriting a trusted callee's clean must be
        stamped propagated, while the callee keeps its own reviewed basis.
        Otherwise an inherited verdict would look like a direct review of the
        caller and be reused across runs."""
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
    """The clean basis must reach the review journal and survive the
    project-index merge, which is the path cross-run reuse reads. If it were
    lost on the way, reuse would be blind to silence-derived cleans again."""

    def test_basis_journaled_and_survives_index_slim(self, tmp_path):
        """The default project-index write blanks long clean bodies, so any
        body-text screen is blind there and the basis field is the only signal
        left. This pins that the basis survives that slimming step."""
        row, _, _, _ = _journal_then_fold(
            tmp_path,
            _clean("[gate violation: G2: x]\n\n" + _PROSE,
                   basis="gate_resolved", dispatched={"semgrep"}),
        )
        # Anti-vacuity: the default index path DID blank the body.
        assert row is not None and not row.body and row.body_offload
        assert _basis(row) == "gate_resolved"

    def test_reviewed_clean_is_journaled_as_verdict(self, tmp_path):
        """A clean produced by an actual review is journaled with the verdict
        basis by default. That is the basis reuse trusts, so getting it wrong
        would either block legitimate reuse or let unreviewed cleans pass as
        reviewed."""
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
        """Only clean rows may carry a clean basis; a dark row must journal
        with none. This keeps the field meaningful and stops non-clean rows
        being matched by basis-reading code."""
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
    """Cross-run verdict reuse must refuse cleans that came from tool silence
    and send them back for review, while still reusing reviewed and
    witness-refuted cleans. Without this, a silence-derived clean would be
    re-imported at no cost on every run of unchanged source."""

    @pytest.mark.parametrize("basis, body", [
        ("gate_resolved", "[gate violation: G2: x]\n\n" + _PROSE),
        ("gate_resolved", "[suspicious-resolution: no verification "
                          "evidence]\n\n" + _PROSE),
        ("propagated", _PROSE),
        ("gate_resolved", "short"),
    ], ids=["gate_long", "suspicious_resolution_long", "propagated",
            "gate_short"])
    def test_silence_derived_clean_resurfaces(self, tmp_path, basis, body):
        """Gate-resolved and propagated cleans, short or long, must be refused
        by reuse with the silence_derived_clean reason and come back as gaps to
        review. If this broke, a clean nobody reviewed would be imported again
        on every later run."""
        _, reused, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(body, basis=basis, dispatched={"semgrep"}))
        assert reused is None
        assert why == "silence_derived_clean"
        assert resurfaced

    @pytest.mark.parametrize("basis", ["verdict", "dark_verify_refuted"])
    def test_control_reviewed_and_witness_cleans_still_reused(
        self, tmp_path, basis,
    ):
        """Reviewed cleans and cleans refuted by an executed witness must still
        be reused. This guards against the silence-derived refusal being so
        broad that it forces costly re-review of trustworthy verdicts."""
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
        """Rows journaled before the basis field existed must be re-reviewed
        when their body prefix or dispatch record shows any trace of silence
        derivation, or when the body was offloaded and cannot be read.
        Otherwise old silence-derived cleans would keep being imported
        indefinitely."""
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
    """Evidence grading must not call a silence-derived clean tool_backed just
    because a scanner was dispatched. Silence is not a tool finding, so
    overstating it would inflate the confidence reported for the verdict."""

    @pytest.mark.parametrize("basis, tier", [
        ("gate_resolved", "speculative"),
        ("propagated", "speculative"),
        ("verdict", "tool_backed"),
        (None, "tool_backed"),
    ])
    def test_tier_reads_the_basis(self, basis, tier):
        """The tier computation must read the clean basis: gate-resolved and
        propagated cleans grade speculative while reviewed or unstamped cleans
        with a dispatched tool grade tool_backed. If the basis were ignored,
        silence would be graded as tool evidence."""
        clean = _clean("b", basis=basis, dispatched={"semgrep"})
        assert clean.compute_tier() == tier


class TestSarifCleanLaneIsSilenceDerived:
    """The sarif-clean gate resolves a function from file-level SARIF
    silence without review: stamped ``sarif_clean`` — refused by reuse
    (the $0 gate re-runs instead), never tool_backed."""

    def test_sarif_clean_row_resurfaces(self, tmp_path):
        """A clean resolved from file-level SARIF silence without review must
        be refused by reuse so the cheap gate runs again instead. Importing it
        would freeze a verdict that never saw a review."""
        _, reused, why, resurfaced = _journal_then_fold(
            tmp_path, _clean("[sarif-clean gate] File has zero CodeQL "
                             "alerts ...", basis="sarif_clean"))
        assert reused is None and why == "silence_derived_clean"
        assert resurfaced

    def test_sarif_clean_never_tool_backed(self):
        """A sarif_clean row must grade speculative even when a tool was
        dispatched. Grading it tool_backed would present the absence of alerts
        as positive tool evidence."""
        clean = _clean("b", basis="sarif_clean", dispatched={"semgrep"})
        assert clean.compute_tier() == "speculative"


class TestValidateCorrectionStampsVerdict:
    """A clean written by importing human or validation rulings is a deliberate
    correction, not tool silence. It must be stamped as a verdict so reuse
    keeps honouring it."""

    def test_validate_downgrade_to_clean_is_verdict(self, tmp_path):
        """When validation rules a finding out and the import rewrites it as
        clean, the new journal row must carry the verdict basis. If it carried
        a silence basis or none, the correction would be thrown away and
        re-reviewed on the next run."""
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


# ------------------------------------------- retired prose-gate cleans

# The body the retired review-time rationale-consistency gate stamped
# (exact base wording) on the clean it minted from a phrase match.
_RETIRED_RATIONALE_MARKER = (
    "[rationale-consistency demotion: the rationale below concludes "
    "clean while the emitted status was finding — verdict recorded as "
    "clean]\n\n"
)


class TestRetiredProseCleansReReview:
    """A clean minted by a gate that read the verdict off model prose
    (and no longer exists) was journaled with the collector's default
    ``verdict`` basis, so it was imported at $0 on every later run of
    unchanged source — the fix never reached audited projects. Such a
    row is refused once in every era; the fresh row never carries the
    marker, so the next run reuses normally."""

    @pytest.mark.parametrize("body", [
        _RETIRED_RATIONALE_MARKER + "The input is not properly validated.",
        _RETIRED_RATIONALE_MARKER + _PROSE,   # offloaded at the index slim
    ], ids=["short", "long"])
    def test_field_era_row_resurfaces(self, tmp_path, body):
        """A clean minted by the retired rationale-consistency gate was
        journaled with the default verdict basis, so the basis alone cannot
        catch it. Reuse must spot its marker, short or offloaded, and refuse it
        so the retired gate's verdict does not live on in audited projects."""
        row, sunk, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(body))
        assert _basis(row) == "verdict"  # the base writer's default
        assert sunk is None
        assert resurfaced
        assert why == "retired_prose_clean"

    def test_pre_field_row_resurfaces(self, tmp_path):
        """A retired prose-gate clean journaled before the basis field existed
        must also be refused by reuse. Otherwise older projects would keep
        importing a verdict that was decided by a phrase match."""
        row, sunk, why, resurfaced = TestLegacyRowsFailClosed()._legacy(
            tmp_path,
            _clean(_RETIRED_RATIONALE_MARKER + "Validated before use."),
        )
        assert _basis(row) is None
        assert resurfaced and sunk is None
        assert why == "retired_prose_clean"

    def test_reuse_rejournal_of_such_a_row_resurfaces(self, tmp_path):
        # A field-era run that already imported the row re-journaled it
        # behind the ``[reused:`` lead, keeping basis ``verdict``.
        """A retired prose-gate clean that an earlier run already reused gets
        re-journaled behind a reused lead. The screen must look past that lead,
        or one import would hide the marker and launder the clean forever."""
        body = (
            "[reused: verdict imported from run run-base; source hash "
            "unchanged]  " + _RETIRED_RATIONALE_MARKER + "Validated."
        )
        _, sunk, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(body, basis="verdict"))
        assert resurfaced and sunk is None
        assert why == "retired_prose_clean"

    @pytest.mark.parametrize("body", [
        "The input is properly validated before use.",
        "Note: an older run said [rationale-consistency demotion: x] "
        "here; the cast on line 2 bounds it.",
        # Model-authored marker: defanged at ingestion, so it is prose.
        "[llm-claimed] " + _RETIRED_RATIONALE_MARKER + "Validated.",
    ], ids=["no-marker", "mid-body", "model-authored"])
    def test_controls_still_reused(self, tmp_path, body):
        """A clean with no retired marker, with the marker only quoted
        mid-body, or with a model-authored copy of it that was defanged at
        ingestion must still be reused. This stops the screen from refusing
        ordinary reviewed cleans on loose text matches."""
        _, sunk, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(body))
        assert not resurfaced
        assert sunk is not None and why is None

    def test_refused_once_then_reused(self, tmp_path):
        """A retired prose-gate clean is refused once, and the fresh review it
        triggers carries no marker, so the following run reuses normally. This
        pins that the refusal costs one re-review rather than looping forever.
        """
        tgt = _target(tmp_path)
        project = tmp_path / "proj"
        for run_id, body in (
            ("run1", _RETIRED_RATIONALE_MARKER + "Validated."),
            # The re-review the refusal bought (any verdict; a clean
            # here) carries no retired marker.
            ("run2", "The id is cast to int on line 2 before use."),
        ):
            run_dir = project / run_id
            run_dir.mkdir(parents=True)
            append_journal_for_outcome(
                out_dir=run_dir, target_path=tgt, run_id=run_id,
                outcome=_clean(body), gap=dict(_GAP),
            )
            merge_run_into_index(project, run_dir)
            sink: dict = {}
            stats: dict = {}
            gaps = compute_gaps(
                _checklist(tgt), [], project_dir=project,
                reuse_sink=sink, reuse_stats=stats,
            )
            resurfaced = _KEY in {f"{g['file']}:{g['name']}" for g in gaps}
            if run_id == "run1":
                assert resurfaced
                assert stats.get(_KEY) == "retired_prose_clean"
            else:
                assert not resurfaced and _KEY in sink

    def test_long_row_needs_its_origin_run(self, tmp_path):
        # The index stub of a long body is read back from the origin
        # run journal (hash-checked against the stub pointer). With the
        # origin run gone the body is out of sight and the row is
        # reused — the documented limit of a content screen.
        """For a long body the index keeps only a stub, and the marker is read
        back from the original run's journal. If that run is gone the row is
        reused, which is the documented limit of a content screen and must stay
        explicit rather than becoming silent failure elsewhere."""
        tgt = _target(tmp_path)
        project = tmp_path / "proj"
        run_dir = project / "run1"
        run_dir.mkdir(parents=True)
        append_journal_for_outcome(
            out_dir=run_dir, target_path=tgt, run_id="run1",
            outcome=_clean(_RETIRED_RATIONALE_MARKER + _PROSE),
            gap=dict(_GAP),
        )
        merge_run_into_index(project, run_dir)
        assert load_index(project)[_KEY].body == ""  # slimmed stub
        run_dir.rename(tmp_path / "moved-away")
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(tgt), [], project_dir=project,
            reuse_sink=sink, reuse_stats={},
        )
        assert _KEY not in {f"{g['file']}:{g['name']}" for g in gaps}
        assert _KEY in sink

    def test_edited_origin_run_cannot_steer(self, tmp_path):
        # The origin-run read-back is accepted only when its offloaded
        # fields hash to the index stub's pointer: an origin journal
        # edited to carry the retired marker does not refuse a clean
        # the index recorded without it.
        """The read-back from the original run is accepted only when its
        contents hash to the index stub's pointer. An origin journal edited
        after the fact to insert the retired marker must not be able to make
        reuse refuse a clean the index recorded without it."""
        tgt = _target(tmp_path)
        project = tmp_path / "proj"
        run_dir = project / "run1"
        run_dir.mkdir(parents=True)
        append_journal_for_outcome(
            out_dir=run_dir, target_path=tgt, run_id="run1",
            outcome=_clean(_PROSE), gap=dict(_GAP),
        )
        merge_run_into_index(project, run_dir)
        assert load_index(project)[_KEY].body == ""  # slimmed stub
        journal = run_dir / "review-journal.jsonl"
        rows = [json.loads(line) for line in journal.read_text().splitlines()
                if line.strip()]
        for row in rows:
            row["body"] = _RETIRED_RATIONALE_MARKER + row["body"]
            row.pop("integrity", None)
        journal.write_text("".join(json.dumps(r) + "\n" for r in rows))
        from core.coverage.journal import load_entries
        edited = [e for e in load_entries(run_dir, fresh=True)
                  if e.function == "getUser"]
        assert edited and edited[-1].body.startswith(
            "[rationale-consistency demotion:")  # the edit is visible
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(tgt), [], project_dir=project,
            reuse_sink=sink, reuse_stats={},
        )
        assert _KEY not in {f"{g['file']}:{g['name']}" for g in gaps}
        assert _KEY in sink

    def test_repeated_reuse_leads_are_all_skipped(self, tmp_path):
        # A row imported twice re-journals behind two `[reused:` leads.
        """A row imported twice is re-journaled behind two reused leads. The
        screen must skip every such lead, not just the first, or a second
        import would hide the retired marker."""
        lead = ("[reused: verdict imported from run r0; source hash "
                "unchanged]\n\n")
        _, sunk, why, resurfaced = _journal_then_fold(
            tmp_path, _clean(lead + lead + _RETIRED_RATIONALE_MARKER
                             + "Validated.", basis="verdict"))
        assert resurfaced and sunk is None
        assert why == "retired_prose_clean"


class TestOriginReadBackIsLinear:
    """The origin-run read-back runs for every index-slimmed clean
    stub; it must read each origin journal once per content state, not
    once per stub (12,000 stubs took 45 s when each stub re-read its
    journal; 3.5 s without the read-back)."""

    @staticmethod
    def _project(tmp_path, n):
        tgt = tmp_path / "tgt"
        tgt.mkdir(parents=True)
        tgt.joinpath("app.php").write_text("<?php\n" + "".join(
            f"function f{i}($id) {{\n  return $id;\n}}\n" for i in range(n)))
        items = [{"name": f"f{i}", "kind": "function",
                  "line_start": 2 + 3 * i, "line_end": 4 + 3 * i}
                 for i in range(n)]
        project = tmp_path / "proj"
        run = project / "run1"
        run.mkdir(parents=True)
        for it in items:
            o = ReviewOutcome(
                file="app.php", function=it["name"], status="clean",
                body=_PROSE, hypothesis="none", evidence_tool="",
                line=it["line_start"])
            append_journal_for_outcome(
                out_dir=run, target_path=tgt, run_id="run1", outcome=o,
                gap={"file": "app.php", "name": it["name"],
                     "line_start": it["line_start"],
                     "line_end": it["line_end"],
                     "strategies": sorted(
                         strategies_from_item(dict(it), "app.php"))})
        merge_run_into_index(project, run)
        checklist = {"target_path": str(tgt), "files": [{
            "path": "app.php", "language": "php", "items": items}]}
        return project, run, checklist

    def test_each_origin_journal_read_once(self, tmp_path, monkeypatch):
        """The origin-run read-back runs for every slimmed clean stub, so it
        must read each origin journal once per content state rather than once
        per stub. Re-reading per stub made large projects fold quadratically
        slower."""
        import core.coverage.journal as journal_mod

        project, run, checklist = self._project(tmp_path, 60)
        assert load_index(project)["app.php:f0"].body == ""  # stubs
        real = journal_mod.load_entries
        reads: list = []

        def counting(out_dir, *a, **kw):
            if Path(out_dir).resolve() == run.resolve():
                reads.append(out_dir)
            return real(out_dir, *a, **kw)

        monkeypatch.setattr(journal_mod, "load_entries", counting)
        sink: dict = {}
        compute_gaps(checklist, [], project_dir=project,
                     reuse_sink=sink, reuse_stats={})
        assert len(sink) == 60
        assert len(reads) == 1
        # The row cache is fold-local: a second fold builds its own
        # index of the origin journal, exactly once.
        compute_gaps(checklist, [], project_dir=project,
                     reuse_sink={}, reuse_stats={})
        assert len(reads) == 2

    def test_read_back_adds_bounded_fold_time(self, tmp_path, monkeypatch):
        """End to end, folding thousands of slimmed stubs with the read-back on
        must stay within a small constant factor of folding with it off. This
        catches a return to per-stub journal reads, which once made the fold
        many times slower."""
        # End-to-end cost: the same fold over 2,000 index stubs with the
        # read-back on vs stubbed out. The quadratic read-back measured
        # ~5x the baseline here (45 s vs 3.5 s at 12,000 rows); linear
        # stays within a small constant factor.
        import time

        import core.audit.gaps as gaps_mod

        project, _, checklist = self._project(tmp_path, 2000)

        def fold():
            t0 = time.perf_counter()
            sink: dict = {}
            compute_gaps(checklist, [], project_dir=project,
                         reuse_sink=sink, reuse_stats={})
            assert len(sink) == 2000
            return time.perf_counter() - t0

        fold()  # warm the process caches both runs share
        with_read_back = fold()
        with monkeypatch.context() as m:
            m.setattr(gaps_mod, "_origin_run_body",
                      lambda entry, origin_cache=None: "")
            baseline = fold()
        assert with_read_back < 2.5 * baseline + 0.25, (
            with_read_back, baseline)


class TestOriginCacheInvalidation:
    """Within one cache (a fold's, or one a direct caller passes), the
    origin-run row map is re-read whenever the origin journal's content
    state changes — size, mtime, file identity, or the shard set — and
    only then. Each cell isolates one fingerprint component by
    restoring the others."""

    @staticmethod
    def _setup(tmp_path, monkeypatch):
        import core.audit.gaps as gaps_mod
        import core.coverage.journal as journal_mod

        project, run, _ = TestOriginReadBackIsLinear._project(tmp_path, 2)
        stub = load_index(project)["app.php:f0"]
        assert stub.body == ""
        real = journal_mod.load_entries
        reads: list = []

        def counting(out_dir, *a, **kw):
            if Path(out_dir).resolve() == run.resolve():
                reads.append(1)
            return real(out_dir, *a, **kw)

        monkeypatch.setattr(journal_mod, "load_entries", counting)
        cache: dict = {}
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 1
        return gaps_mod, run, stub, reads, cache

    def test_unchanged_is_served_from_cache(self, tmp_path, monkeypatch):
        """When the origin journal has not changed, a second read-back must
        come from cache without touching the file. Otherwise the cache would
        give no benefit and the fold would slow down again."""
        gaps_mod, _, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 1

    def test_size_change_rereads(self, tmp_path, monkeypatch):
        """A change in the origin journal's size, with mtime held fixed, must
        invalidate the cache. Without this, appended rows could be missed and a
        stale body screened."""
        import os
        gaps_mod, run, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        journal = run / "review-journal.jsonl"
        st = journal.stat()
        with journal.open("a") as fh:
            fh.write("\n")
        os.utime(journal, ns=(st.st_atime_ns, st.st_mtime_ns))
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 2

    def test_mtime_change_rereads(self, tmp_path, monkeypatch):
        """A rewrite that keeps the size but changes mtime must invalidate the
        cache. Otherwise a same-length edit would be served from stale cached
        content."""
        import os
        gaps_mod, run, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        journal = run / "review-journal.jsonl"
        st = journal.stat()
        journal.write_bytes(journal.read_bytes())  # same size
        os.utime(journal, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
        assert journal.stat().st_size == st.st_size
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 2

    def test_replaced_file_rereads(self, tmp_path, monkeypatch):
        """Replacing the origin journal with a new file of the same size and
        mtime must still invalidate the cache via file identity. Otherwise an
        atomic replace would go unnoticed and stale rows would be screened."""
        import os
        gaps_mod, run, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        journal = run / "review-journal.jsonl"
        st = journal.stat()
        fresh = run / "replacement.tmp"
        fresh.write_bytes(journal.read_bytes())
        os.utime(fresh, ns=(st.st_atime_ns, st.st_mtime_ns))
        fresh.replace(journal)  # same size + mtime, new inode
        assert journal.stat().st_ino != st.st_ino
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 2

    def test_new_shard_rereads(self, tmp_path, monkeypatch):
        """Adding a new journal shard to the origin run must invalidate the
        cache. Rows written to the new shard would otherwise never be seen by
        the read-back."""
        from core.coverage.journal import _journal_shard_name
        gaps_mod, run, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        (run / _journal_shard_name(2)).write_text("")
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 2


    def test_in_place_rewrite_keeps_the_authenticated_body(
            self, tmp_path, monkeypatch):
        """An in-place rewrite that keeps inode, size and mtime is invisible to
        the fingerprint. The warm cache must still serve only the body that
        hashed to the stub pointer, and a fresh read of the rewritten journal
        must yield nothing."""
        # A rewrite the fingerprint cannot see (same inode, size and
        # mtime) leaves the cached row in place: the warm cache still
        # serves the body that hashed to the stub pointer, never the new
        # bytes. A fresh cache reads the new bytes, whose fields no
        # longer hash to the pointer, so it yields nothing.
        import os
        import core.coverage.journal as journal_mod
        gaps_mod, run, stub, reads, cache = self._setup(tmp_path, monkeypatch)
        journal = run / "review-journal.jsonl"
        st = journal.stat()
        old = _PROSE[:40].encode()
        new = old.upper()
        assert new != old and len(new) == len(old)
        data = journal.read_bytes()
        at = data.index(old)
        with journal.open("r+b") as fh:
            fh.seek(at)
            fh.write(new)
        os.utime(journal, ns=(st.st_atime_ns, st.st_mtime_ns))
        now = journal.stat()
        assert (now.st_ino, now.st_size, now.st_mtime_ns) == (
            st.st_ino, st.st_size, st.st_mtime_ns)
        assert journal.read_bytes() != data
        assert gaps_mod._origin_run_body(stub, origin_cache=cache) == _PROSE
        assert len(reads) == 1
        # The journal loader keeps its own process-local view; read the
        # bytes on disk so only the stub-pointer check decides.
        counting = journal_mod.load_entries
        monkeypatch.setattr(
            journal_mod, "load_entries",
            lambda out_dir, *a, **kw: counting(out_dir, fresh=True))
        assert gaps_mod._origin_run_body(stub, origin_cache={}) == ""
        assert len(reads) == 2

    def test_no_cache_means_one_read_per_call(self, tmp_path, monkeypatch):
        """A direct caller that passes no cache gets no retention: every call
        indexes the origin journal again."""
        # Direct-caller lifetime policy: without an explicit cache every
        # call indexes the origin journal afresh — nothing is retained.
        gaps_mod, _, stub, reads, _ = self._setup(tmp_path, monkeypatch)
        assert gaps_mod._origin_run_body(stub) == _PROSE
        assert gaps_mod._origin_run_body(stub) == _PROSE
        assert len(reads) == 3


class TestOriginCacheIsFoldLocal:
    """The origin-run row cache lives in one fold's frame and is passed
    down explicitly; nothing is retained by the process between folds,
    and nested or overlapping folds cannot clear or share each other's
    cache (a module-level map would keep every origin journal ever
    read for the life of the process)."""

    @staticmethod
    def _interleaved(tmp_path, n, runs):
        """n slimmed clean stubs spread round-robin over ``runs`` origin
        runs, so consecutive checklist items come from different runs."""
        tgt = tmp_path / "tgt"
        tgt.mkdir(parents=True)
        tgt.joinpath("app.php").write_text("<?php\n" + "".join(
            f"function f{i}($id) {{\n  return $id;\n}}\n" for i in range(n)))
        items = [{"name": f"f{i}", "kind": "function",
                  "line_start": 2 + 3 * i, "line_end": 4 + 3 * i}
                 for i in range(n)]
        project = tmp_path / "proj"
        run_dirs = [project / f"run{r}" for r in range(runs)]
        for d in run_dirs:
            d.mkdir(parents=True)
        for i, it in enumerate(items):
            r = i % runs
            body = (_RETIRED_RATIONALE_MARKER + _PROSE) if i == 0 else _PROSE
            o = ReviewOutcome(
                file="app.php", function=it["name"], status="clean",
                body=body, hypothesis="none", evidence_tool="",
                line=it["line_start"])
            append_journal_for_outcome(
                out_dir=run_dirs[r], target_path=tgt, run_id=f"run{r}",
                outcome=o,
                gap={"file": "app.php", "name": it["name"],
                     "line_start": it["line_start"],
                     "line_end": it["line_end"],
                     "strategies": sorted(
                         strategies_from_item(dict(it), "app.php"))})
        for d in run_dirs:
            merge_run_into_index(project, d)
        checklist = {"target_path": str(tgt), "files": [{
            "path": "app.php", "language": "php", "items": items}]}
        return project, run_dirs, checklist

    @staticmethod
    def _count_builds(monkeypatch, run_dirs):
        import core.coverage.journal as journal_mod
        real = journal_mod.load_entries
        builds = {d.resolve(): 0 for d in run_dirs}

        def counting(out_dir, *a, **kw):
            key = Path(out_dir).resolve()
            if key in builds:
                builds[key] += 1
            return real(out_dir, *a, **kw)

        monkeypatch.setattr(journal_mod, "load_entries", counting)
        return builds

    @staticmethod
    def _fold(project, checklist):
        sink: dict = {}
        stats: dict = {}
        compute_gaps(checklist, [], project_dir=project,
                     reuse_sink=sink, reuse_stats=stats)
        return sink, stats

    def test_no_process_global_cache(self):
        """The origin-run row cache must not be a module global, which would
        keep every origin journal it read for the life of the process."""
        import core.audit.gaps as gaps_mod
        assert not hasattr(gaps_mod, "_ORIGIN_RUN_ROWS")

    def test_interleaved_origins_one_build_per_origin_per_fold(
            self, tmp_path, monkeypatch):
        """With stubs from several origin runs interleaved, each fold indexes
        each origin journal exactly once, and a second fold builds its own
        index."""
        # Counts index builds (load_entries calls into each origin run);
        # physical disk reads can be fewer — the journal loader keeps its
        # own bounded cache.
        project, run_dirs, checklist = self._interleaved(tmp_path, 30, 3)
        builds = self._count_builds(monkeypatch, run_dirs)
        for fold_no in (1, 2):
            sink, stats = self._fold(project, checklist)
            assert len(sink) == 29
            assert stats.get("app.php:f0") == "retired_prose_clean"
            assert all(n == fold_no for n in builds.values()), builds

    def test_nested_fold_does_not_disturb_the_outer_fold(
            self, tmp_path, monkeypatch):
        """A fold started inside another fold gets its own cache: neither fold
        indexes an origin journal twice or loses the retired-gate refusal."""
        import core.audit.gaps as gaps_mod

        outer = self._interleaved(tmp_path / "outer", 12, 2)
        inner = self._interleaved(tmp_path / "inner", 6, 2)
        builds = self._count_builds(monkeypatch, outer[1] + inner[1])
        real = gaps_mod._reuse_ineligibility
        nested: list = []
        started: list = []

        def with_nested(*a, **kw):
            if not started:  # once, from inside the OUTER fold
                started.append(1)
                nested.append(self._fold(inner[0], inner[2]))
            return real(*a, **kw)

        monkeypatch.setattr(gaps_mod, "_reuse_ineligibility", with_nested)
        sink, stats = self._fold(outer[0], outer[2])
        assert len(sink) == 11
        assert stats.get("app.php:f0") == "retired_prose_clean"
        (inner_sink, inner_stats), = nested
        assert len(inner_sink) == 5
        assert inner_stats.get("app.php:f0") == "retired_prose_clean"
        assert all(n == 1 for n in builds.values()), builds

    def test_exception_mid_fold_leaves_nothing_behind(
            self, tmp_path, monkeypatch):
        """A fold aborted after caching both origins leaves no cache behind.
        The next fold starts empty and still refuses the retired-gate row."""
        import core.audit.gaps as gaps_mod

        project, run_dirs, checklist = self._interleaved(tmp_path, 8, 2)
        builds = self._count_builds(monkeypatch, run_dirs)
        real = gaps_mod._reuse_ineligibility
        calls: list = []

        def boom(*a, **kw):
            calls.append(1)
            if all(n >= 1 for n in builds.values()):
                # Both origins are now cached in this fold: abort it.
                raise RuntimeError("fold aborted")
            return real(*a, **kw)

        with monkeypatch.context() as m:
            m.setattr(gaps_mod, "_reuse_ineligibility", boom)
            # compute_gaps contains a failed project-index fold (logs it
            # and treats prior reviews as absent): nothing is imported.
            aborted_sink, _ = self._fold(project, checklist)
        assert calls  # the fold ran and was aborted mid-way
        assert all(n == 1 for n in builds.values()), builds
        sink, stats = self._fold(project, checklist)
        assert len(sink) == 7
        assert stats.get("app.php:f0") == "retired_prose_clean"
        # The next fold starts from an empty cache: one fresh build each.
        assert all(n == 2 for n in builds.values()), builds

    def test_origin_mutation_between_folds_changes_eligibility(
            self, tmp_path, monkeypatch):
        """Eligibility follows the origin journal's current content. Once the
        row is removed from its origin run, the next fold cannot read it back
        and reuses the stub."""
        # Fold 1 refuses the retired-gate row (read back from its origin
        # run). The origin journal is then rewritten without that row:
        # fold 2 can no longer read it back and reuses the stub (the
        # documented fail-toward-reuse limit) — eligibility follows the
        # journal's current content, never a map retained from fold 1.
        project, run_dirs, checklist = self._interleaved(tmp_path, 4, 2)
        _, stats = self._fold(project, checklist)
        assert stats.get("app.php:f0") == "retired_prose_clean"
        journal = run_dirs[0] / "review-journal.jsonl"
        rows = [json.loads(line) for line in journal.read_text().splitlines()
                if line.strip()]
        kept = [r for r in rows if r.get("function") != "f0"]
        assert len(kept) == len(rows) - 1
        journal.write_text("".join(json.dumps(r) + "\n" for r in kept))
        sink, stats = self._fold(project, checklist)
        assert "app.php:f0" not in stats
        assert "app.php:f0" in sink
