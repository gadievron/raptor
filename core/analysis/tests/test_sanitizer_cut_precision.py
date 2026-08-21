"""Tests for the sanitizer-cut zero-false-suppress precision harness
and the record-only enforcement gate around it."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.analysis.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_SUPPRESS,
    SanitizerCutResult,
    record_sanitizer_cut_suppression,
)
from core.analysis.sanitizer_cut_precision import (
    LABEL_MAY_SUPPRESS,
    LABEL_MUST_NOT_SUPPRESS,
    CutFixture,
    FixtureMeasurement,
    build_corpus,
    main,
    run_corpus,
)
from core.testing.treesitter import requires_ts


# ---------------------------------------------------------------------------
# Corpus integrity
# ---------------------------------------------------------------------------


class TestCorpusIntegrity:
    def test_fixture_names_unique(self):
        names = [f.name for f in build_corpus()]
        assert len(names) == len(set(names))

    def test_every_covered_class_has_adversarial_battery(self):
        by_class: dict[str, list[CutFixture]] = {}
        for f in build_corpus():
            by_class.setdefault(f.sink_class, []).append(f)
        for cls in ("xss", "cmdi", "pathtrav"):
            labels = [f.label for f in by_class[cls]]
            assert labels.count(LABEL_MUST_NOT_SUPPRESS) >= 8, cls
            assert labels.count(LABEL_MAY_SUPPRESS) >= 2, cls
        # The catalog-empty class is represented so a python sqli
        # finding can never be suppressed unnoticed.
        assert "sqli" in by_class

    def test_fixture_sanitizers_match_catalog(self):
        """The safe fixtures use REAL catalog sanitizers for their
        class; the wrong-class fixtures use a sanitizer that is NOT
        in the catalog for the fixture's CWE. Pins the corpus to the
        catalog so a catalog rename can't silently hollow it out."""
        from core.dataflow.sanitizer_catalog import (
            sanitizer_callables_for_cwe,
        )
        for f in build_corpus():
            if f.language != "python":
                continue
            catalog = sanitizer_callables_for_cwe(f.cwe, "python")
            if f.shape in ("straight_line", "symmetric_branches"):
                assert any(c in f.source for c in catalog), f.name
            if f.shape == "wrong_class_sanitizer":
                # The sanitizer called in the fixture must not be a
                # catalog entry for this CWE.
                called = [c for c in catalog if c in f.source]
                assert not called, (f.name, called)


# ---------------------------------------------------------------------------
# The gate itself
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def report():
    return run_corpus()


class TestPrecisionGate:
    def test_zero_false_suppressions(self, report):
        """THE gate metric. A failure here means an adversarial shape
        (a fixture with a real or unprovable flaw) received the
        suppress verdict — the sanitizer-cut witness must not be
        allowed anywhere near enforcement until this is clean."""
        assert report.false_suppressions == []

    def test_rule_of_three_ub_reported_when_clean(self, report):
        assert report.n_must_not >= 20
        assert report.rule_of_three_95_ub == pytest.approx(
            3.0 / report.n_must_not)

    @requires_ts("java")
    def test_all_safe_shapes_suppress(self, report):
        """Utility pin: every may-suppress fixture currently earns the
        suppress verdict. Not a gate condition (soundness first), but
        a regression here means the gate lost coverage it had.

        Needs the Java grammar: the corpus's Java may-suppress
        fixtures degrade to ``unresolved`` without it (a refusal, so
        the soundness gate above still runs everywhere — only this
        utility pin skips)."""
        assert report.missed_suppressions == []

    def test_cross_tab_covers_classes(self, report):
        for cls in ("xss", "cmdi", "pathtrav", "sqli"):
            assert cls in report.cross_tab

    def test_report_dict_shape(self, report):
        d = report.to_dict()
        for key in ("corpus", "n_fixtures", "n_must_not_suppress",
                    "verdict_counts", "false_suppressions", "cross_tab",
                    "rule_of_three_95_upper_bound_false_suppress_rate",
                    "toolchain", "measurements"):
            assert key in d, key
        assert d["toolchain"].get("python")

    def test_main_writes_reports_and_exits_zero(self, tmp_path):
        rc = main(["--out", str(tmp_path)])
        assert rc == 0
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["false_suppressions"] == []
        assert "Gate clean" in (tmp_path / "report.md").read_text()

    def test_false_suppress_measurement_property(self):
        m = FixtureMeasurement(
            name="x", sink_class="xss", shape="s",
            label=LABEL_MUST_NOT_SUPPRESS, verdict="suppress")
        assert m.false_suppress
        m2 = FixtureMeasurement(
            name="x", sink_class="xss", shape="s",
            label=LABEL_MUST_NOT_SUPPRESS, verdict="candidate_only")
        assert not m2.false_suppress


# ---------------------------------------------------------------------------
# Record-only enforcement semantics
# ---------------------------------------------------------------------------


def _result(verdict: str) -> SanitizerCutResult:
    return SanitizerCutResult(
        suppress=(verdict == VERDICT_SUPPRESS),
        reason="test",
        cut_set=frozenset(),
        candidate_callables=frozenset({"html.escape"}),
        verdict=verdict,
    )


def _read_records(out_dir: Path) -> list[dict]:
    path = out_dir / "suppressions.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)
            for line in path.read_text().splitlines() if line.strip()]


class TestRecordOnlyEnforcement:
    def test_suppress_verdict_records_dropped_false_by_default(
            self, tmp_path):
        record_sanitizer_cut_suppression(
            tmp_path, {"file_path": "a.py", "line": 3},
            _result(VERDICT_SUPPRESS))
        (rec,) = _read_records(tmp_path)
        assert rec["verdict"] == "sanitizer_dominated"
        assert rec["dropped"] is False
        assert rec["enforced"] is False

    def test_suppress_verdict_with_enforce_records_dropped_true(
            self, tmp_path):
        record_sanitizer_cut_suppression(
            tmp_path, {"file_path": "a.py", "line": 3},
            _result(VERDICT_SUPPRESS), enforce=True)
        (rec,) = _read_records(tmp_path)
        assert rec["dropped"] is True
        assert rec["enforced"] is True

    def test_candidate_only_never_dropped_even_enforced(self, tmp_path):
        record_sanitizer_cut_suppression(
            tmp_path, {"file_path": "a.py", "line": 3},
            _result(VERDICT_CANDIDATE_ONLY), enforce=True)
        (rec,) = _read_records(tmp_path)
        assert rec["verdict"] == "sanitizer_candidate"
        assert rec["dropped"] is False


# ---------------------------------------------------------------------------
# Witness registry
# ---------------------------------------------------------------------------


class TestWitnessRegistry:
    def test_sanitizer_dominated_spec(self):
        from core.analysis.reach_witness import (
            STRUCTURALLY_SUPPRESSIBLE_KINDS,
            VERDICTS,
            Soundness,
            WitnessKind,
        )
        spec = VERDICTS["sanitizer_dominated"]
        assert spec.kind is WitnessKind.SANITIZER_CUT
        assert spec.soundness is Soundness.SOUND
        # Re-pinned 2026-08-19: earns_suppression flipped True under
        # the corpus-earning protocol with operator approval (b46
        # re-attempt; attestation report sha256 139a3f07…, 239
        # fixtures, zero false suppressions). The safety property
        # moved from "the earned set excludes it" to "enforcement is
        # bounded by this spec field" — reverting to record-only is
        # this one field (test_enforcement_bounded_by_spec).
        assert spec.earns_suppression is True
        # The earned set is DERIVED from the table, so the kind joins
        # it with the flip; the chokepoint-safety property is guarded
        # by test_chokepoint_never_fires_on_sanitizer_cut (a planted
        # sanitizer-cut tag in the function-verdict slot still yields
        # None).
        assert WitnessKind.SANITIZER_CUT in STRUCTURALLY_SUPPRESSIBLE_KINDS

    def test_chokepoint_never_fires_on_sanitizer_cut(self):
        # Re-pinned 2026-08-19 (b46 flip): may_suppress now returns
        # True — the earned contract. The chokepoint-safety property
        # this test guarded survives structurally: the FUNCTION-
        # REACHABILITY chokepoint's input stream carries function
        # classifications (absent/symbol_present/...), never the
        # sanitizer-cut verdict tag — the enforcement consumer is the
        # scan post-pass alone, full-proof suppress verdicts only.
        from core.analysis.reach_chokepoint import check_suppress
        from core.analysis.reach_witness import (
            STRUCTURALLY_SUPPRESSIBLE_KINDS,
            verdict_from_classification,
        )
        v = verdict_from_classification("sanitizer_dominated")
        assert v.may_suppress(STRUCTURALLY_SUPPRESSIBLE_KINDS)
        # The chokepoint consumes per-FUNCTION reachability verdicts
        # from the checklist; a sanitizer-cut tag planted in that slot
        # must still not license suppression there (the enforcement
        # consumer is the postpass alone).
        assert check_suppress(
            checklist={"files": {"src/T.java": {"functions": {"f": {
                "binary_oracle": {"verdict": "sanitizer_dominated"},
            }}}}},
            file_path="src/T.java",
            function_name="f",
            line=1,
            repo_root=Path("/nonexistent"),
        ) is None


# ---------------------------------------------------------------------------
# Live record-only wiring (config → smt_barrier → suppressions.jsonl)
# ---------------------------------------------------------------------------


class TestAuditWiring:
    @pytest.fixture(autouse=True)
    def _reset_config(self):
        import os

        from core.dataflow import sanitizer_cut_config
        yield
        sanitizer_cut_config.reset()
        # configure(export_env=True) WRITES these; monkeypatch.delenv
        # on an initially-absent var registers no undo, so scrub
        # explicitly or the gate silently turns on for later tests.
        for var in (
            "RAPTOR_SANITIZER_CUT",
            "RAPTOR_SANITIZER_CUT_NO_LEXICAL",
            "RAPTOR_SANITIZER_CUT_PARITY_LOG",
            "RAPTOR_SANITIZER_CUT_AUDIT_DIR",
        ):
            os.environ.pop(var, None)

    def test_config_audit_dir_resolution(self, tmp_path):
        from core.dataflow import sanitizer_cut_config as sc
        assert sc.config_for_mode(
            "on", run_dir=str(tmp_path)).audit_dir == str(tmp_path)
        assert sc.config_for_mode(
            "strict", run_dir=str(tmp_path)).audit_dir == str(tmp_path)
        assert sc.config_for_mode("off", run_dir=str(tmp_path)).audit_dir \
            is None
        assert sc.config_for_mode(
            "shadow", run_dir=str(tmp_path)).audit_dir is None
        assert sc.config_for_mode("on").audit_dir is None

    def test_audit_dir_env_round_trip(self, tmp_path, monkeypatch):
        from core.dataflow import sanitizer_cut_config as sc
        monkeypatch.delenv("RAPTOR_SANITIZER_CUT", raising=False)
        monkeypatch.delenv("RAPTOR_SANITIZER_CUT_AUDIT_DIR", raising=False)
        sc.configure("on", run_dir=str(tmp_path), export_env=True)
        sc.reset()  # force env fallback resolution
        cfg = sc.current()
        assert cfg.value_bound_enabled
        assert cfg.audit_dir == str(tmp_path)

    def test_gate_run_writes_record_only_audit(self, tmp_path):
        """End to end: gate on + run dir configured → a suppressing
        finding leaves a sanitizer_dominated evidence record with
        dropped=false; the dominance verdict itself is unchanged."""
        from core.dataflow import sanitizer_cut_config as sc
        from core.dataflow.smt_barrier import _value_bound_dominates

        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        fixture = tmp_path / "safe.py"
        fixture.write_text(src, encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        sc.configure("on", run_dir=str(run_dir))

        verdict = _value_bound_dominates(
            file_path=str(fixture), validator_line=1, sink_line=3,
            cwe="CWE-79", language="python",
        )
        assert verdict is True
        (rec,) = _read_records(run_dir)
        assert rec["verdict"] == "sanitizer_dominated"
        assert rec["dropped"] is False
        assert rec["enforced"] is False
        assert rec["file_path"] == str(fixture)

    def test_gate_run_without_audit_dir_writes_nothing(self, tmp_path):
        from core.dataflow import sanitizer_cut_config as sc
        from core.dataflow.smt_barrier import _value_bound_dominates

        fixture = tmp_path / "safe.py"
        fixture.write_text(
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n", encoding="utf-8")
        sc.configure("on")  # no run_dir → no audit dir

        verdict = _value_bound_dominates(
            file_path=str(fixture), validator_line=1, sink_line=3,
            cwe="CWE-79", language="python",
        )
        assert verdict is True
        assert not (tmp_path / "suppressions.jsonl").exists()
