"""Tests for core.audit.layer_resolution."""

from __future__ import annotations

import json
import logging

from core.audit.evidence_grade import Confidence
from core.audit.layer_resolution import (
    CpgConfidence,
    Disagreement,
    DisagreementKind,
    LayerClaim,
    LayerVerdict,
    ObservationRecord,
    ObservationStatus,
    adjust_triage_for_cpg_confidence,
    assign_observation_status,
    cap_confidence_for_unobserved,
    cpg_reachability_weight,
    format_disagreement_summary,
    get_cpg_profile,
    resolve_disagreement,
    write_disagreements,
    write_observation_records,
)


class TestCpgProfiles:
    def test_c_is_high(self):
        p = get_cpg_profile("c")
        assert p.cpg_confidence == CpgConfidence.HIGH
        assert p.reachability_weight >= 0.9

    def test_python_is_moderate(self):
        p = get_cpg_profile("python")
        assert p.cpg_confidence == CpgConfidence.MODERATE
        assert 0.5 < p.reachability_weight < 0.8

    def test_ruby_is_low(self):
        p = get_cpg_profile("ruby")
        assert p.cpg_confidence == CpgConfidence.LOW
        assert p.reachability_weight < 0.5

    def test_unknown_language_gets_default(self):
        p = get_cpg_profile("brainfuck")
        assert p.cpg_confidence == CpgConfidence.MODERATE

    def test_case_insensitive(self):
        p = get_cpg_profile("Java")
        assert p.cpg_confidence == CpgConfidence.HIGH

    def test_weight_helper(self):
        assert cpg_reachability_weight("c") > cpg_reachability_weight("ruby")


class TestDisagreementResolution:
    def test_no_disagreement_when_layers_agree(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=True)
        llm_c = LayerClaim(layer=LayerVerdict.LLM, reachable=True)
        result = resolve_disagreement("a.c", "foo", mechanical=m, llm=llm_c)
        assert result is None

    def test_mechanical_wins_without_evasion(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=False)
        llm_c = LayerClaim(layer=LayerVerdict.LLM, reachable=True)
        d = resolve_disagreement("a.c", "foo", mechanical=m, llm=llm_c, language="c")
        assert d is not None
        assert d.winner == LayerVerdict.MECHANICAL
        assert "no valid evasion" in d.resolution

    def test_llm_wins_with_valid_evasion_low_cpg(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=False)
        llm_c = LayerClaim(
            layer=LayerVerdict.LLM, reachable=True,
            evasion_mechanism="callback",
        )
        d = resolve_disagreement("a.rb", "foo", mechanical=m, llm=llm_c, language="ruby")
        assert d is not None
        assert d.winner == LayerVerdict.LLM
        assert "accepted" in d.resolution

    def test_llm_plausible_with_valid_evasion_high_cpg(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=False)
        llm_c = LayerClaim(
            layer=LayerVerdict.LLM, reachable=True,
            evasion_mechanism="vtable",
        )
        d = resolve_disagreement("a.c", "foo", mechanical=m, llm=llm_c, language="c")
        assert d is not None
        assert d.winner == LayerVerdict.LLM
        assert "plausible" in d.resolution

    def test_invalid_evasion_rejected(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=False)
        llm_c = LayerClaim(
            layer=LayerVerdict.LLM, reachable=True,
            evasion_mechanism="i_think_it_exists",
        )
        d = resolve_disagreement("a.c", "foo", mechanical=m, llm=llm_c, language="c")
        assert d is not None
        assert d.winner == LayerVerdict.MECHANICAL
        assert "rejected" in d.resolution

    def test_dynamic_positive_wins(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=False)
        dyn = LayerClaim(layer=LayerVerdict.DYNAMIC, reachable=True)
        d = resolve_disagreement("a.c", "foo", mechanical=m, dynamic=dyn)
        assert d is not None
        assert d.winner == LayerVerdict.DYNAMIC
        assert "confirms" in d.resolution

    def test_frida_absence_not_negative_evidence(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=True)
        dyn = LayerClaim(layer=LayerVerdict.DYNAMIC, reachable=False)
        d = resolve_disagreement("a.c", "foo", mechanical=m, dynamic=dyn)
        assert d is not None
        assert d.winner == LayerVerdict.MECHANICAL
        assert "not evidence of absence" in d.resolution

    def test_single_claim_returns_none(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=True)
        result = resolve_disagreement("a.c", "foo", mechanical=m)
        assert result is None

    def test_all_three_kind(self):
        m = LayerClaim(layer=LayerVerdict.MECHANICAL, reachable=True)
        llm_c = LayerClaim(layer=LayerVerdict.LLM, reachable=False)
        dyn = LayerClaim(layer=LayerVerdict.DYNAMIC, reachable=True)
        d = resolve_disagreement("a.c", "foo", mechanical=m, llm=llm_c, dynamic=dyn)
        assert d is not None
        assert d.kind == DisagreementKind.ALL_THREE

    def test_disagreement_to_dict(self):
        d = Disagreement(
            file="a.c", function="foo",
            kind=DisagreementKind.MECHANICAL_VS_LLM,
            mechanical_claim=LayerClaim(
                layer=LayerVerdict.MECHANICAL, reachable=False,
            ),
            llm_claim=LayerClaim(
                layer=LayerVerdict.LLM, reachable=True,
                evasion_mechanism="callback",
            ),
            resolution="test", winner=LayerVerdict.LLM,
        )
        data = d.to_dict()
        assert data["file"] == "a.c"
        assert data["kind"] == "mechanical_vs_llm"
        assert data["winner"] == "llm"
        assert "mechanical" in data
        assert "llm" in data


class TestObservationStatus:
    def test_not_observable_without_frida(self):
        rec = assign_observation_status("a.c", "foo", frida_available=False)
        assert rec.status == ObservationStatus.NOT_OBSERVABLE

    def test_observed_when_in_set(self):
        obs = frozenset({"a.c:foo"})
        rec = assign_observation_status(
            "a.c", "foo", frida_available=True,
            observed_functions=obs, observation_runs=1,
        )
        assert rec.status == ObservationStatus.OBSERVED

    def test_unobserved_when_not_in_set(self):
        obs = frozenset({"a.c:bar"})
        rec = assign_observation_status(
            "a.c", "foo", frida_available=True,
            observed_functions=obs, observation_runs=2,
        )
        assert rec.status == ObservationStatus.UNOBSERVED
        assert rec.observation_runs == 2

    def test_observation_record_to_dict(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.OBSERVED,
            coverage_pct=75.0, observation_runs=1,
        )
        d = rec.to_dict()
        assert d["status"] == "observed"
        assert d["coverage_pct"] == 75.0


class TestConfidenceCapping:
    def test_high_capped_to_medium_when_unobserved_twice(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.UNOBSERVED,
            observation_runs=2,
        )
        result = cap_confidence_for_unobserved(Confidence.HIGH, rec)
        assert result == Confidence.MEDIUM

    def test_medium_unchanged_when_unobserved(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.UNOBSERVED,
            observation_runs=2,
        )
        result = cap_confidence_for_unobserved(Confidence.MEDIUM, rec)
        assert result == Confidence.MEDIUM

    def test_high_unchanged_when_observed(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.OBSERVED,
            observation_runs=1,
        )
        result = cap_confidence_for_unobserved(Confidence.HIGH, rec)
        assert result == Confidence.HIGH

    def test_high_unchanged_after_only_one_run(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.UNOBSERVED,
            observation_runs=1,
        )
        result = cap_confidence_for_unobserved(Confidence.HIGH, rec)
        assert result == Confidence.HIGH

    def test_not_observable_no_cap(self):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.NOT_OBSERVABLE,
        )
        result = cap_confidence_for_unobserved(Confidence.HIGH, rec)
        assert result == Confidence.HIGH


class TestTriageAdjustment:
    def test_c_joern_not_reachable_suppresses(self):
        assert adjust_triage_for_cpg_confidence(True, "c") is True

    def test_ruby_joern_not_reachable_does_not_suppress(self):
        assert adjust_triage_for_cpg_confidence(True, "ruby") is False

    def test_python_joern_not_reachable_does_not_suppress(self):
        assert adjust_triage_for_cpg_confidence(True, "python") is False

    def test_go_joern_not_reachable_suppresses(self):
        assert adjust_triage_for_cpg_confidence(True, "go") is True

    def test_reachable_not_suppressed(self):
        assert adjust_triage_for_cpg_confidence(False, "c") is False


class TestPersistence:
    def test_write_disagreements(self, tmp_path):
        d = Disagreement(
            file="a.c", function="foo",
            kind=DisagreementKind.MECHANICAL_VS_LLM,
            resolution="test", winner=LayerVerdict.MECHANICAL,
        )
        path = write_disagreements([d], tmp_path)
        assert path is not None
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["file"] == "a.c"

    def test_write_empty_disagreements(self, tmp_path):
        result = write_disagreements([], tmp_path)
        assert result is None

    def test_write_observation_records(self, tmp_path):
        rec = ObservationRecord(
            file="a.c", function="foo",
            status=ObservationStatus.OBSERVED,
        )
        path = write_observation_records([rec], tmp_path)
        assert path is not None
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["status"] == "observed"

    def test_write_empty_observations(self, tmp_path):
        result = write_observation_records([], tmp_path)
        assert result is None

    def test_successful_write_logs_count_and_path(self, tmp_path, caplog):
        records = [
            ObservationRecord(
                file="a.c", function="f",
                status=ObservationStatus.OBSERVED,
                observation_runs=1,
            ),
            ObservationRecord(
                file="b.c", function="g",
                status=ObservationStatus.UNOBSERVED,
                observation_runs=2,
            ),
        ]

        with caplog.at_level(logging.INFO, logger="core.audit.layer_resolution"):
            path = write_observation_records(records, tmp_path)

        assert path == tmp_path / "observation-status.json"
        data = json.loads(path.read_text())
        assert len(data) == 2

        msgs = [r.getMessage() for r in caplog.records]
        assert any(
            "2" in m and "observation record" in m and str(path) in m
            for m in msgs
        ), f"expected write log line, got: {msgs}"

    def test_empty_records_no_write_no_log(self, tmp_path, caplog):
        with caplog.at_level(logging.INFO, logger="core.audit.layer_resolution"):
            assert write_observation_records([], tmp_path) is None
        assert not (tmp_path / "observation-status.json").exists()
        assert not caplog.records


class TestFormatSummary:
    def test_empty_summary(self):
        s = format_disagreement_summary([])
        assert "no disagreements" in s

    def test_summary_with_items(self):
        items = [
            Disagreement(
                file="a.c", function="f1",
                kind=DisagreementKind.MECHANICAL_VS_LLM,
            ),
            Disagreement(
                file="b.c", function="f2",
                kind=DisagreementKind.MECHANICAL_VS_LLM,
            ),
            Disagreement(
                file="c.c", function="f3",
                kind=DisagreementKind.LLM_VS_DYNAMIC,
            ),
        ]
        s = format_disagreement_summary(items)
        assert "3 disagreements" in s
        assert "mechanical_vs_llm=2" in s
