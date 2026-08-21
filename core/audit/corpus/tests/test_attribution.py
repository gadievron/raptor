"""Tests for corpus mechanism attribution."""

from __future__ import annotations

import json

from core.audit.corpus.attribution import (
    SignalIndex,
    annotate_results,
    attribute_row,
    build_signal_index,
    mechanism_matches,
    normalise_expected,
    observed_mechanisms,
)


def _row(fid, expected, actual, *, mechanism="", match=None, **extra):
    row = {
        "function_id": fid,
        "bug_class": "lifecycle",
        "expected": expected,
        "actual": actual,
        "expected_mechanism": mechanism,
        "match": (expected == actual) if match is None else match,
        "hypothesis": "",
        "evidence_tool": "",
    }
    row.update(extra)
    return row


def _write_run_dir(tmp_path, *, audit_log=(), journal=(), mechanical=None):
    """Build a fake audit run directory."""
    d = tmp_path / "run" / "demo-repo"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / ".audit-log.jsonl", "w") as f:
        for e in audit_log:
            f.write(json.dumps(e) + "\n")
    with open(d / "review-journal.jsonl", "w") as f:
        for e in journal:
            f.write(json.dumps(e) + "\n")
    if mechanical is not None:
        (d / "mechanical-findings.json").write_text(json.dumps(mechanical))
    return tmp_path / "run"


class TestNormalise:
    def test_expected_aliases(self):
        assert normalise_expected("anti_self_refute") == "anti_self_refutation"
        assert (
            normalise_expected("refutation:input_bound_t0")
            == "refutation:known_return_type"
        )
        assert normalise_expected(" Concept_Compiler ") == "concept_compiler"

    def test_empty(self):
        assert normalise_expected("") == ""
        assert normalise_expected(None) == ""


class TestMechanismMatches:
    def test_exact_token(self):
        assert mechanism_matches(
            "refutation:known_return_type",
            {"refutation:known_return_type"},
        )

    def test_bare_channel_matches_subtool(self):
        assert mechanism_matches("smt", {"smt:check-early-release", "smt"})
        assert mechanism_matches(
            "dispatch_table", {"dispatch_table:pkt_output"},
        )

    def test_specific_subtool_never_matches_on_channel_alone(self):
        # "some SMT check fired" is not evidence for "this SMT check fired"
        assert not mechanism_matches("smt:check-overflow", {"smt"})
        assert not mechanism_matches(
            "smt:check-overflow", {"smt:check-early-release"},
        )

    def test_no_expected(self):
        assert not mechanism_matches("", {"smt"})


class TestObservedMechanisms:
    def test_row_evidence_tool_yields_token_and_channel(self):
        row = _row("f.c:g", "finding", "finding",
                   evidence_tool="smt:check-early-release")
        obs = observed_mechanisms(row)
        assert "smt:check-early-release" in obs
        assert "smt" in obs

    def test_hypothesis_gate_marker(self):
        row = _row("f.c:g", "clean", "clean",
                   hypothesis="[input_bound_t0: next() returns bounded rune]")
        obs = observed_mechanisms(row)
        assert "refutation:known_return_type" in obs

    def test_unknown_bracket_prefix_ignored(self):
        row = _row("f.c:g", "clean", "clean",
                   hypothesis="[dead-code gate: unreachable]")
        assert observed_mechanisms(row) == set()

    def test_detector_alias(self):
        index = SignalIndex()
        index.add(index.detectors, "f.c:g", "callback_lifetime_cross")
        row = _row("f.c:g", "clean", "clean")
        obs = observed_mechanisms(row, index)
        assert "callback_lifetime" in obs

    def test_empty_row_no_signals(self):
        row = _row("f.c:g", "clean", "clean")
        assert observed_mechanisms(row) == set()

    def test_free_text_evidence_reduced_to_channel(self):
        # llm-claimed:<whole hypothesis sentence> — the prose is not a
        # matchable mechanism identity; keep only the channel
        prose = "llm-claimed:" + "cocci report evaluated and " * 8
        row = _row("f.c:g", "clean", "clean", evidence_tool=prose)
        obs = observed_mechanisms(row)
        assert obs == {"llm-claimed"}


class TestBuildSignalIndex:
    def test_refutation_gate_receipt(self, tmp_path):
        run = _write_run_dir(tmp_path, audit_log=[
            {"action": "refutation_gate", "gate": "contract",
             "key": "src/store/log.c:record_from_disk:120",
             "applied": True},
        ])
        index = build_signal_index([run])
        assert index.gates["src/store/log.c:record_from_disk"] == {
            "contract",
        }

    def test_unapplied_gate_excluded(self, tmp_path):
        run = _write_run_dir(tmp_path, audit_log=[
            {"action": "refutation_gate", "gate": "contract",
             "key": "a.c:f:1", "applied": False},
        ])
        index = build_signal_index([run])
        assert "a.c:f" not in index.gates

    def test_review_and_sweep_evidence_tools(self, tmp_path):
        run = _write_run_dir(tmp_path, audit_log=[
            {"action": "orchestrator_review", "key": "a.c:f:10",
             "status": "clean", "evidence_tool": ""},
            {"action": "sweep_promotion", "key": "a.c:f:10",
             "status": "suspicious",
             "evidence_tool": "smt:check-early-release"},
        ])
        index = build_signal_index([run])
        assert index.tools["a.c:f"] == {"smt:check-early-release"}

    def test_journal_evidence_tools(self, tmp_path):
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "suspicious",
             "evidence_tools": ["cross_function", "joern"]},
        ])
        index = build_signal_index([run])
        assert index.tools["a.c:f"] == {"cross_function", "joern"}

    def test_journal_study_receipts(self, tmp_path):
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "clean",
             "study_receipts": [
                 {"question": "does g() free its arg?", "tier": "callee",
                  "file": "b.c", "line": 10, "sha256": "ab",
                  "verified": True},
             ]},
        ])
        index = build_signal_index([run])
        assert index.tools["a.c:f"] == {"study", "study:callee"}

    def test_study_receipt_without_tier_yields_bare_channel(self, tmp_path):
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "clean",
             "study_receipts": [{"question": "q", "sha256": "ab"}]},
        ])
        index = build_signal_index([run])
        assert index.tools["a.c:f"] == {"study"}

    def test_malformed_study_receipts_skipped(self, tmp_path):
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "clean",
             "study_receipts": ["not-a-dict", 7]},
        ])
        index = build_signal_index([run])
        assert "a.c:f" not in index.tools

    def test_mechanical_detectors(self, tmp_path):
        run = _write_run_dir(tmp_path, mechanical={
            "a.c:f": [{"detector": "callback_lifetime_cross", "line": 5}],
        })
        index = build_signal_index([run])
        assert index.detectors["a.c:f"] == {"callback_lifetime_cross"}

    def test_malformed_lines_skipped(self, tmp_path):
        d = tmp_path / "run" / "repo"
        d.mkdir(parents=True)
        (d / ".audit-log.jsonl").write_text("not json\n{\n")
        (d / "review-journal.jsonl").write_text("]]]\n")
        index = build_signal_index([tmp_path / "run"])
        assert index.tools == {}
        assert index.gates == {}

    def test_missing_dir_ignored(self, tmp_path):
        index = build_signal_index([tmp_path / "nope"])
        assert index.tools == {}


class TestAttributeRow:
    def test_attributed(self, tmp_path):
        run = _write_run_dir(tmp_path, audit_log=[
            {"action": "refutation_gate", "gate": "input_bound_t0",
             "key": "lex/lexer.go:readNumber:381",
             "applied": True},
        ])
        index = build_signal_index([run])
        row = _row("lex/lexer.go:readNumber", "clean", "clean",
                   mechanism="refutation:known_return_type")
        attr = attribute_row(row, index)
        assert attr["attribution"] == "attributed"
        assert attr["mechanism_match"] is True

    def test_study_expectation_attributes(self, tmp_path):
        # Labels with expected_mechanism "study" bind through the
        # journal's study_receipts — previously they could only ever
        # land unattributed (the study channel writes no
        # evidence_tool of its own).
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "clean",
             "study_receipts": [
                 {"question": "q", "tier": "callee", "sha256": "ab",
                  "verified": True},
             ]},
        ])
        index = build_signal_index([run])
        row = _row("a.c:f", "clean", "clean", mechanism="study")
        attr = attribute_row(row, index)
        assert attr["attribution"] == "attributed"
        assert "study" in attr["observed_mechanisms"]
        assert "study:callee" in attr["observed_mechanisms"]

    def test_study_tier_expectation_needs_exact_tier(self, tmp_path):
        run = _write_run_dir(tmp_path, journal=[
            {"file": "a.c", "function": "f", "verdict": "clean",
             "study_receipts": [
                 {"question": "q", "tier": "callee", "sha256": "ab"},
             ]},
        ])
        index = build_signal_index([run])
        matched = _row("a.c:f", "clean", "clean", mechanism="study:callee")
        assert attribute_row(matched, index)["attribution"] == "attributed"
        other = _row("a.c:f", "clean", "clean", mechanism="study:concept")
        assert attribute_row(other, index)["attribution"] == "misattributed"

    def test_misattributed_the_dangerous_quiet_cell(self):
        # Right verdict, but produced by the triage classifier —
        # the expected refutation gate was never exercised.
        row = _row("a.c:f", "clean", "clean",
                   mechanism="refutation:contract",
                   evidence_tool="triage:classifier")
        attr = attribute_row(row)
        assert attr["attribution"] == "misattributed"
        assert attr["mechanism_match"] is False
        assert "triage:classifier" in attr["observed_mechanisms"]

    def test_unattributed_no_receipt(self):
        row = _row("a.c:f", "clean", "clean",
                   mechanism="refutation:contract")
        attr = attribute_row(row)
        assert attr["attribution"] == "unattributed"
        assert attr["observed_mechanisms"] == []

    def test_wrong_verdict_dominates(self):
        row = _row("a.c:f", "finding", "clean",
                   mechanism="dispatch_table", match=False,
                   evidence_tool="dispatch_table:widget")
        attr = attribute_row(row)
        assert attr["attribution"] == "wrong_verdict"

    def test_error_dominates(self):
        row = _row("a.c:f", "finding", "error",
                   mechanism="dispatch_table", match=False)
        attr = attribute_row(row)
        assert attr["attribution"] == "error"

    def test_no_expectation(self):
        row = _row("a.c:f", "clean", "clean", evidence_tool="smt:x")
        attr = attribute_row(row)
        assert attr["attribution"] == "no_expectation"
        assert attr["mechanism_match"] is None


class TestAnnotateResults:
    def test_annotates_in_place_with_receipts(self, tmp_path):
        run = _write_run_dir(tmp_path, audit_log=[
            {"action": "refutation_gate", "gate": "architecture",
             "key": "src/core/queue.c:queue_drain:100", "applied": True},
        ])
        results = [
            _row("src/core/queue.c:queue_drain", "clean", "clean",
                 mechanism="refutation:architecture"),
        ]
        annotated, receipt_dirs = annotate_results(results, [run])
        assert annotated == 1
        assert receipt_dirs == 1
        assert results[0]["attribution"] == "attributed"

    def test_no_run_dirs_degrades_to_row_level(self, tmp_path):
        results = [
            _row("a.c:f", "clean", "clean",
                 mechanism="refutation:contract",
                 hypothesis="[contract: caller guarantees non-null]"),
        ]
        annotated, receipt_dirs = annotate_results(
            results, [tmp_path / "missing"],
        )
        assert receipt_dirs == 0
        # row-level signal still attributed
        assert results[0]["attribution"] == "attributed"
