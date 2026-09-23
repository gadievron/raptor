"""Persisted disagreement samples must be secret-redacted at rest.

Models occasionally quote a tool-output snippet containing an API key
or Bearer token in their reasoning; the scorecard sidecar is designed
to outlive the run, so an unredacted sample parks the secret on disk
indefinitely. Redaction is applied at the single sink every producer
funnels through (``ModelScorecard._append_sample``) — pre-fix it was a
per-producer responsibility and only one of seven producers did it.

Each test drives a key-shaped string through one producer's public
entrypoint and asserts the ON-DISK sidecar no longer contains it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.llm.scorecard.scorecard import ModelScorecard

# Matches core.security.redaction's OpenAI/Anthropic key shape
# (sk- prefix + long body).
SECRET = "sk-ant-api03-" + "A" * 40


@pytest.fixture
def sc_path(tmp_path: Path) -> Path:
    return tmp_path / "sc.json"


@pytest.fixture
def scorecard(sc_path: Path) -> ModelScorecard:
    return ModelScorecard(sc_path, shadow_rate=0.0)


def _assert_redacted_at_rest(sc_path: Path) -> None:
    raw = sc_path.read_text()
    assert SECRET not in raw, "key-shaped string persisted unredacted"
    assert "[REDACTED" in raw, "expected a redaction marker in a sample"
    # The samples themselves must still be present and well-formed.
    data = json.loads(raw)
    samples = [
        s
        for by_dc in data["models"].values()
        for cell in by_dc.values()
        for s in cell.get("disagreement_samples", [])
    ]
    assert samples, "no disagreement sample was persisted"


class TestSinkEntrypoints:
    """All three sample-append entrypoints redact."""

    def test_record_event(self, scorecard, sc_path):
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": f"key was {SECRET} in output"},
        )
        _assert_redacted_at_rest(sc_path)

    def test_record_events_batch(self, scorecard, sc_path):
        scorecard.record_events([{
            "decision_class": "agentic:r1",
            "model": "m1",
            "event_type": "multi_model_consensus",
            "outcome": "incorrect",
            "sample": {"this_reasoning": f"quoting {SECRET}"},
        }])
        _assert_redacted_at_rest(sc_path)

    def test_claim_and_record_tool_evidence(self, scorecard, sc_path):
        assert scorecard.claim_and_record_tool_evidence(
            "agentic:r1", "m1", "f1", "incorrect",
            sample={"this_reasoning": f"tool printed {SECRET}"},
        )
        _assert_redacted_at_rest(sc_path)

    def test_non_string_scalar_values_preserved(self, scorecard, sc_path):
        """Numeric/bool/None leaves carry no text and pass through."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": SECRET, "hops": 3, "sure": True,
                    "extra": None},
        )
        data = json.loads(sc_path.read_text())
        cell = data["models"]["m1"]["agentic:r1"]
        s = cell["disagreement_samples"][0]
        assert s["hops"] == 3
        assert s["sure"] is True
        assert s["extra"] is None
        _assert_redacted_at_rest(sc_path)

    def test_secret_inside_list_value_redacted(self, scorecard, sc_path):
        """Redaction descends containers: a str-leaves-only pass let a
        full key persist inside a list value."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": [f"step 1 saw {SECRET}", "step 2"]},
        )
        data = json.loads(sc_path.read_text())
        cell = data["models"]["m1"]["agentic:r1"]
        val = cell["disagreement_samples"][0]["this_reasoning"]
        assert isinstance(val, list) and len(val) == 2
        assert val[1] == "step 2"
        _assert_redacted_at_rest(sc_path)

    def test_secret_inside_nested_dict_and_tuple_redacted(
        self, scorecard, sc_path,
    ):
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": {
                "chain": ({"quote": f"key {SECRET}"}, 7),
                "n": 2,
            }},
        )
        data = json.loads(sc_path.read_text())
        cell = data["models"]["m1"]["agentic:r1"]
        val = cell["disagreement_samples"][0]["this_reasoning"]
        assert val["n"] == 2
        assert val["chain"][1] == 7
        _assert_redacted_at_rest(sc_path)

    def test_secret_as_dict_key_redacted(self, scorecard, sc_path):
        """Dict KEYS join the pass at every nesting level: a
        secret-bearing string used as a key (an LLM-echoed header
        dict riding a model-derived sample tree) reaches json.dump
        just as well as a value — keys were the one shape that
        skipped redaction."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": {
                "headers": {f"x-api-key: {SECRET}": "present"},
            }},
        )
        _assert_redacted_at_rest(sc_path)

    def test_legit_keys_preserved(self, scorecard, sc_path):
        """Both directions: ordinary key names survive the key pass
        byte-identical — consumers address samples by key."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": {
                "chain": {"quote": f"key {SECRET}", "step": 1},
            }},
        )
        data = json.loads(sc_path.read_text())
        cell = data["models"]["m1"]["agentic:r1"]
        val = cell["disagreement_samples"][0]["this_reasoning"]
        assert set(val.keys()) == {"chain"}
        assert set(val["chain"].keys()) == {"quote", "step"}
        assert val["chain"]["step"] == 1
        _assert_redacted_at_rest(sc_path)

    def test_exotic_type_coerced_and_redacted(self, scorecard, sc_path):
        """A non-JSON type is str-coerced then redacted — the
        fail-safe direction; type can never bypass the pass."""

        class Blob:
            def __str__(self) -> str:
                return f"blob carrying {SECRET}"

        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": Blob()},
        )
        _assert_redacted_at_rest(sc_path)

    def test_cross_family_list_trigger_redacted_at_rest(
        self, scorecard, sc_path,
    ):
        """Producer-drift shape from review: an upstream list in the
        cross-family trigger slot must not smuggle a nested secret to
        disk (str-coerced at the producer; the sink descends anyway)."""
        from core.llm.scorecard.cross_family import (
            record_cross_family_outcomes,
        )

        n = record_cross_family_outcomes(
            scorecard,
            results_by_id={"f1": {
                "rule_id": "r1",
                "cross_family_check": {
                    "verdict": "disputed",
                    "checker_model": "m2",
                    "trigger": ["verdict-flip", {"ctx": SECRET}],
                    "checker_ruling": "cr",
                },
            }},
        )
        assert n == 1
        _assert_redacted_at_rest(sc_path)


class TestProducerPaths:
    def test_consensus(self, scorecard, sc_path):
        from core.llm.scorecard.consensus import record_consensus_outcomes

        n = record_consensus_outcomes(
            scorecard,
            correlation={
                "agreement_matrix": {"f1": {
                    "pro": {"is_exploitable": True},
                    "opus": {"is_exploitable": True},
                    "flash": {"is_exploitable": False},
                }},
                "confidence_signals": {"f1": "disputed"},
            },
            results_by_id={"f1": {"rule_id": "r1"}},
            per_finding_results={"f1": [
                {"analysed_by": "flash",
                 "reasoning": f"saw {SECRET} in the tool output"},
            ]},
        )
        assert n == 3
        _assert_redacted_at_rest(sc_path)

    def test_judge(self, scorecard, sc_path):
        from core.llm.scorecard.judge import record_judge_outcomes

        n = record_judge_outcomes(
            scorecard,
            results_by_id={"f1": {
                "judge": "disputed",
                "rule_id": "r1",
                "analysed_by": "primary",
                "is_exploitable": True,
                "reasoning": f"primary cited {SECRET}",
                "judge_analyses": [
                    {"model": "j1", "is_exploitable": True,
                     "reasoning": "agree"},
                    {"model": "j2", "is_exploitable": False,
                     "reasoning": f"dissent, key {SECRET}"},
                ],
            }},
            primary_verdicts_before_judge={"f1": False},
        )
        assert n == 3
        _assert_redacted_at_rest(sc_path)

    def test_prefilter(self, scorecard, sc_path):
        from core.llm.scorecard.prefilter import record_prefilter_outcome

        record_prefilter_outcome(
            scorecard,
            decision_class="agentic:r1",
            model="m1",
            cheap_says_fp=True,
            full_says_fp=False,
            cheap_reasoning=f"cheap saw {SECRET}",
            full_reasoning=f"full saw {SECRET}",
        )
        _assert_redacted_at_rest(sc_path)

    def test_tool_evidence(self, scorecard, sc_path):
        from core.llm.scorecard.tool_evidence import (
            record_tool_evidence_outcome,
        )

        assert record_tool_evidence_outcome(
            scorecard,
            model="m1",
            rule_id="r1",
            analysis_verdict=True,
            validation_verdict=False,
            finding_id="f1",
            analysis_reasoning=f"exploitable because {SECRET}",
        )
        _assert_redacted_at_rest(sc_path)

    def test_stability(self, scorecard, sc_path, tmp_path):
        from core.llm.scorecard.stability import record_cross_run_stability

        def result(verdict: bool) -> dict:
            return {
                "finding_id": "f1",
                "is_exploitable": verdict,
                "is_true_positive": verdict,
                "rule_id": "r1",
                "analysed_by": "m1",
                "resolved_model": "m1",
                "reasoning": f"verdict flip mentioning {SECRET}",
            }

        prior = tmp_path / "agentic_20260101_000000_pid1_1"
        prior.mkdir()
        (prior / ".raptor-run.json").write_text(json.dumps({
            "target": "/tmp/target", "status": "completed",
            "command": "agentic", "timestamp": "2026-01-01T00:00:00Z",
        }))
        (prior / "orchestrated_report.json").write_text(
            json.dumps({"results": [result(True)]}),
        )
        current = tmp_path / "agentic_20260102_000000_pid2_2"
        current.mkdir()
        (current / ".raptor-run.json").write_text(json.dumps({
            "target": "/tmp/target", "status": "running",
            "command": "agentic", "timestamp": "2026-01-02T00:00:00Z",
        }))

        n = record_cross_run_stability(
            scorecard, out_dir=current,
            results_by_id={"f1": result(False)},
        )
        assert n == 1
        _assert_redacted_at_rest(sc_path)

    def test_self_consistency(self, scorecard, sc_path):
        from core.llm.scorecard.self_consistency import (
            record_self_consistency_outcomes,
        )

        n = record_self_consistency_outcomes(
            scorecard,
            results_by_id={"f1": {
                "retried": True,
                "is_exploitable": False,
                "rule_id": "r1",
                "analysed_by": "m1",
                "reasoning": f"changed my mind about {SECRET}",
            }},
            verdicts_pre_retry={"f1": True},
        )
        assert n == 1
        _assert_redacted_at_rest(sc_path)

    def test_cross_family(self, scorecard, sc_path):
        from core.llm.scorecard.cross_family import (
            record_cross_family_outcomes,
        )

        n = record_cross_family_outcomes(
            scorecard,
            results_by_id={"f1": {
                "rule_id": "r1",
                "cross_family_check": {
                    "verdict": "disputed",
                    "checker_model": "m2",
                    "trigger": "verdict-flip",
                    "checker_ruling": f"checker quoted {SECRET}",
                },
            }},
        )
        assert n == 1
        _assert_redacted_at_rest(sc_path)

    def test_validate_feedback(self, scorecard, sc_path):
        from core.llm.scorecard.validate_feedback import (
            record_validate_feedback_outcome,
        )

        assert record_validate_feedback_outcome(
            scorecard,
            model="m1",
            cwe="CWE-79",
            prior_verdict="finding",
            validate_verdict="disproven",
            file="a.py",
            function="f",
            reason=f"validator saw {SECRET}",
        )
        _assert_redacted_at_rest(sc_path)

    def test_reasoning_divergence(self, scorecard, sc_path):
        """This producer already redacted at source; the behaviour is
        preserved (and now double-covered by the sink)."""
        from core.llm.scorecard.reasoning_divergence import (
            record_reasoning_divergence,
        )

        # ≥8 unique tokens and ≥50 chars per doc (the divergence
        # metric's floors); a/b identical, c fully disjoint → mean
        # pairwise Jaccard distance ≈ 0.67, well above the threshold.
        base = (
            "the user supplied index flows unchecked into the memcpy "
            "length parameter of the packet parser"
        )
        n = record_reasoning_divergence(
            scorecard,
            correlation={
                "agreement_matrix": {"f1": {
                    "a": {"is_exploitable": True},
                    "b": {"is_exploitable": True},
                    "c": {"is_exploitable": True},
                }},
                "confidence_signals": {"f1": "high"},
            },
            results_by_id={"f1": {"rule_id": "r1"}},
            per_finding_results={"f1": [
                {"analysed_by": "a", "reasoning": base},
                {"analysed_by": "b", "reasoning": base},
                {"analysed_by": "c",
                 "reasoning": f"credentials appear hardcoded near token "
                              f"{SECRET} making exploitation moot here "
                              f"entirely regardless"},
            ]},
            divergence_threshold=0.1,
        )
        assert n == 3
        _assert_redacted_at_rest(sc_path)


class TestTopLevelKeyRedaction:
    def test_secret_as_top_level_sample_key_redacted(
        self, scorecard, sc_path,
    ):
        """The tree walk redacts keys at every nesting level — the
        OUTERMOST sample dict must not be the one shape that skips
        it (its keys were spliced in verbatim around the walk)."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={
                f"x-api-key: {SECRET}": "echoed header",
                "this_reasoning": "context",
            },
        )
        _assert_redacted_at_rest(sc_path)

    def test_top_level_bookkeeping_keys_survive(self, scorecard, sc_path):
        """Both directions: ordinary top-level keys stay byte-identical
        (consumers address samples by key), alongside the appended
        ts/event_type bookkeeping."""
        scorecard.record_event(
            "agentic:r1", "m1", "cheap_short_circuit", "incorrect",
            sample={"this_reasoning": f"saw {SECRET}",
                    "other_reasoning": "plain"},
        )
        data = json.loads(sc_path.read_text())
        samp = data["models"]["m1"]["agentic:r1"][
            "disagreement_samples"][0]
        assert set(samp.keys()) == {
            "ts", "event_type", "this_reasoning", "other_reasoning",
        }
        _assert_redacted_at_rest(sc_path)


class TestSampleBoundedAtSink:
    """Every string leaf in a persisted sample is length-bounded at
    the single sink (``_append_sample``), alongside the redaction
    walk. The per-producer ``_MAX_REASONING_CHARS`` slices remain the
    first line, but the sink makes the package's bounding claim true
    by construction — pre-fix, sibling fields (function_id, trigger,
    method, the mark --note) and forged/corrupt run-report strings
    shipped unsliced, parking multi-MB strings in the sidecar that
    every read re-parses under the flock."""

    def test_every_string_leaf_bounded(self, scorecard, sc_path):
        from core.llm.scorecard import _MAX_REASONING_CHARS
        big = "N" * 1_000_000
        scorecard.record_event(
            "dc", "m", "cheap_short_circuit", "incorrect",
            sample={
                "note": big,
                "reasoning": big,
                "nested": {"deep": [big, {"k": big}]},
            },
        )
        raw = json.loads(sc_path.read_text())
        samples = raw["models"]["m"]["dc"]["disagreement_samples"]

        def _walk(v):
            if isinstance(v, str):
                assert len(v) <= _MAX_REASONING_CHARS
            elif isinstance(v, dict):
                for k, x in v.items():
                    _walk(k)
                    _walk(x)
            elif isinstance(v, list):
                for x in v:
                    _walk(x)

        _walk(samples)
        assert len(sc_path.read_text()) < 100_000

    def test_short_values_pass_unsliced(self, scorecard, sc_path):
        scorecard.record_event(
            "dc", "m", "cheap_short_circuit", "incorrect",
            sample={"note": "short operator note"},
        )
        raw = json.loads(sc_path.read_text())
        sample = raw["models"]["m"]["dc"]["disagreement_samples"][0]
        assert sample["note"] == "short operator note"

    def test_cli_mark_note_bounded(self, tmp_path, monkeypatch, capsys):
        from core.llm.scorecard import _MAX_REASONING_CHARS
        from core.llm.scorecard.cli import main
        sidecar = tmp_path / "sc.json"
        rc = main([
            "--path", str(sidecar), "mark", "dc", "incorrect",
            "--model", "m", "--note", "X" * 100_000,
        ])
        assert rc == 0
        raw = json.loads(sidecar.read_text())
        sample = raw["models"]["m"]["dc"]["disagreement_samples"][0]
        assert len(sample["note"]) <= _MAX_REASONING_CHARS
        capsys.readouterr()
