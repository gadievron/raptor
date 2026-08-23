"""Tests for Hypothesis, Location, FlowStep, ValidationResult,
ToolCapability, ToolEvidence."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.hypothesis_validation.adapters.base import (
    ToolCapability,
    ToolEvidence,
    ToolInvocation,
)
from packages.hypothesis_validation.hypothesis import (
    FlowStep,
    Hypothesis,
    Location,
)
from packages.hypothesis_validation.result import Evidence, ValidationResult


class TestHypothesis:
    def test_minimal(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        assert h.claim == "x"
        assert h.target == Path("/src")
        assert h.target_function == ""
        assert h.cwe == ""
        assert h.suggested_tools == []

    def test_to_dict(self):
        h = Hypothesis(
            claim="UAF",
            target=Path("/src/a.c"),
            target_function="foo",
            cwe="CWE-416",
            suggested_tools=["coccinelle"],
            context="caller validates len",
        )
        d = h.to_dict()
        assert d["claim"] == "UAF"
        assert d["target"] == "/src/a.c"
        assert d["target_function"] == "foo"
        assert d["cwe"] == "CWE-416"
        assert d["suggested_tools"] == ["coccinelle"]
        assert d["context"] == "caller validates len"

    def test_from_dict(self):
        d = {
            "claim": "x", "target": "/src", "target_function": "f",
            "cwe": "CWE-129", "suggested_tools": ["semgrep"],
        }
        h = Hypothesis.from_dict(d)
        assert h.claim == "x"
        assert h.target == Path("/src")
        assert h.cwe == "CWE-129"
        assert h.suggested_tools == ["semgrep"]

    def test_from_dict_empty(self):
        h = Hypothesis.from_dict({})
        assert h.claim == ""
        assert h.target == Path(".")

    def test_from_dict_none(self):
        h = Hypothesis.from_dict(None)
        assert h.claim == ""

    def test_roundtrip(self):
        h = Hypothesis(claim="x", target=Path("/y"), cwe="CWE-1")
        h2 = Hypothesis.from_dict(h.to_dict())
        assert h2.claim == h.claim
        assert h2.target == h.target
        assert h2.cwe == h.cwe


class TestLocationLineCoercion:
    """LLM-supplied JSON with a non-numeric ``line`` must degrade to
    line=0, never raise from ``int()`` coercion."""

    def test_non_numeric_string_becomes_zero(self):
        assert Location.from_dict({"line": "not-a-number"}).line == 0

    def test_numeric_string_parses(self):
        assert Location.from_dict({"line": "42"}).line == 42

    def test_none_becomes_zero(self):
        assert Location.from_dict({"line": None}).line == 0

    def test_truthy_non_numeric_type_becomes_zero(self):
        assert Location.from_dict({"line": ["7"]}).line == 0

    def test_int_passes_through(self):
        assert Location.from_dict({"line": 7}).line == 7


class TestFlowStepLineCoercion:
    def test_non_numeric_string_becomes_zero(self):
        assert FlowStep.from_dict({"line": "abc"}).line == 0

    def test_numeric_string_parses(self):
        assert FlowStep.from_dict({"line": "13"}).line == 13

    def test_truthy_non_numeric_type_becomes_zero(self):
        assert FlowStep.from_dict({"line": {"n": 3}}).line == 0


class TestHypothesisFromDictLineCoercion:
    def test_bad_lines_in_nested_fields_do_not_raise(self):
        h = Hypothesis.from_dict({
            "claim": "c",
            "target": "/src",
            "source": {"kind": "network", "line": "unknown"},
            "sink": {"kind": "exec", "line": "12"},
            "flow_steps": [
                {"function": "f", "line": "??"},
                {"function": "g", "line": 9},
            ],
        })
        assert h.source.line == 0
        assert h.sink.line == 12
        assert [s.line for s in h.flow_steps] == [0, 9]


class TestEvidence:
    def test_default(self):
        e = Evidence(tool="cocci", rule="r", summary="s")
        assert e.success
        assert e.matches == []

    def test_to_dict(self):
        e = Evidence(
            tool="cocci", rule="r", summary="3 matches",
            matches=[{"file": "a.c", "line": 1}],
        )
        d = e.to_dict()
        assert d["tool"] == "cocci"
        assert d["matches"] == [{"file": "a.c", "line": 1}]
        assert d["success"] is True


class TestValidationResult:
    def test_confirmed(self):
        r = ValidationResult(verdict="confirmed")
        assert r.confirmed
        assert not r.refuted
        assert not r.inconclusive

    def test_refuted(self):
        r = ValidationResult(verdict="refuted")
        assert r.refuted

    def test_inconclusive(self):
        r = ValidationResult(verdict="inconclusive")
        assert r.inconclusive

    def test_supporting_evidence_only_successful_with_matches(self):
        r = ValidationResult(
            verdict="confirmed",
            evidence=[
                Evidence(tool="a", rule="r", summary="s",
                         matches=[{"file": "x", "line": 1}], success=True),
                Evidence(tool="b", rule="r", summary="s",
                         matches=[], success=True),
                Evidence(tool="c", rule="r", summary="s",
                         matches=[{"file": "y", "line": 1}], success=False),
            ],
        )
        supporting = r.supporting_evidence
        assert len(supporting) == 1
        assert supporting[0].tool == "a"

    def test_to_dict(self):
        r = ValidationResult(
            verdict="confirmed",
            evidence=[Evidence(tool="t", rule="r", summary="s")],
            iterations=2,
            reasoning="why",
        )
        d = r.to_dict()
        assert d["verdict"] == "confirmed"
        assert len(d["evidence"]) == 1
        assert d["iterations"] == 2
        assert d["reasoning"] == "why"


class TestToolCapability:
    def test_minimal(self):
        c = ToolCapability(name="t")
        assert c.name == "t"
        assert c.good_for == []

    def test_render_for_prompt_includes_name(self):
        c = ToolCapability(name="cocci", good_for=["lock checks"])
        text = c.render_for_prompt()
        assert "## cocci" in text
        assert "lock checks" in text

    def test_render_for_prompt_omits_empty_sections(self):
        c = ToolCapability(name="t")
        text = c.render_for_prompt()
        assert "Good for:" not in text
        assert "Not for:" not in text
        assert "Example:" not in text

    def test_render_for_prompt_includes_languages(self):
        c = ToolCapability(name="t", languages=["c", "cpp"])
        text = c.render_for_prompt()
        assert "Languages: c, cpp" in text

    def test_render_for_prompt_includes_syntax(self):
        c = ToolCapability(name="t", syntax_example="rule { x }")
        text = c.render_for_prompt()
        assert "rule { x }" in text


class TestToolEvidence:
    def test_confirms_requires_success_and_matches(self):
        assert not ToolEvidence(tool="t", rule="r", success=True, matches=[]).confirms
        assert not ToolEvidence(tool="t", rule="r", success=False,
                                matches=[{"file": "a"}]).confirms
        assert ToolEvidence(tool="t", rule="r", success=True,
                            matches=[{"file": "a"}]).confirms


class TestToolInvocation:
    def test_to_dict(self):
        inv = ToolInvocation(tool="cocci", rule="r", target="/src",
                             args={"x": 1})
        d = inv.to_dict()
        assert d["tool"] == "cocci"
        assert d["args"] == {"x": 1}
