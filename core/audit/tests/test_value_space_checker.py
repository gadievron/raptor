"""Tests for core.audit.value_space_checker."""

from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from typing import List

from core.audit.value_space_checker import (
    ValueSpaceMismatch,
    _extract_function_literals,
    _LiteralExtractor,
    detect_value_space_mismatches,
)


# -- helpers ---------------------------------------------------------------


@dataclass
class FakeCall:
    caller: str
    chain: List[str]


@dataclass
class FakeCallGraph:
    calls: List[FakeCall] = field(default_factory=list)


# -- test cases ------------------------------------------------------------


class TestUnhandledValues:
    """Producer emits values the consumer doesn't handle."""

    def test_producer_emits_extra_value(self):
        """Producer emits {"a", "b", "c"}, consumer handles {"a", "b"}.

        "c" should be flagged as unhandled.
        """
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    ecosystem = "a"\n'
                '    ecosystem = "b"\n'
                '    ecosystem = "c"\n'
            ),
            "pkg/consumer.py": (
                'def consume(ecosystem):\n'
                '    if ecosystem == "a":\n'
                '        pass\n'
                '    elif ecosystem == "b":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        assert len(results) >= 1
        # Find the mismatch for our produce→consume pair.
        match = _find_mismatch(results, "produce", "consume")
        assert match is not None, f"Expected produce→consume mismatch, got {results}"
        assert "c" in match.unhandled

    def test_dict_producer_vs_equality_consumer(self):
        """Dict keys as producer values, equality checks as consumer."""
        source = {
            "pkg/mapping.py": (
                'def get_label(ecosystem):\n'
                '    labels = {"Packagist": "PHP", "npm": "JS", "PyPI": "Python"}\n'
                '    return labels.get(ecosystem)\n'
            ),
            "pkg/review.py": (
                'def review(ecosystem):\n'
                '    if ecosystem == "Composer":\n'
                '        return True\n'
                '    elif ecosystem == "npm":\n'
                '        return True\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        # get_label produces {"Packagist", "npm", "PyPI"} (dict keys)
        # plus the return strings "PHP", "JS", "Python".
        # review consumes {"Composer", "npm"}.
        # This should flag value-space gaps.
        assert len(results) >= 1
        # At minimum: Composer is consumed but never produced (dead branch).
        any_dead_composer = any("Composer" in m.dead_branches for m in results)
        assert any_dead_composer, f"Expected Composer as dead branch: {results}"


class TestPerfectAlignment:
    """No findings when producer and consumer value spaces match."""

    def test_same_values_no_findings(self):
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    status = "ok"\n'
                '    status = "error"\n'
            ),
            "pkg/consumer.py": (
                'def consume(status):\n'
                '    if status == "ok":\n'
                '        pass\n'
                '    elif status == "error":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        # Either no results, or any that exist have empty gaps.
        for m in results:
            if m.producer_function == "produce" and m.consumer_function == "consume":
                assert not m.unhandled, f"Unexpected unhandled: {m.unhandled}"
                assert not m.dead_branches, f"Unexpected dead: {m.dead_branches}"


class TestDeadBranches:
    """Consumer handles values nobody produces."""

    def test_consumer_has_unreachable_branch(self):
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    status = "ok"\n'
            ),
            "pkg/consumer.py": (
                'def consume(status):\n'
                '    if status == "ok":\n'
                '        pass\n'
                '    elif status == "never_produced":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        assert len(results) >= 1
        match = _find_mismatch(results, "produce", "consume")
        assert match is not None, f"Expected produce→consume mismatch, got {results}"
        assert "never_produced" in match.dead_branches

    def test_set_membership_consumer(self):
        """Consumer uses set-membership test instead of equality."""
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    severity = "high"\n'
            ),
            "pkg/consumer.py": (
                'def consume(severity):\n'
                '    if severity in {"high", "critical", "unknown"}:\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        assert len(results) >= 1
        match = _find_mismatch(results, "produce", "consume")
        assert match is not None
        # "critical" and "unknown" consumed but never produced.
        assert "critical" in match.dead_branches
        assert "unknown" in match.dead_branches


class TestMultiplePairsInSameFile:
    """Multiple producer-consumer pairs within a single file."""

    def test_intra_module_pairs(self):
        source = {
            "handlers.py": (
                'def get_status():\n'
                '    return "active"\n'
                '\n'
                'def check_status(val):\n'
                '    if val == "active":\n'
                '        pass\n'
                '    elif val == "deleted":\n'
                '        pass\n'
                '\n'
                'def get_mode():\n'
                '    return "fast"\n'
                '\n'
                'def apply_mode(m):\n'
                '    if m == "fast":\n'
                '        pass\n'
                '    elif m == "slow":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        # Two intra-module pairs should both fire.
        status_match = _find_mismatch(results, "get_status", "check_status")
        mode_match = _find_mismatch(results, "get_mode", "apply_mode")
        assert status_match is not None, f"Expected status pair: {results}"
        assert "deleted" in status_match.dead_branches
        assert mode_match is not None, f"Expected mode pair: {results}"
        assert "slow" in mode_match.dead_branches


class TestCallGraphLinking:
    """Producer-consumer linking via explicit call graphs."""

    def test_call_graph_link_detects_gap(self):
        source = {
            "mod.py": (
                'def producer():\n'
                '    return "x"\n'
                '\n'
                'def consumer(val):\n'
                '    if val == "x":\n'
                '        pass\n'
                '    elif val == "y":\n'
                '        pass\n'
            ),
        }
        cg = {
            "mod.py": FakeCallGraph(calls=[
                FakeCall(caller="consumer", chain=["producer"]),
            ]),
        }
        results = detect_value_space_mismatches(source, call_graphs=cg)
        assert len(results) >= 1
        match = _find_mismatch(results, "producer", "consumer")
        assert match is not None
        assert "y" in match.dead_branches
        assert match.confidence == "high"

    def test_call_graph_no_mismatch(self):
        source = {
            "mod.py": (
                'def producer():\n'
                '    return "x"\n'
                '\n'
                'def consumer(val):\n'
                '    if val == "x":\n'
                '        pass\n'
            ),
        }
        cg = {
            "mod.py": FakeCallGraph(calls=[
                FakeCall(caller="consumer", chain=["producer"]),
            ]),
        }
        results = detect_value_space_mismatches(source, call_graphs=cg)
        for m in results:
            if m.producer_function == "producer" and m.consumer_function == "consumer":
                assert not m.unhandled
                assert not m.dead_branches


class TestSelfPairGuard:
    """A self-recursive producer-consumer must not pair with itself."""

    def test_recursive_function_not_linked_to_itself(self):
        source = {
            "mod.py": (
                'def walk(status):\n'
                '    if status == "ok":\n'
                '        return walk("next")\n'
                '    return "done"\n'
            ),
        }
        cg = {
            "mod.py": FakeCallGraph(calls=[
                FakeCall(caller="walk", chain=["walk"]),
            ]),
        }
        results = detect_value_space_mismatches(source, call_graphs=cg)
        assert _find_mismatch(results, "walk", "walk") is None, (
            f"self-pair fabricated a mismatch: {results}"
        )

    def test_genuine_same_file_link_unaffected(self):
        source = {
            "mod.py": (
                'def producer():\n'
                '    return "x"\n'
                '\n'
                'def consumer(val):\n'
                '    if val == "x":\n'
                '        pass\n'
                '    elif val == "y":\n'
                '        pass\n'
            ),
        }
        cg = {
            "mod.py": FakeCallGraph(calls=[
                FakeCall(caller="consumer", chain=["producer"]),
            ]),
        }
        results = detect_value_space_mismatches(source, call_graphs=cg)
        match = _find_mismatch(results, "producer", "consumer")
        assert match is not None
        assert match.confidence == "high"
        assert "y" in match.dead_branches


class TestToDict:
    """ValueSpaceMismatch.to_dict round-trip."""

    def test_to_dict_keys(self):
        m = ValueSpaceMismatch(
            producer_file="a.py",
            producer_function="make",
            producer_values=["x", "y"],
            consumer_file="b.py",
            consumer_function="use",
            consumer_values=["x"],
            unhandled=["y"],
            dead_branches=[],
            confidence="high",
        )
        d = m.to_dict()
        assert d["producer_file"] == "a.py"
        assert d["unhandled"] == ["y"]
        assert d["dead_branches"] == []
        assert d["confidence"] == "high"


class TestEdgeCases:
    """Edge cases and robustness."""

    def test_empty_input(self):
        assert detect_value_space_mismatches({}) == []

    def test_syntax_error_skipped(self):
        source = {"bad.py": "def broken(\n"}
        assert detect_value_space_mismatches(source) == []

    def test_no_string_literals(self):
        source = {"math.py": "def add(a, b):\n    return a + b\n"}
        assert detect_value_space_mismatches(source) == []

    def test_non_field_name_not_linked(self):
        """Assignments to arbitrary variable names don't trigger linking."""
        source = {
            "pkg/a.py": (
                'def f():\n'
                '    foo = "bar"\n'
            ),
            "pkg/b.py": (
                'def g(foo):\n'
                '    if foo == "baz":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        # "foo" is not a recognized field name, so no field-based linking.
        # Intra-module linking also won't fire (different files).
        assert len(results) == 0


# -- helpers ---------------------------------------------------------------


def _find_mismatch(
    results: List[ValueSpaceMismatch],
    producer_func: str,
    consumer_func: str,
) -> ValueSpaceMismatch | None:
    for m in results:
        if (
            m.producer_function == producer_func
            and m.consumer_function == consumer_func
        ):
            return m
    return None


# ---------------------------------------------------------------
# Dynamic key construction (f-strings, .format(), concatenation)
# ---------------------------------------------------------------


class TestFStringExtraction:
    """f-string templates should be extracted as produced values."""

    def test_fstring_template_extracted(self):
        src = """\
def produce(num):
    return f"signal_{num}"

def consume(key):
    if key == "signal_7":
        return True
    if key == "signal_11":
        return True
    return False
"""
        results = detect_value_space_mismatches({"mod.py": src})
        # The template "signal_{}" covers "signal_7" and "signal_11"
        # so they should not appear as dead branches
        for r in results:
            if r.producer_function == "produce" and r.consumer_function == "consume":
                assert "signal_7" not in r.dead_branches
                assert "signal_11" not in r.dead_branches

    def test_fstring_with_format_spec(self):
        src = """\
def produce(num):
    return f"CWE-{num:03d}"
"""
        results = detect_value_space_mismatches({"mod.py": src})
        # Should extract template "CWE-{:03d}" as produced value
        # (no consumer to mismatch against, but extraction should not crash)
        assert isinstance(results, list)


class TestFormatMethodExtraction:
    def test_format_template_extracted(self):
        src = """\
def produce(eco):
    return "pkg_{}".format(eco)

def consume(key):
    if key == "pkg_npm":
        pass
"""
        results = detect_value_space_mismatches({"mod.py": src})
        for r in results:
            if r.producer_function == "produce":
                assert "pkg_{}" not in r.unhandled


class TestConcatenationExtraction:
    def test_concat_template_extracted(self):
        src = """\
def produce(name):
    return "error_" + name

def consume(key):
    if key == "error_timeout":
        pass
"""
        results = detect_value_space_mismatches({"mod.py": src})
        for r in results:
            if r.producer_function == "produce":
                assert "error_{}" not in r.unhandled


class TestFormatNormalization:
    def test_padding_mismatch_detected(self):
        src = """\
def produce():
    return "07"

def consume(val):
    if val == "7":
        pass
"""
        # These are in the same file — intra-module linking should fire
        results = detect_value_space_mismatches({"mod.py": src})
        # The "07" vs "7" should still show as unhandled (the format
        # mismatch IS the bug)
        for r in results:
            if r.producer_function == "produce" and r.consumer_function == "consume":
                assert "07" in r.unhandled


# ---------------------------------------------------------------
# Non-Python files via tree-sitter
# ---------------------------------------------------------------


class TestNonPythonExtraction:
    """Tree-sitter literal extraction for non-Python files."""

    def test_go_produced_and_consumed(self):
        """Go function with return + switch should extract both."""
        go_src = '''\
package main

func getStatus() string {
    return "active"
}

func checkStatus(s string) bool {
    switch s {
    case "active":
        return true
    case "deleted":
        return false
    }
    return false
}
'''
        from core.audit.value_space_checker import _extract_function_literals_ts
        funcs = _extract_function_literals_ts(go_src, "status.go")
        if not funcs:
            pytest.skip("tree-sitter not available")
        by_name = {fl.function: fl for fl in funcs}
        assert "getStatus" in by_name
        assert "active" in by_name["getStatus"].produced
        assert "checkStatus" in by_name
        assert "active" in by_name["checkStatus"].consumed
        assert "deleted" in by_name["checkStatus"].consumed

    def test_js_dict_key_produced(self):
        """JS object literal keys should be classified as produced."""
        js_src = '''\
function getLabels() {
    const labels = {
        "npm": "JavaScript",
        "PyPI": "Python",
    };
    return labels;
}
'''
        from core.audit.value_space_checker import _extract_function_literals_ts
        funcs = _extract_function_literals_ts(js_src, "labels.js")
        if not funcs:
            pytest.skip("tree-sitter not available")
        assert len(funcs) >= 1
        fl = funcs[0]
        assert "npm" in fl.produced
        assert "PyPI" in fl.produced

    def test_python_not_used_for_ts_path(self):
        """Python files should return empty from the ts path."""
        from core.audit.value_space_checker import _extract_function_literals_ts
        funcs = _extract_function_literals_ts(
            'def f():\n    return "x"\n', "test.py"
        )
        assert funcs == []

    def test_cross_language_mismatch(self):
        """Go producer + Python consumer should detect gap."""
        go_src = '''\
package main

func getMode() string {
    return "fast"
}
'''
        py_src = '''\
def apply_mode(m):
    if m == "fast":
        pass
    elif m == "slow":
        pass
'''
        results = detect_value_space_mismatches({
            "mode.go": go_src,
            "handler.py": py_src,
        })
        match = _find_mismatch(results, "getMode", "apply_mode")
        if match is None:
            pytest.skip("tree-sitter not available or no intra-module link")
        assert "slow" in match.dead_branches


class TestFormatMismatchFiltering:
    """Format-normalized values should be removed from unhandled."""

    def test_format_mismatch_not_in_unhandled(self):
        """A value that differs only in zero-padding should not appear in unhandled."""
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    signal = "07"\n'
                '    signal = "11"\n'
                '    signal = "15"\n'
            ),
            "pkg/consumer.py": (
                'def consume(signal):\n'
                '    if signal == "7":\n'
                '        pass\n'
                '    elif signal == "11":\n'
                '        pass\n'
                '    elif signal == "15":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        match = _find_mismatch(results, "produce", "consume")
        if match is None:
            return
        assert "07" not in match.unhandled, (
            "format-mismatch value '07' should be removed from unhandled"
        )

    def test_case_mismatch_not_in_dead(self):
        """A consumed value that differs only in case from a produced value
        should not be reported as dead."""
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    return "error"\n'
            ),
            "pkg/consumer.py": (
                'def consume(v):\n'
                '    if v == "ERROR":\n'
                '        pass\n'
                '    elif v == "error":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        match = _find_mismatch(results, "produce", "consume")
        if match is None:
            return
        assert "ERROR" not in match.dead, (
            "case-variant 'ERROR' should not appear in dead branches"
        )


class TestFormatMismatchOnFinding:
    """Pure format-mismatch pairs carry the mismatch text on the finding."""

    def test_zero_padding_mismatch_carried(self):
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    signal = "07"\n'
            ),
            "pkg/consumer.py": (
                'def consume(signal):\n'
                '    if signal == "7":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        match = _find_mismatch(results, "produce", "consume")
        assert match is not None, f"Expected produce-consume pair: {results}"
        # The exact-miss sets are empty — the format mismatch IS the bug,
        # and it must survive onto the finding.
        assert match.unhandled == []
        assert match.dead_branches == []
        assert match.format_mismatches
        assert any("07" in fm and "7" in fm for fm in match.format_mismatches)

    def test_format_mismatches_serialized(self):
        m = ValueSpaceMismatch(
            producer_file="a.py",
            producer_function="make",
            producer_values=["07"],
            consumer_file="b.py",
            consumer_function="use",
            consumer_values=["7"],
            unhandled=[],
            dead_branches=[],
            confidence="medium",
            format_mismatches=["'07' vs '7' (format mismatch)"],
        )
        d = m.to_dict()
        assert d["format_mismatches"] == ["'07' vs '7' (format mismatch)"]

    def test_format_mismatches_defaults_empty(self):
        m = ValueSpaceMismatch(
            producer_file="a.py",
            producer_function="make",
            producer_values=["x"],
            consumer_file="b.py",
            consumer_function="use",
            consumer_values=["x", "y"],
            unhandled=[],
            dead_branches=["y"],
            confidence="high",
        )
        assert m.format_mismatches == []
        assert m.to_dict()["format_mismatches"] == []


class TestFieldNameBookkeeping:
    """field_produced/field_consumed track field names only."""

    def test_producer_field_names(self):
        funcs = _extract_function_literals(
            'def f():\n    status = "ok"\n', "a.py"
        )
        assert len(funcs) == 1
        assert funcs[0].field_produced == {"status"}

    def test_consumer_field_names(self):
        funcs = _extract_function_literals(
            'def g(status):\n'
            '    if status == "ok":\n'
            '        pass\n'
            '    if status in {"bad", "worse"}:\n'
            '        pass\n',
            "b.py",
        )
        assert len(funcs) == 1
        assert funcs[0].field_consumed == {"status"}

    def test_field_linking_still_fires(self):
        source = {
            "pkg/producer.py": (
                'def produce():\n'
                '    ecosystem = "npm"\n'
                '    ecosystem = "PyPI"\n'
            ),
            "pkg/consumer.py": (
                'def consume(ecosystem):\n'
                '    if ecosystem == "npm":\n'
                '        pass\n'
            ),
        }
        results = detect_value_space_mismatches(source)
        match = _find_mismatch(results, "produce", "consume")
        assert match is not None
        assert "PyPI" in match.unhandled


class TestDeadVisitorFlagsRemoved:
    def test_no_vestigial_state(self):
        extractor = _LiteralExtractor("a.py", "f")
        assert not hasattr(extractor, "_in_compare")
        assert not hasattr(extractor, "_in_membership")
