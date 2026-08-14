"""Tests for packages.joern.models."""

from __future__ import annotations

from pathlib import Path

from packages.joern.models import FlowStep, JoernCPG, JoernResult, TaintFlow


class TestFlowStep:
    def test_from_dict(self):
        d = {
            "file": "src/handler.c",
            "function": "parse_header",
            "line": 42,
            "code": "memcpy(buf, src, len)",
            "variable": "len",
        }
        step = FlowStep.from_dict(d)
        assert step.file == "src/handler.c"
        assert step.function == "parse_header"
        assert step.line == 42
        assert step.code == "memcpy(buf, src, len)"
        assert step.variable == "len"

    def test_from_dict_missing_fields(self):
        step = FlowStep.from_dict({})
        assert step.file == ""
        assert step.function == ""
        assert step.line == 0

    def test_round_trip(self):
        step = FlowStep(
            file="a.c", function="f", line=10,
            code="x = y", variable="y",
        )
        assert FlowStep.from_dict(step.to_dict()) == step


class TestTaintFlow:
    def test_from_dict_basic(self):
        d = {
            "source_method": "parse_header",
            "source_param": "buf",
            "sink_call": "memcpy",
            "sink_arg_idx": 1,
            "steps": [
                {"file": "a.c", "function": "parse_header",
                 "line": 10, "code": "buf", "variable": "buf"},
                {"file": "a.c", "function": "parse_header",
                 "line": 15, "code": "memcpy(dst, buf, n)",
                 "variable": "buf"},
            ],
        }
        flow = TaintFlow.from_dict(d)
        assert flow.source_method == "parse_header"
        assert flow.sink_call == "memcpy"
        assert len(flow.steps) == 2
        assert not flow.is_inter_procedural

    def test_inter_procedural_detection(self):
        d = {
            "source_method": "caller",
            "source_param": "x",
            "sink_call": "system",
            "sink_arg_idx": 0,
            "steps": [
                {"file": "a.c", "function": "caller",
                 "line": 1, "code": "x", "variable": "x"},
                {"file": "b.c", "function": "helper",
                 "line": 5, "code": "y", "variable": "y"},
                {"file": "c.c", "function": "exec_cmd",
                 "line": 10, "code": "system(cmd)",
                 "variable": "cmd"},
            ],
        }
        flow = TaintFlow.from_dict(d)
        assert flow.is_inter_procedural

    def test_round_trip(self):
        flow = TaintFlow(
            source_method="f", source_param="p",
            sink_call="g", sink_arg_idx=0,
            steps=[FlowStep("a.c", "f", 1, "p", "p")],
        )
        d = flow.to_dict()
        assert d["source_method"] == "f"
        assert len(d["steps"]) == 1

    def test_empty_steps(self):
        flow = TaintFlow.from_dict({})
        assert flow.steps == []
        assert not flow.is_inter_procedural


class TestJoernCPG:
    def test_exists_false(self, tmp_path: Path):
        cpg = JoernCPG(path=tmp_path / "nonexistent.bin", target=tmp_path)
        assert not cpg.exists()

    def test_exists_true(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)
        assert cpg.exists()


class TestJoernResult:
    def test_ok_when_no_errors(self):
        r = JoernResult(query="cpg.method.l")
        assert r.ok

    def test_not_ok_with_errors(self):
        r = JoernResult(query="bad", errors=["failed"])
        assert not r.ok

    def test_flow_count(self):
        flow = TaintFlow(
            source_method="f", source_param="p",
            sink_call="g", sink_arg_idx=0,
        )
        r = JoernResult(query="q", flows=[flow])
        assert r.flow_count == 1

    def test_to_dict(self):
        r = JoernResult(query="q", errors=["e"], elapsed_ms=100)
        d = r.to_dict()
        assert d["query"] == "q"
        assert d["errors"] == ["e"]
        assert d["elapsed_ms"] == 100
