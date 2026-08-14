"""Tests for core.analysis.lifecycle_model — data model round-trip and properties."""

from __future__ import annotations

from core.analysis.lifecycle_model import (
    Guard,
    LifecycleFinding,
    ReadSite,
    StateField,
    WriteSite,
)


class TestGuard:
    def test_round_trip(self):
        g = Guard(condition="task->mm != NULL", file="kernel/ptrace.c", line=42)
        d = g.to_dict()
        g2 = Guard.from_dict(d)
        assert g2 == g
        assert d["condition"] == "task->mm != NULL"
        assert "polarity" not in d

    def test_non_default_polarity(self):
        g = Guard(
            condition="task->mm == NULL", file="a.c", line=1,
            polarity=False, smt_parseable=True,
        )
        d = g.to_dict()
        assert d["polarity"] is False
        assert d["smt_parseable"] is True
        assert Guard.from_dict(d) == g


class TestWriteSite:
    def test_round_trip(self):
        ws = WriteSite(
            file="fs/exec.c", line=100, function="setup_new_exec",
            guards=frozenset({
                Guard(condition="current->mm", file="fs/exec.c", line=95),
            }),
        )
        d = ws.to_dict()
        ws2 = WriteSite.from_dict(d)
        assert ws2.file == "fs/exec.c"
        assert ws2.function == "setup_new_exec"
        assert len(ws2.guards) == 1

    def test_no_guards(self):
        ws = WriteSite(file="a.c", line=1, function="f", guards=frozenset())
        d = ws.to_dict()
        assert d["guards"] == []
        assert WriteSite.from_dict(d).guards == frozenset()


class TestReadSite:
    def test_round_trip(self):
        rs = ReadSite(
            file="kernel/ptrace.c", line=200, function="__ptrace_may_access",
            guards=frozenset(),
        )
        d = rs.to_dict()
        rs2 = ReadSite.from_dict(d)
        assert rs2 == rs
        assert rs2.security_relevant is True

    def test_non_security_relevant(self):
        rs = ReadSite(
            file="a.c", line=1, function="f",
            guards=frozenset(), security_relevant=False,
        )
        d = rs.to_dict()
        assert d["security_relevant"] is False
        assert ReadSite.from_dict(d).security_relevant is False


class TestStateField:
    def test_round_trip(self):
        field = StateField(
            name="dumpable",
            struct_type="task_struct",
            invariant="meaningful only when task owns an mm",
            cwe="CWE-863",
            write_sites=[
                WriteSite(
                    file="fs/exec.c", line=100, function="setup_new_exec",
                    guards=frozenset({
                        Guard(condition="current->mm", file="fs/exec.c", line=95),
                    }),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="kernel/ptrace.c", line=200,
                    function="__ptrace_may_access",
                    guards=frozenset(),
                ),
            ],
        )
        d = field.to_dict()
        field2 = StateField.from_dict(d)
        assert field2.name == "dumpable"
        assert field2.struct_type == "task_struct"
        assert len(field2.write_sites) == 1
        assert len(field2.read_sites) == 1
        assert field2.cwe == "CWE-863"

    def test_write_guard_conditions(self):
        field = StateField(
            name="x", struct_type="S", invariant="test",
            write_sites=[
                WriteSite(
                    file="a.c", line=1, function="f",
                    guards=frozenset({
                        Guard(condition="p != NULL", file="a.c", line=1),
                    }),
                ),
                WriteSite(
                    file="b.c", line=2, function="g",
                    guards=frozenset({
                        Guard(condition="q > 0", file="b.c", line=2),
                    }),
                ),
            ],
        )
        assert field.write_guard_conditions == frozenset({"p != NULL", "q > 0"})


class TestLifecycleFinding:
    def test_to_dict(self):
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="meaningful only when task owns an mm",
            cwe="CWE-863",
        )
        rs = ReadSite(
            file="kernel/ptrace.c", line=200,
            function="__ptrace_may_access",
            guards=frozenset(),
        )
        finding = LifecycleFinding(
            state_field=field,
            read_site=rs,
            missing_guards=frozenset({"current->mm"}),
            confidence="high",
        )
        d = finding.to_dict()
        assert d["field"] == "dumpable"
        assert d["struct_type"] == "task_struct"
        assert d["missing_guards"] == ["current->mm"]
        assert d["confidence"] == "high"
        assert d["cwe"] == "CWE-863"
