"""Tests for core.analysis.lifecycle_checker — coverage analysis."""

from __future__ import annotations

from core.analysis.lifecycle_checker import (
    _guard_covers,
    _normalize_condition,
    check_all_fields,
    check_coverage,
    check_coverage_with_cfg,
)
from core.analysis.lifecycle_model import (
    Guard,
    ReadSite,
    StateField,
    WriteSite,
)


def _guard(cond: str, file: str = "a.c", line: int = 1) -> Guard:
    return Guard(condition=cond, file=file, line=line)


def _ptrace_field() -> StateField:
    """The canonical CVE-2026-46333 test case."""
    return StateField(
        name="dumpable",
        struct_type="task_struct",
        invariant="meaningful only when task owns an mm",
        cwe="CWE-863",
        write_sites=[
            WriteSite(
                file="fs/exec.c", line=100, function="setup_new_exec",
                guards=frozenset({_guard("current->mm", "fs/exec.c", 95)}),
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


class TestNormalizeCondition:
    def test_null_check_normalized(self):
        assert _normalize_condition("task->mm != NULL") == "task->mm"

    def test_zero_check_normalized(self):
        assert _normalize_condition("x != 0") == "x"

    def test_whitespace_normalized(self):
        assert _normalize_condition("  a  &&  b  ") == "a && b"

    def test_equality_null_preserved(self):
        assert "== null" in _normalize_condition("p == NULL")

    def test_plain_condition(self):
        assert _normalize_condition("x > 5") == "x > 5"


class TestGuardCovers:
    def test_exact_match(self):
        a = _guard("task->mm != NULL")
        b = _guard("task->mm != NULL")
        assert _guard_covers(a, b)

    def test_normalized_match(self):
        a = _guard("task->mm")
        b = _guard("task->mm != NULL")
        assert _guard_covers(a, b)

    def test_no_match(self):
        a = _guard("task->flags")
        b = _guard("task->mm != NULL")
        assert not _guard_covers(a, b)


class TestCheckCoverage:
    def test_ptrace_dumpability(self):
        """CVE-2026-46333: read site lacks write-site guard."""
        field = _ptrace_field()
        findings = check_coverage(field)
        assert len(findings) == 1
        assert "current->mm" in findings[0].missing_guards
        assert findings[0].confidence == "high"
        assert findings[0].read_site.function == "__ptrace_may_access"

    def test_covered_read_site(self):
        """Read site has the same guard — no finding."""
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="meaningful only when task owns an mm",
            write_sites=[
                WriteSite(
                    file="fs/exec.c", line=100, function="setup_new_exec",
                    guards=frozenset({_guard("task->mm != NULL", "fs/exec.c", 95)}),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="kernel/ptrace.c", line=200,
                    function="__ptrace_may_access",
                    guards=frozenset({_guard("task->mm != NULL", "kernel/ptrace.c", 195)}),
                ),
            ],
        )
        findings = check_coverage(field)
        assert len(findings) == 0

    def test_no_write_guards(self):
        """Write site has no guards — nothing to check."""
        field = StateField(
            name="x", struct_type="S", invariant="test",
            write_sites=[
                WriteSite(file="a.c", line=1, function="f", guards=frozenset()),
            ],
            read_sites=[
                ReadSite(file="b.c", line=2, function="g", guards=frozenset()),
            ],
        )
        findings = check_coverage(field)
        assert len(findings) == 0

    def test_non_security_relevant_skipped(self):
        field = _ptrace_field()
        field.read_sites = [
            ReadSite(
                file="kernel/ptrace.c", line=200,
                function="__ptrace_may_access",
                guards=frozenset(),
                security_relevant=False,
            ),
        ]
        findings = check_coverage(field)
        assert len(findings) == 0

    def test_partial_coverage_medium_confidence(self):
        """Read site covers one guard but misses another."""
        field = StateField(
            name="flags", struct_type="task_struct",
            invariant="requires both mm and lock",
            write_sites=[
                WriteSite(
                    file="a.c", line=1, function="f",
                    guards=frozenset({
                        _guard("task->mm != NULL", "a.c", 1),
                        _guard("lock_held", "a.c", 2),
                    }),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="b.c", line=10, function="g",
                    guards=frozenset({_guard("task->mm", "b.c", 9)}),
                ),
            ],
        )
        findings = check_coverage(field)
        assert len(findings) == 1
        assert findings[0].confidence == "medium"
        assert "lock_held" in findings[0].missing_guards


class TestCheckAllFields:
    def test_multiple_fields(self):
        fields = [
            _ptrace_field(),
            StateField(
                name="safe", struct_type="task_struct", invariant="always safe",
                write_sites=[],
                read_sites=[
                    ReadSite(file="a.c", line=1, function="f", guards=frozenset()),
                ],
            ),
        ]
        findings = check_all_fields(fields)
        assert len(findings) == 1


class _FakeNode:
    def __init__(self, lineno, label):
        self.lineno = lineno
        self.label = label


class _FakeCFG:
    def __init__(self, nodes, adjacency):
        self._nodes = nodes
        self._adjacency = adjacency
        self.entry = nodes[0] if nodes else None

    def nodes(self):
        return self._nodes

    def successors(self, node):
        return self._adjacency.get(id(node), [])


class TestCheckCoverageWithCfg:
    def test_guarded_read_no_finding(self):
        """CFG has guard on all paths to read site — no finding."""
        n_entry = _FakeNode(1, "entry")
        n_guard = _FakeNode(95, "If (current->mm)")
        n_read = _FakeNode(200, "get_dumpable()")
        n_exit = _FakeNode(300, "exit")
        cfg = _FakeCFG(
            [n_entry, n_guard, n_read, n_exit],
            {
                id(n_entry): [n_guard],
                id(n_guard): [n_read, n_exit],
                id(n_read): [n_exit],
            },
        )
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="requires mm",
            write_sites=[
                WriteSite(
                    file="a.c", line=10, function="write_fn",
                    guards=frozenset({_guard("current->mm", "a.c", 5)}),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="b.c", line=200, function="read_fn",
                    guards=frozenset(),
                ),
            ],
        )
        findings = check_coverage_with_cfg(field, cfg)
        assert len(findings) == 0

    def test_unguarded_read_produces_finding(self):
        """CFG has path that bypasses guard — finding emitted."""
        n_entry = _FakeNode(1, "entry")
        n_guard = _FakeNode(95, "If (current->mm)")
        n_guarded = _FakeNode(96, "guarded path")
        n_bypass = _FakeNode(97, "bypass path")
        n_read = _FakeNode(200, "get_dumpable()")
        n_exit = _FakeNode(300, "exit")
        cfg = _FakeCFG(
            [n_entry, n_guard, n_guarded, n_bypass, n_read, n_exit],
            {
                id(n_entry): [n_guard, n_bypass],
                id(n_guard): [n_guarded, n_exit],
                id(n_guarded): [n_read],
                id(n_bypass): [n_read],
                id(n_read): [n_exit],
            },
        )
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="requires mm",
            write_sites=[
                WriteSite(
                    file="a.c", line=10, function="write_fn",
                    guards=frozenset({_guard("current->mm", "a.c", 5)}),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="b.c", line=200, function="read_fn",
                    guards=frozenset(),
                ),
            ],
        )
        findings = check_coverage_with_cfg(field, cfg)
        assert len(findings) == 1
        assert "current->mm" in findings[0].missing_guards

    def test_fallback_when_cfg_has_no_entry(self):
        """Falls back to textual when CFG lacks expected interface."""
        field = _ptrace_field()
        findings = check_coverage_with_cfg(field, object())
        assert len(findings) == 1


class TestCheckAllFieldsWithCfgs:
    def test_uses_cfg_when_available(self):
        n_entry = _FakeNode(1, "entry")
        n_guard = _FakeNode(95, "If (current->mm)")
        n_read = _FakeNode(200, "get_dumpable()")
        n_exit = _FakeNode(300, "exit")
        cfg = _FakeCFG(
            [n_entry, n_guard, n_read, n_exit],
            {
                id(n_entry): [n_guard],
                id(n_guard): [n_read, n_exit],
                id(n_read): [n_exit],
            },
        )
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="requires mm",
            write_sites=[
                WriteSite(
                    file="a.c", line=10, function="write_fn",
                    guards=frozenset({_guard("current->mm", "a.c", 5)}),
                ),
            ],
            read_sites=[
                ReadSite(
                    file="kernel/ptrace.c", line=200, function="read_fn",
                    guards=frozenset(),
                ),
            ],
        )
        findings = check_all_fields([field], cfgs={"kernel/ptrace.c": cfg})
        assert len(findings) == 0

    def test_without_cfgs_uses_textual(self):
        field = _ptrace_field()
        findings = check_all_fields([field])
        assert len(findings) == 1
