"""Tests for core.analysis.lifecycle_collector — guard extraction."""

from __future__ import annotations

from core.analysis.lifecycle_collector import (
    _extract_condition_from_label,
    collect_field_sites_from_source,
)


class TestExtractCondition:
    def test_if_condition(self):
        assert _extract_condition_from_label("If (x != NULL)") == "x != NULL"

    def test_while_condition(self):
        assert _extract_condition_from_label("While (i < n)") == "i < n"

    def test_elif_condition(self):
        assert _extract_condition_from_label("ElIf (y > 0)") == "y > 0"

    def test_no_condition(self):
        assert _extract_condition_from_label("stmt: x = 5") is None

    def test_complex_condition(self):
        cond = _extract_condition_from_label("If (task->mm && task->flags & PF_EXITING)")
        assert cond == "task->mm && task->flags & PF_EXITING"


class TestCollectFieldSites:
    def test_arrow_write_and_read(self):
        source = (
            "void f(struct task_struct *t) {\n"
            "    if (t->mm) {\n"
            "        t->dumpable = SUID_DUMP_USER;\n"
            "    }\n"
            "}\n"
            "int g(struct task_struct *t) {\n"
            "    return t->dumpable;\n"
            "}\n"
        )
        sites = collect_field_sites_from_source(source, "test.c", "dumpable")
        assert 3 in sites["writes"]
        assert 7 in sites["reads"]

    def test_dot_access(self):
        source = (
            "obj.field = 1;\n"
            "x = obj.field;\n"
        )
        sites = collect_field_sites_from_source(source, "test.py", "field")
        assert 1 in sites["writes"]
        assert 2 in sites["reads"]

    def test_comparison_not_write(self):
        source = "if (t->dumpable == 0) return;\n"
        sites = collect_field_sites_from_source(source, "test.c", "dumpable")
        assert sites["writes"] == []
        assert 1 in sites["reads"]

    def test_no_matches(self):
        source = "int x = 5;\n"
        sites = collect_field_sites_from_source(source, "test.c", "dumpable")
        assert sites["writes"] == []
        assert sites["reads"] == []
