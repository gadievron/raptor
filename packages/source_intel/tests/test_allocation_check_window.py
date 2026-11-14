"""Inert lexical-window controls; no source parsing or native tools."""

import pytest

from packages.source_intel import adapter


@pytest.mark.parametrize("lines,sink,expected", [
    (["p = alloc();", "if (validate(p))", "use(p);", "return;"], 3, False),
    (["p = alloc();", "if (validate(p)) return;", "use(p);"], 3, True),
    (["p = alloc();", "err = validate(p);", "use(p);", "if (err) return;"], 3, False),
    (["p = alloc();", "err = validate(p);", "if (err) return;", "use(p);"], 4, True),
    (["p = alloc();", "err = validate(p);", "if (err)", "use(p);", "return;"], 4, False),
])
def test_checks_and_exits_must_precede_sink(monkeypatch, lines, sink, expected):
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda *args: lines)
    assert adapter._has_interprocedural_check("owned-unused.c", 1, sink, "p") is expected
