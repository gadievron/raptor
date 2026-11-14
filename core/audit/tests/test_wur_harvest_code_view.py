"""Harvest code-view admission using owned views, not lexer execution."""

import ast
import __future__
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from core.audit import source_view


@pytest.fixture
def harvest():
    path = Path(__file__).resolve().parents[1] / "return_contracts.py"
    tree = ast.parse(path.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "harvest_wur_declarations")
    namespace = {"re": re, "split_lines": lambda text: text.split("\n")}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec",
                 flags=__future__.annotations.compiler_flag), namespace)
    return namespace["harvest_wur_declarations"]


@pytest.mark.parametrize("raw", ["/* __wur */\nint victim(void);\n", 'const char *note = "__wur";\nint victim(void);\n'],
                         ids=["comment", "string"])
def test_blanked_alias_decoy_does_not_donate_function(harvest, monkeypatch, raw):
    code = " " * len(raw.split("\n")[0]) + "\nint victim(void);\n"
    calls = []

    def view(text, path):
        assert text == raw and path == "owned.h"
        calls.append(path)
        return SimpleNamespace(text=code, ambiguous=False)

    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    assert harvest({"owned.h": raw}) == frozenset()
    assert calls == ["owned.h"]


@pytest.mark.parametrize("text, expected", [
    ("__wur int victim(void);\n", {"victim"}),
    ("[[nodiscard]] int victim(void);\n", {"victim"}),
    ("int victim(int a,\n int b) __attribute__((warn_unused_result));\n", {"victim"}),
    ("int unrelated(void);\n__attribute__((warn_unused_result))\nint victim(void);\n", {"victim"}),
], ids=["alias", "cpp-literal", "wrapped-trailing", "attribute-first"])
def test_admitted_code_keeps_existing_declaration_window(harvest, monkeypatch, text, expected):
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda raw, path: SimpleNamespace(text=raw, ambiguous=False))
    assert harvest({"owned.hpp": text}) == frozenset(expected)


def test_ambiguous_view_does_not_donate_facts(harvest, monkeypatch):
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda raw, path: SimpleNamespace(text=raw, ambiguous=True))
    assert harvest({"owned.h": "__wur int victim(void);"}) == frozenset()


def test_no_alias_prefilter_avoids_code_view(harvest, monkeypatch):
    monkeypatch.setattr(source_view, "sanitized_view_with_status", lambda *args: pytest.fail("unexpected view"))
    assert harvest({"owned.h": "int victim(void);"}) == frozenset()
