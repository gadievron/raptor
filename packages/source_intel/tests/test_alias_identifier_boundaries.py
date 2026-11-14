"""WUR identifier spellings need token boundaries, not substring matches."""

import ast
from collections import deque
import __future__
from pathlib import Path
import re
from typing import cast
from types import SimpleNamespace

from core.audit import source_view

import pytest

from packages.source_intel import aliases


@pytest.mark.parametrize("spelling", ["__must_check", "__wur", "__attribute_warn_unused_result__", "__result_use_check"],
                         ids=["kernel", "glibc", "glibc-attribute", "bsd"])
@pytest.mark.parametrize("shape", ["prefix", "suffix", "both"])
def test_identifier_alias_inside_longer_identifier_is_not_a_match(spelling, shape):
    text = {"prefix": "ordinary" + spelling, "suffix": spelling + "suffix",
            "both": "ordinary" + spelling + "suffix"}[shape]
    assert not aliases.wur_alias_in(text)


@pytest.mark.parametrize("spelling", aliases.ALL_WUR_ALIASES,
                         ids=["gcc", "gcc-underscores", "kernel", "glibc", "glibc-attribute", "nodiscard", "gnu", "clang", "bsd"])
def test_existing_spellings_still_match(spelling):
    assert aliases.wur_alias_in(" " + spelling + " int victim(void);")


def _owned_helper(relative_path, name, namespace):
    root = Path(__file__).resolve().parents[3]
    path = root / relative_path
    tree = ast.parse(path.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec",
                 flags=__future__.annotations.compiler_flag), namespace)
    return namespace[name]


@pytest.mark.parametrize("consumer", ["same-file", "harvest"])
@pytest.mark.parametrize("annotation", [False, True], ids=["embedded", "real-alias"])
def test_actual_consumer_helpers_do_not_promote_embedded_identifier(consumer, annotation, monkeypatch):
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda text, path: SimpleNamespace(text=text, ambiguous=False))
    text = "__wur int victim(void);\n" if annotation else "int ordinary__wur_suffix;\nint victim(void);\n"
    namespace = {"re": re, "split_lines": lambda source: source.split("\n"),
                 "_SEGMENT_TYPE_IMPL": type, "cast": cast, "deque": deque}
    if consumer == "same-file":
        helper = _owned_helper("core/audit/fail_open_verify.py", "_same_file_wur", namespace)
        assert helper(text, "victim") is annotation
    else:
        helper = _owned_helper("core/audit/return_contracts.py", "harvest_wur_declarations", namespace)
        assert ("victim" in helper({"owned.c": text})) is annotation
