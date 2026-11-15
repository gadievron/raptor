"""Owned embedded reports retain full spans through parsing and deduplication."""
import ast
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from packages.coccinelle.runner import _dedup_matches, _parse_results

_RULES = Path(__file__).resolve().parents[1] / "rules"
_SCRIPTS = [
    ("is_err_not_ptr_err", 0), ("is_err_not_ptr_err", 1),
    ("is_err_not_ptr_err", 2), ("double_byteswap", 0),
    ("sensitive_data_leak", 0),
    ("division_by_zero", 0), ("division_by_zero", 1),
    ("double_sizeof", 0), ("double_sizeof", 1), ("sizeof_container_of", 0),
]


def _report(name, index, position, **bindings):
    rule = _RULES / f"{name}.cocci"
    scripts = re.findall(
        r"@script:python[^\n]*\n.*?\n@@\n(.*?)(?=\n@|\Z)", rule.read_text(), re.S,
    )
    tree = ast.parse(scripts[index])
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    output = io.StringIO()
    namespace = {"json": json, "p": [position], "p2": [position], "PARAM": "count", "swap1": "htons", "swap2": "ntohs", "V": "secret"}
    namespace.update(bindings)
    with redirect_stdout(output):
        exec(compile(tree, str(rule), "exec"), namespace)
    return output.getvalue()


@pytest.mark.parametrize("name,index", _SCRIPTS, ids=[f"{name}-{index}" for name, index in _SCRIPTS])
def test_report_spans_survive_parser_and_deduplication(name, index):
    first = SimpleNamespace(file="owned.c", line="4", column="2", line_end="5", column_end="18")
    second = SimpleNamespace(file="owned.c", line="4", column="2", line_end="6", column_end="23")
    first_output = _report(name, index, first)
    second_output = _report(name, index, second)
    # Plain-prefix parsing is an owned transport control, not a nonce-authentication test.
    matches = _parse_results(first_output + second_output + first_output, name)
    assert len(matches) == 3
    rows = _dedup_matches(matches)
    assert len(rows) == 2
    assert [(row.file, row.line, row.column, row.line_end, row.column_end) for row in rows] == [
        ("owned.c", 4, 2, 5, 18), ("owned.c", 4, 2, 6, 23),
    ]
    expected_rule = {
        ("division_by_zero", 0): "division_by_zero_param",
        ("division_by_zero", 1): "modulo_by_zero_param",
        ("double_sizeof", 1): "pointer_scaling_double",
    }.get((name, index), name)
    assert all(row.rule == expected_rule and row.message for row in rows)
    assert rows[0].message == rows[1].message


@pytest.mark.parametrize("bindings", [
    {"swap1": "htons", "swap2": "htole16"},
    {"swap1": "htons", "swap2": "htonl"},
], ids=["different-family", "different-width"])
def test_conversion_filter_stays_quiet(bindings):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("double_byteswap", 0, position, **bindings) == ""


def test_benign_sensitive_name_stays_quiet():
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("sensitive_data_leak", 0, position, V="usb_keyboard") == ""
