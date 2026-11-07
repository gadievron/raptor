"""Shared target layout primitives have no dependency on audit orchestration."""

import ast
import importlib
from pathlib import Path

import pytest

from core.smt_solver.integer_abi import INTEGER_ABIS
from core.smt_solver.sizeof_model import builtin_integer_sizeof


@pytest.mark.parametrize(
    "profile,spelling,expected",
    [
        ("lp64", "long", 8),
        ("ilp32", "long", 4),
        ("i16", "int", 2),
        ("lp64", "unsigned char", 1),
        ("lp64", "_Bool", None),
        ("lp64", "long*", None),
        (None, "long", None),
    ],
)
def test_storage_facts_are_explicit_and_target_bound(profile, spelling, expected):
    assert builtin_integer_sizeof(spelling, profile) == expected


def test_target_byte_unit_comes_from_the_layout():
    layout = dict(INTEGER_ABIS["lp64"].record(), name="wide-byte", char_bits=16)
    assert builtin_integer_sizeof("long", layout) == 4


@pytest.mark.parametrize("name", ["integer_abi", "integer_types", "sizeof_model"])
def test_shared_layout_modules_do_not_import_audit(name):
    module = importlib.import_module("core.smt_solver." + name)
    tree = ast.parse(Path(module.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("core.audit")
        elif isinstance(node, ast.Import):
            assert not any(alias.name.startswith("core.audit") for alias in node.names)
