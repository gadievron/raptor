import ast
import functools

import pytest

from core.dataflow import structural_validator as sv
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


@pytest.mark.parametrize("spelling,canonical", [("K", "K"), ("Ｋ", "K"), ("Κ", "Κ"), ("K", "K")],
                         ids=["kelvin", "fullwidth", "greek", "ascii"])
def test_python_span_caller_uses_the_ast_identifier_form(tmp_path, spelling, canonical):
    source = f"def helper(value):\n    return value\n\ndef {spelling}(value):\n    copied = value\n    helper(copied)\n"
    assert ast.parse(source).body[1].name == canonical
    (tmp_path / "app.py").write_text(source)
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 5},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert result.evidence[0]["function"] == canonical


def test_normalized_caller_without_the_edge_still_refutes(tmp_path):
    (tmp_path / "app.py").write_text("def helper(value):\n    return value\n\ndef K(value):\n    copied = value\n    return copied\n")
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 5},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.refuted
