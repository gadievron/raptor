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


@pytest.mark.parametrize("callee,expected", [("helper", "confirmed"), ("other", "refuted")])
def test_nested_assignment_uses_inner_call_edges(tmp_path, callee, expected):
    source = ("def helper(value):\n    return value\n\ndef outer(value):\n"
              "    def inner(value):\n        copied = value\n"
              f"        {callee}(copied)\n    return inner(value)\n")
    (tmp_path / "app.py").write_text(source)
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 6},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == expected
    assert result.evidence[0]["function"] == "inner"


def test_outer_assignment_keeps_outer_call_edges(tmp_path):
    (tmp_path / "app.py").write_text(
        "def helper(value):\n    return value\n\ndef outer(value):\n"
        "    def inner(value):\n        helper(value)\n"
        "    copied = value\n    return copied\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 7},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.refuted
    assert result.evidence[0]["function"] == "outer"
