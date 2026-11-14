import ast
import functools

import pytest

from core.dataflow import structural_validator as sv
from core.testing.module_state import isolated_module_state


_SOURCE = "def source():\n    return input()\n\ndef handler():\n    value = source()\n    eval(value)\n"


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


def _path():
    return {"source": {"file": "app.py", "line": 2},
            "sink": {"file": "app.py", "line": 6}}


def test_bom_parse_failure_cannot_establish_a_broken_call_chain(tmp_path):
    raw = b"\xef\xbb\xbf" + _SOURCE.encode()
    ast.parse(raw)  # Valid owned byte source; never executed.
    (tmp_path / "app.py").write_bytes(raw)
    result = sv.validate_structurally(_path(), tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted


def test_syntax_failure_does_not_establish_call_absence(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE + "if (\n")
    result = sv.validate_structurally(_path(), tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted


def test_valid_return_flow_still_confirms(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE)
    result = sv.validate_structurally(_path(), tmp_path, language="python")
    assert result.verdict == "confirmed"


def test_valid_call_free_source_still_supports_a_broken_edge(tmp_path):
    source = "def first():\n    return 1\n\ndef second():\n    return 2\n"
    (tmp_path / "app.py").write_text(source)
    graph = sv._extract_graph(source, "python")
    assert graph is not None and graph.calls == []
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 2},
        "sink": {"file": "app.py", "line": 5},
    }, tmp_path, language="python")
    assert result.refuted
