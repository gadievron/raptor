import functools

import pytest

from core.dataflow import structural_validator as sv
from core.inventory import extractors
from core.testing.module_state import isolated_module_state


_JS = ("function helper(v) { return v; }\nfunction outer(v) {\n"
       "  function* inner(v) {\n    const copied = v;\n"
       "    helper(copied);\n    yield copied;\n  }\n"
       "  return inner(v);\n}\n")


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


def _fail_inner_metadata(monkeypatch):
    original = extractors.TreeSitterExtractor._extract_function
    reached = []

    def fail_inner(self, node, *args, **kwargs):
        name = node.child_by_field_name("name")
        if name is not None and name.text == b"inner":
            reached.append(node.text.decode())
            raise RuntimeError("owned inner metadata failure")
        return original(self, node, *args, **kwargs)

    monkeypatch.setattr(extractors.TreeSitterExtractor, "_extract_function", fail_inner)
    return reached


@pytest.mark.parametrize("language,extension,grammar", [
    ("javascript", "js", "tree_sitter_javascript"),
    ("typescript", "ts", "tree_sitter_typescript"),
    ("tsx", "tsx", "tree_sitter_typescript"),
], ids=["js", "ts", "tsx"])
def test_partial_native_function_spans_cannot_refute(tmp_path, monkeypatch, language, extension, grammar):
    pytest.importorskip(grammar)
    graph = sv._extract_graph(_JS, language)
    assert any(c.caller == "inner" and c.chain == ["helper"] for c in graph.calls)
    reached = _fail_inner_metadata(monkeypatch)
    filename = "app." + extension
    (tmp_path / filename).write_text(_JS)
    result = sv.validate_structurally({
        "source": {"file": filename, "line": 4},
        "sink": {"file": filename, "line": 1},
    }, tmp_path, language=language)
    assert len(reached) == 1
    assert result.verdict == "inconclusive"


def test_python_spans_use_ast_when_rich_metadata_is_unavailable(tmp_path, monkeypatch):
    pytest.importorskip("tree_sitter_python")
    reached = _fail_inner_metadata(monkeypatch)
    (tmp_path / "app.py").write_text(
        "def helper(v):\n    return v\n\ndef outer(v):\n"
        "    def inner(v):\n        copied = v\n        helper(copied)\n"
        "        return copied\n    return inner(v)\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 6},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert result.evidence[0]["function"] == "inner"
    assert not reached


def test_inventory_partial_recovery_remains_default(monkeypatch):
    pytest.importorskip("tree_sitter_javascript")
    reached = _fail_inner_metadata(monkeypatch)
    extractor = extractors.TreeSitterExtractor("javascript")
    assert {x.name for x in extractor.extract("owned.js", _JS)} == {"helper", "outer"}
    with pytest.raises(RuntimeError, match="owned inner metadata failure"):
        extractor.extract("owned.js", _JS, raise_on_error=True)
    assert {x.name for x in extractor.extract("owned.js", _JS)} == {"helper", "outer"}
    assert len(reached) == 3


def test_python_top_level_call_keeps_module_attribution(tmp_path):
    (tmp_path / "app.py").write_text(
        "def helper(v):\n    return v\n\nvalue = input()\nhelper(value)\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 5},
        "sink": {"file": "app.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert "function" not in result.evidence[0]
