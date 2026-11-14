import functools

import pytest

from core.dataflow import structural_validator as sv
from core.inventory.extractors import TreeSitterExtractor
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


def _source(name, callee="helper"):
    return ("void helper(char *v) { (void)v; }\n"
            "void other(char *v) { (void)v; }\n"
            f"void {name}(char *v) {{\n  char *copied = v;\n"
            f"  {callee}(copied);\n}}\n")


@pytest.mark.parametrize("name", ["class", "new"])
def test_refused_named_c_span_cannot_establish_absence(tmp_path, name):
    pytest.importorskip("tree_sitter_c")
    source = _source(name)
    extractor = TreeSitterExtractor("c")
    tree = extractor.parser.parse(source.encode())
    assert not tree.root_node.has_error
    spans = extractor.extract("app.c", source, _tree=tree)
    assert {x.name for x in spans} == {"helper", "other"}  # Existing inventory gate.
    graph = sv._extract_graph(source, "c")
    assert any(c.caller == name and c.chain == ["helper"] for c in graph.calls)
    (tmp_path / "app.c").write_text(source)
    result = sv.validate_structurally({
        "source": {"file": "app.c", "line": 4},
        "sink": {"file": "app.c", "line": 1},
    }, tmp_path, language="c")
    assert result.verdict == "inconclusive"


@pytest.mark.parametrize("callee,expected", [("helper", "confirmed"), ("other", "refuted")])
def test_ordinary_c_span_preserves_link_decisions(tmp_path, callee, expected):
    pytest.importorskip("tree_sitter_c")
    (tmp_path / "app.c").write_text(_source("handler", callee))
    result = sv.validate_structurally({
        "source": {"file": "app.c", "line": 4},
        "sink": {"file": "app.c", "line": 1},
    }, tmp_path, language="c")
    assert result.verdict == expected


def test_unnamed_generator_is_not_a_refused_named_span():
    pytest.importorskip("tree_sitter_javascript")
    extractor = TreeSitterExtractor("javascript")
    source = "export default function*(value) { yield value; }\n"
    tree = extractor.parser.parse(source.encode())
    assert not tree.root_node.has_error
    assert extractor.extract("owned.js", source, _tree=tree, raise_on_error=True) == []
