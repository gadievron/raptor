import functools

import pytest

from core.dataflow import structural_validator as sv
from core.inventory import call_graph, extractors
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


@pytest.mark.parametrize("failure", ["exception", "no_tree"])
@pytest.mark.parametrize("language,suffix,grammar", [
    ("javascript", "js", "tree_sitter_javascript"),
    ("typescript", "ts", "tree_sitter_typescript"),
    ("tsx", "tsx", "tree_sitter_typescript"),
])
def test_native_graph_parser_failure_is_not_a_broken_edge(tmp_path, language, suffix, grammar, failure):
    pytest.importorskip(grammar)
    source = "function source() {\n  return input();\n}\nfunction handler() {\n  const value = source();\n  sink(value);\n}\n"
    if language != "javascript":
        source = source.replace("const value =", "const value: string =")
    name = f"app.{suffix}"
    (tmp_path / name).write_text(source)
    path = {"source": {"file": name, "line": 2},
            "sink": {"file": name, "line": 6}}
    assert sv.validate_structurally(path, tmp_path, language=language).verdict == "confirmed"
    assert {item.name for item in sv._extract_functions_cached(language, source)} >= {"source", "handler"}
    calls = []

    class FailedParser:
        def parse(self, content):
            assert content == source.encode()
            calls.append(content)
            if failure == "no_tree":
                return None
            raise RuntimeError("owned graph parser unavailable")

    with pytest.MonkeyPatch.context() as patcher:
        for consumer in (call_graph, extractors):
            patch_module_attribute(
                patcher, consumer, "_ts_cache", "cached_parser",
                lambda key, language_factory: FailedParser(),
            )
        result = sv.validate_structurally(path, tmp_path, language=language)
    assert len(calls) == 1
    assert result.verdict == "inconclusive"
    assert not result.refuted


def test_valid_empty_javascript_graph_can_still_refute_an_absent_edge(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = "function first() {\n  return 1;\n}\nfunction second() {\n  return 2;\n}\n"
    (tmp_path / "app.js").write_text(source)
    graph = sv._extract_graph(source, "javascript")
    assert graph is not None and graph.calls == []
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 2},
        "sink": {"file": "app.js", "line": 5},
    }, tmp_path, language="javascript")
    assert result.refuted
