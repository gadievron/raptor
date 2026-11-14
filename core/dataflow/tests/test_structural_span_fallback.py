import functools

import pytest

from core.dataflow import structural_validator as sv
from core.inventory import extractors
from core.testing.module_state import isolated_module_state


_SOURCE = ("function helper(v) { return v; }\nfunction outer(v) {\n"
           "  function* inner(v) {\n    const copied = v;\n"
           "    helper(copied);\n    yield copied;\n  }\n"
           "  return inner(v);\n}\n")


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


@pytest.mark.parametrize("language,extension,grammar", [
    ("javascript", "js", "tree_sitter_javascript"),
    ("typescript", "ts", "tree_sitter_typescript"),
    ("tsx", "tsx", "tree_sitter_typescript"),
], ids=["js", "ts", "tsx"])
@pytest.mark.parametrize("failure", ["factory", "parse", "no_tree"])
def test_native_span_failure_is_not_regex_absence(tmp_path, monkeypatch, language, extension, grammar, failure):
    pytest.importorskip(grammar)
    graph = sv._extract_graph(_SOURCE, language)
    assert graph is not None
    assert any(c.caller == "inner" and c.chain == ["helper"] for c in graph.calls)
    original = extractors.TreeSitterExtractor
    reached = []

    class SpanParserFailure:
        def parse(self, payload):
            assert payload == _SOURCE.encode()
            reached.append("parse")
            if failure == "parse":
                raise RuntimeError("owned span parse failure")
            return None

    def span_factory(selected_language):
        assert selected_language == language
        reached.append("factory")
        if failure == "factory":
            raise RuntimeError("owned span factory failure")
        extractor = original(selected_language)
        extractor.parser = SpanParserFailure()
        return extractor

    filename = "app." + extension
    (tmp_path / filename).write_text(_SOURCE)
    monkeypatch.setattr(extractors, "TreeSitterExtractor", span_factory)
    result = sv.validate_structurally({
        "source": {"file": filename, "line": 4},
        "sink": {"file": filename, "line": 1},
    }, tmp_path, language=language)
    assert reached.count("factory") == 1
    if failure != "factory":
        assert reached.count("parse") == 1
    assert result.verdict == "inconclusive"
    assert not result.refuted
