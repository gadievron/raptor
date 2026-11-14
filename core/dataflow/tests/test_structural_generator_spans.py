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


@pytest.mark.parametrize("language,extension,grammar", [
    ("javascript", "js", "tree_sitter_javascript"),
    ("typescript", "ts", "tree_sitter_typescript"),
    ("tsx", "tsx", "tree_sitter_typescript"),
], ids=["js", "ts", "tsx"])
@pytest.mark.parametrize("prefix", ["", "async "], ids=["sync", "async"])
@pytest.mark.parametrize("callee,expected", [("helper", "confirmed"), ("other", "refuted")],
                         ids=["edge", "missing"])
def test_nested_generator_uses_its_own_span(tmp_path, language, extension, grammar, prefix, callee, expected):
    pytest.importorskip(grammar)
    source = ("function helper(v) { return v; }\nfunction outer(v) {\n"
              f"  {prefix}function* inner(v) {{\n    const copied = v;\n"
              f"    {callee}(copied);\n    yield copied;\n  }}\n"
              "  return inner(v);\n}\n")
    filename = "app." + extension
    (tmp_path / filename).write_text(source)
    result = sv.validate_structurally({
        "source": {"file": filename, "line": 4},
        "sink": {"file": filename, "line": 1},
    }, tmp_path, language=language)
    assert result.verdict == expected
    assert result.evidence[0]["function"] == "inner"
    spans = TreeSitterExtractor(language).extract(filename, source)
    inner = next(item for item in spans if item.name == "inner")
    assert (inner.line_start, inner.line_end) == (3, 7)


def test_outer_step_does_not_borrow_generator_calls(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = ("function helper(v) { return v; }\nfunction outer(v) {\n"
              "  function* inner(v) {\n    helper(v);\n    yield v;\n  }\n"
              "  const copied = v;\n  return inner(copied);\n}\n")
    (tmp_path / "app.js").write_text(source)
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 7},
        "sink": {"file": "app.js", "line": 1},
    }, tmp_path, language="javascript")
    assert result.refuted
    assert result.evidence[0]["function"] == "outer"
