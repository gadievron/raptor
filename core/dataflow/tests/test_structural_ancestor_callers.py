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


@pytest.mark.parametrize("language,extension,grammar", [
    ("javascript", "js", "tree_sitter_javascript"),
    ("typescript", "ts", "tree_sitter_typescript"),
    ("tsx", "tsx", "tree_sitter_typescript"),
], ids=["js", "ts", "tsx"])
def test_nested_arrow_ancestor_attribution_cannot_refute(tmp_path, language, extension, grammar):
    pytest.importorskip(grammar)
    source = ("function helper(v) { return v; }\nfunction outer(v) {\n"
              "  const inner = (v) => {\n    const copied = v;\n"
              "    helper(copied);\n    return copied;\n  };\n"
              "  return inner(v);\n}\n")
    filename = "app." + extension
    (tmp_path / filename).write_text(source)
    result = sv.validate_structurally({
        "source": {"file": filename, "line": 4},
        "sink": {"file": filename, "line": 1},
    }, tmp_path, language=language)
    assert result.verdict == "inconclusive"
    assert result.evidence[0]["function"] == "inner"


def test_named_child_calls_do_not_demote_genuine_outer_absence(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_text(
        "function helper(v) { return v; }\nfunction outer(v) {\n"
        "  function child(v) { helper(v); }\n  const copied = v;\n"
        "  return copied;\n}\n",
    )
    result = sv.validate_structurally({
        "source": {"file": "app.js", "line": 4},
        "sink": {"file": "app.js", "line": 1},
    }, tmp_path, language="javascript")
    assert result.refuted
    assert result.evidence[0]["function"] == "outer"
