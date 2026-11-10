"""Unavailable preprocessing must reach every C/C++ CFG proof consumer."""
import pytest

from core.analysis.finding_resolver import ResolutionFailure, resolve_finding
from core.analysis.tests.test_cpp_macro_fidelity import _source, gap_transport as gap_transport
from core.audit import release_order, resource_bounds
from core.audit.block_review import try_build_cfg

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("collector", [resource_bounds._guards_at, release_order._guards_at])
def test_guard_collectors_cannot_read_a_preprocessor_approximation(language, collector):
    source = _source("#define CHANGE safe = raw\n")
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume(safe)" in text)
    assert collector(source, "handle", line, "owned.c", language) is None


@pytest.mark.parametrize("language,suffix", [("c", "c"), ("cpp", "cpp")])
def test_finding_and_block_consumers_receive_unavailable_cfg(tmp_path, language, suffix):
    source = _source("#define CHANGE safe = raw\n")
    path = tmp_path / f"owned.{suffix}"
    path.write_text(source)
    assert try_build_cfg(path.name, "handle", tmp_path) is None
    source_line = next(i for i, text in enumerate(source.splitlines(), 1) if "void handle(" in text)
    sink_line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume(safe)" in text)
    result = resolve_finding({"file_path": str(path), "source_line": source_line,
                              "sink_line": sink_line, "language": language, "cwe": "CWE-78"})
    assert isinstance(result, ResolutionFailure)
    assert "preprocessing" in result.reason



def test_unavailable_caller_guards_cannot_confirm_missing_bound(tmp_path):
    inner = "void insert_fn(void)\n{\n    list_add(x, y);\n}\n"
    caller = ("#define CAP if (g_session_count > 4) return\n"
              "extern int g_session_count;\nvoid caller(void)\n{\n"
              "    CAP;\n    insert_fn();\n}\n")
    (tmp_path / "inner.c").write_text(inner)
    (tmp_path / "caller.c").write_text(caller)
    result = resource_bounds.run_resource_bounds_check(
        tmp_path, "inner.c", "insert_fn", "the list grows without limit",
        source_texts={"inner.c": inner, "caller.c": caller},
    )
    assert result.outcome == "inconclusive", result.reason
    assert resource_bounds.REASON_CENSUS_DEGRADED in result.reason
    caller_receipt, = result.bound_search["callers"]
    assert caller_receipt["guards_available"] is False
