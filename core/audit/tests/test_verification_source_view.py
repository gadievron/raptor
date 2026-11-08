"""The review loop keeps prompt rendering out of mechanical source input."""

import pytest

from core.audit import orchestrator as orch
from core.audit.probe_function_scope import source_for_function
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.shared_state import SharedState
from core.audit.sweep import SweepResult
from core.json import load_json


FULL_SOURCE = "// owned fixture\n// non-first-line function\nint f(int n) {\n    return n;\n}\n"
RAW_SOURCE = "int f(int n) {\n    return n;\n}"


@pytest.mark.parametrize("has_gap_source", [False, True])
@pytest.mark.parametrize("mutation", ["none", "stale", "bad_gutter", "empty_gutter", "interior_gutter"])
def test_review_loop_dispatches_only_bound_raw_source(tmp_path, monkeypatch, has_gap_source, mutation):
    target = tmp_path / "target"
    target.mkdir()
    path = target / "a.c"
    path.write_text(FULL_SOURCE, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    gap = {"file": "a.c", "name": "f", "line_start": 3, "line_end": 5,
           "kind": "function", "sloc": 3, "pinned": True}
    if has_gap_source:
        gap["source"] = RAW_SOURCE
    item = {key: value for key, value in gap.items() if key != "source"}
    shared = SharedState(checklist={"files": [{"path": "a.c", "items": [item]}]})
    config = orch.OrchestratorConfig(target_path=target, out_dir=out_dir,
        prefilter=False, max_refinements=0, immediate_verify=True)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    # Proactive validation is a separate consumer which deliberately reads
    # its own whole-file input. This fixture observes the immediate path.
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **kw: outcome)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw:
                        [{"type": "smt", "config": {"verb": "check-overflow"}}])
    seen, checked = [], []

    def review(context, cfg):
        seen.append(context["source"])
        assert context["source"].startswith("   3  int f(int n)")
        if mutation == "stale":
            path.write_text(FULL_SOURCE.replace("return n;", "return n + 0;"), encoding="utf-8")
        elif mutation == "bad_gutter":
            context["source"] = context["source"].replace("   3  ", "9999  ", 1)
        elif mutation == "empty_gutter":
            context["source"] = "   3  "
        elif mutation == "interior_gutter":
            context["source"] = context["source"].replace("   4  ", "   6  ", 1)
        return orch.ReviewOutcome(file="a.c", function="f", status="suspicious", body="Unresolved fixture concern",
            hypothesis="fixture arithmetic concern", review_result={"hypothesis": "fixture arithmetic concern", "cwe": "CWE-190"})

    def checker(**kwargs):
        checked.append(kwargs["source"])
        return SweepResult(tool="smt", file_path="a.c", function_name="f", outcome="inconclusive",
                           rule_id="check-overflow", details={"reason": "owned dispatch control"})

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    final = orch.review_one_function(gap, shared, config, review, orch.OrchestratorResult())
    assert len(seen) == 1
    assert checked == ([RAW_SOURCE] if mutation == "none" else [])
    assert final.status == "suspicious"
    assert not final.review_result.get("immediate_verified")
    write_graded_findings(export_findings([final]), out_dir)
    checks = load_json(out_dir / "verification-checks.json")["checks"]
    if mutation == "none":
        assert "smt" in (final.tools_dispatched or set())
        assert "smt" not in (final.tools_skipped or set())
        witness = next(c for c in checks if c["tool"] == "smt")
        assert witness["outcome"] == "inconclusive"
        assert witness["scope"]["source_identity"] is not None
    else:
        assert "smt" in (final.tools_skipped or set())
        rejection = next(c for c in checks if c["rule_id"] == "source-input-unbound")
        assert rejection["tool"] == "source_binding"


@pytest.mark.parametrize("line_start", [0, -1, True, None, "3"])
def test_unknown_occurrence_does_not_acquire_raw_source_from_display(line_start):
    rendered = "   1  int f(void) { return 0; }"
    assert orch._raw_ihv_review_source(rendered, line_start) == rendered


@pytest.mark.parametrize("raw", [
    "int f(void) { return 0; }",
    "int f(void) {\n\n    return 0;\n}",
    'const char *s = "   7  text";',
    "// unicode separator \u2028 remains in a physical line\nint f(void) { return 0; }",
])
def test_display_inverse_retains_source_text(raw):
    from core.source.lines import number_lines, split_lines

    rendered = "\n".join(number_lines(split_lines(raw), start_line=7))
    assert orch._raw_ihv_review_source(rendered, 7) == raw


def test_parser_scope_distinguishes_source_from_display(tmp_path):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")
    from core.audit.context import _read_source

    path = tmp_path / "a.c"
    path.write_text(FULL_SOURCE, encoding="utf-8")
    rendered = _read_source(tmp_path, path.name, 3, 5)
    assert source_for_function(rendered, path.name, "f")[0].status != "selected"
    assert source_for_function(RAW_SOURCE, path.name, "f")[0].status == "selected"


@pytest.mark.parametrize("kind", ["raw", "unmarked_display", "marked_display", "binary_display"])
def test_explicit_source_origin_and_binary_compatibility(tmp_path, monkeypatch, kind):
    from core.audit.context import _read_source

    (tmp_path / "a.c").write_text(FULL_SOURCE, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir, immediate_verify=True)
    file = "binary:demo" if kind == "binary_display" else "a.c"
    outcome = orch.ReviewOutcome(file=file, function="f", line=3, status="suspicious",
        body="Unresolved", hypothesis="fixture arithmetic concern",
        review_result={"hypothesis": "fixture arithmetic concern", "cwe": "CWE-190"})
    source = RAW_SOURCE if kind == "raw" else _read_source(tmp_path, "a.c", 3, 5)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw:
                        [{"type": "smt", "config": {"verb": "check-overflow"}}])
    checked = []

    def checker(**kwargs):
        checked.append(kwargs["source"])
        return SweepResult(tool="smt", file_path=file, function_name="f", outcome="inconclusive", rule_id="check-overflow")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    options = {"source_is_numbered": True} if kind in {"marked_display", "binary_display"} else {}
    final = orch._verify_hypotheses_immediate(outcome, cfg, orch.OrchestratorResult(), source=source, **options)
    expected = [] if kind == "unmarked_display" else [source if kind == "binary_display" else RAW_SOURCE]
    assert checked == expected
    assert final.status == "suspicious" and not final.review_result.get("immediate_verified")
    write_graded_findings(export_findings([final]), out_dir)
    checks = load_json(out_dir / "verification-checks.json")["checks"]
    if kind == "binary_display":
        assert all(c["scope"]["source_identity"] is None for c in checks)
