"""Tests for ``core.dataflow.path_annotator``."""

from __future__ import annotations

import pytest

from core.dataflow import Finding, Step
from core.dataflow.path_annotator import annotate_finding
from core.dataflow.sanitizer_evidence import (
    PROVENANCE_LLM,
    SEMANTICS_AUTH_CHECK,
    SEMANTICS_SQL_ESCAPE,
    CandidateValidator,
)


def _candidate(
    name: str,
    qualified_name: str,
    semantics_tag: str = SEMANTICS_SQL_ESCAPE,
) -> CandidateValidator:
    return CandidateValidator(
        name=name,
        qualified_name=qualified_name,
        semantics_tag=semantics_tag,
        semantics_text="test validator",
        confidence=0.9,
        source_file="x.py",
        source_line=1,
        extraction_provenance=PROVENANCE_LLM,
    )


def _step(file_path: str, snippet: str, line: int = 1) -> Step:
    return Step(
        file_path=file_path,
        line=line,
        column=0,
        snippet=snippet,
        label="step",
    )


def _finding(source: Step, sink: Step, intermediate=(), file_path: str = None) -> Finding:
    return Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="py/x",
        message="m",
        source=source,
        sink=sink,
        intermediate_steps=intermediate,
    )


# ---------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------


def test_annotate_finding_emits_one_per_step_in_path_order():
    f = _finding(
        source=_step("a.py", "x = req.GET['q']"),
        sink=_step("a.py", "execute(x)"),
        intermediate=(_step("a.py", "y = sanitize(x)"),),
    )
    annotations = annotate_finding(f, [])
    assert len(annotations) == 3
    assert tuple(a.step_index for a in annotations) == (0, 1, 2)


def test_annotate_finding_with_no_intermediate_steps():
    f = _finding(
        source=_step("a.py", "x = req.GET['q']"),
        sink=_step("a.py", "execute(x)"),
    )
    annotations = annotate_finding(f, [])
    assert len(annotations) == 2
    assert annotations[0].step_index == 0
    assert annotations[1].step_index == 1


# ---------------------------------------------------------------------
# Bare-name candidate match
# ---------------------------------------------------------------------


def test_bare_name_candidate_matches_bare_call():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = sanitize(x)"),
    )
    candidates = [_candidate(name="sanitize", qualified_name="proj.sanitize")]
    annotations = annotate_finding(f, candidates)
    assert "proj.sanitize" in annotations[1].on_path_validators


def test_bare_name_candidate_matches_attribute_call_with_same_tail():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = utils.sanitize(x)"),
    )
    candidates = [_candidate(name="sanitize", qualified_name="proj.sanitize")]
    annotations = annotate_finding(f, candidates)
    # Tail-name match: utils.sanitize(...) → matches candidate "sanitize"
    assert "proj.sanitize" in annotations[1].on_path_validators


def test_qualified_name_candidate_matches_full_chain():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = db.helpers.escape_sql(x)"),
    )
    candidates = [
        _candidate(name="escape_sql", qualified_name="db.helpers.escape_sql"),
    ]
    annotations = annotate_finding(f, candidates)
    assert "db.helpers.escape_sql" in annotations[1].on_path_validators


# ---------------------------------------------------------------------
# inlined_helpers (calls not matched against any candidate)
# ---------------------------------------------------------------------


def test_unmatched_calls_appear_in_inlined_helpers():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = transform(x)"),
    )
    annotations = annotate_finding(f, [])
    assert "transform" in annotations[1].inlined_helpers


def test_matched_calls_do_not_appear_in_inlined_helpers():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = sanitize(x)"),
    )
    candidates = [_candidate(name="sanitize", qualified_name="proj.sanitize")]
    annotations = annotate_finding(f, candidates)
    assert annotations[1].inlined_helpers == ()


def test_attribute_chain_helpers_recorded_with_dotted_form():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = utils.cleanup(x)"),
    )
    annotations = annotate_finding(f, [])
    assert "utils.cleanup" in annotations[1].inlined_helpers


# ---------------------------------------------------------------------
# variables_referenced
# ---------------------------------------------------------------------


def test_variables_referenced_excludes_callee_tokens():
    f = _finding(
        source=_step("a.py", "y = sanitize(user_input)"),
        sink=_step("a.py", "execute(y)"),
    )
    annotations = annotate_finding(f, [])
    # `sanitize` and `execute` are callees and should not appear as variables.
    assert "user_input" in annotations[0].variables_referenced
    assert "sanitize" not in annotations[0].variables_referenced
    assert "execute" not in annotations[1].variables_referenced
    assert "y" in annotations[1].variables_referenced


def test_variables_referenced_strips_common_noise_tokens():
    f = _finding(
        source=_step("a.py", "if user_input is not None: return user_input"),
        sink=_step("a.py", "x = 1"),
    )
    annotations = annotate_finding(f, [])
    assert "if" not in annotations[0].variables_referenced
    assert "is" not in annotations[0].variables_referenced
    assert "not" not in annotations[0].variables_referenced
    assert "return" not in annotations[0].variables_referenced
    assert "None" not in annotations[0].variables_referenced
    assert "user_input" in annotations[0].variables_referenced


# ---------------------------------------------------------------------
# Cross-language smoke
# ---------------------------------------------------------------------


def test_javascript_call_extraction(pytestconfig):
    pytest.importorskip("tree_sitter_javascript")
    f = _finding(
        source=_step("a.js", "const q = req.query.q"),
        sink=_step("a.js", "exec(`ping ${q}`)"),
    )
    annotations = annotate_finding(f, [_candidate(name="exec", qualified_name="exec")])
    assert "exec" in annotations[1].on_path_validators


def test_java_call_extraction():
    """Java tree-sitter records each call site separately; chained
    expressions like ``Runtime.getRuntime().exec(q)`` produce two
    chains (``Runtime.getRuntime`` and ``exec``). The annotator
    matches on the suffix, so a candidate named ``exec`` matches the
    inner call. This is brittle for chained-method patterns —
    documented limitation."""
    pytest.importorskip("tree_sitter_java")
    f = _finding(
        source=_step("A.java", "String q = request.getParameter(\"q\");"),
        sink=_step("A.java", "Statement.execute(q);"),
    )
    annotations = annotate_finding(
        f,
        [_candidate(name="execute", qualified_name="java.sql.Statement.execute")],
    )
    assert "java.sql.Statement.execute" in annotations[1].on_path_validators


def test_unsupported_language_yields_empty_call_data():
    """C/C++ has no extractor in core.inventory.call_graph yet —
    annotations should degrade gracefully, not raise."""
    f = _finding(
        source=_step("a.c", "char *q = argv[1];"),
        sink=_step("a.c", "system(q);"),
    )
    annotations = annotate_finding(f, [])
    assert annotations[1].on_path_validators == ()
    assert annotations[1].inlined_helpers == ()


def test_unknown_extension_yields_empty_call_data():
    f = _finding(
        source=_step("a.weird_ext", "x = something()"),
        sink=_step("a.weird_ext", "y = other()"),
    )
    annotations = annotate_finding(f, [])
    assert annotations[0].on_path_validators == ()
    assert annotations[1].on_path_validators == ()


# ---------------------------------------------------------------------
# Robustness on malformed snippets
# ---------------------------------------------------------------------


def test_malformed_python_snippet_does_not_raise():
    f = _finding(
        source=_step("a.py", "this is not valid python !@#$%"),
        sink=_step("a.py", "y = foo()"),
    )
    annotations = annotate_finding(f, [])
    # Source step's call data is empty (parse failed), but we still
    # annotated it and the second step parsed fine.
    assert annotations[0].on_path_validators == ()
    assert "foo" in annotations[1].inlined_helpers


def test_partial_python_snippet_with_call_still_extracts():
    f = _finding(
        source=_step("a.py", "result = compute(x, y)"),
        sink=_step("a.py", "store(result)"),
    )
    annotations = annotate_finding(f, [])
    assert "compute" in annotations[0].inlined_helpers
    assert "store" in annotations[1].inlined_helpers


# ---------------------------------------------------------------------
# Pool de-duplication and ordering
# ---------------------------------------------------------------------


def test_duplicate_candidate_match_only_listed_once():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = sanitize(sanitize(x))"),
    )
    candidates = [_candidate(name="sanitize", qualified_name="proj.sanitize")]
    annotations = annotate_finding(f, candidates)
    assert annotations[1].on_path_validators == ("proj.sanitize",)


def test_multiple_distinct_candidates_each_recorded():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "if check_owner(x): escape_sql(x)"),
    )
    candidates = [
        _candidate(
            name="check_owner",
            qualified_name="auth.check_owner",
            semantics_tag=SEMANTICS_AUTH_CHECK,
        ),
        _candidate(
            name="escape_sql",
            qualified_name="db.escape_sql",
            semantics_tag=SEMANTICS_SQL_ESCAPE,
        ),
    ]
    annotations = annotate_finding(f, candidates)
    assert set(annotations[1].on_path_validators) == {
        "auth.check_owner",
        "db.escape_sql",
    }


def test_no_candidate_match_when_name_differs():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "y = sanitize_html(x)"),
    )
    candidates = [
        _candidate(
            name="sanitize_sql",
            qualified_name="db.sanitize_sql",
            semantics_tag=SEMANTICS_SQL_ESCAPE,
        ),
    ]
    annotations = annotate_finding(f, candidates)
    assert annotations[1].on_path_validators == ()
    assert "sanitize_html" in annotations[1].inlined_helpers


# ---------------------------------------------------------------------
# StepAnnotation invariants
# ---------------------------------------------------------------------


def test_annotation_lists_are_sorted_for_determinism():
    """Same input → same annotation; downstream caches need stable
    output ordering."""
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "if z(x): a(x); b(x)"),
    )
    a1 = annotate_finding(f, [])
    a2 = annotate_finding(f, [])
    assert a1 == a2
    # Sorted output
    helpers = a1[1].inlined_helpers
    assert list(helpers) == sorted(helpers)


def test_empty_candidates_still_produces_annotations():
    f = _finding(
        source=_step("a.py", "x = read()"),
        sink=_step("a.py", "execute(x)"),
    )
    annotations = annotate_finding(f, [])
    assert len(annotations) == 2
    assert annotations[0].on_path_validators == ()
    assert annotations[1].on_path_validators == ()
