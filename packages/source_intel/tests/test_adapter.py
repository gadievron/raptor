"""Tests for ``packages.source_intel.adapter.SourceIntelValidator``."""

from __future__ import annotations

from unittest.mock import patch


from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _rule_id_is_wur_relevant,
)
from packages.source_intel.analyze import SourceIntelResult, WurEvidence


# =====================================================================
# Rule-id classifier
# =====================================================================


def test_wur_relevant_rule_ids():
    assert _rule_id_is_wur_relevant("cpp/null-dereference")
    assert _rule_id_is_wur_relevant("cpp/uncontrolled-allocation-size")
    assert _rule_id_is_wur_relevant("cpp/unbounded-write")
    assert _rule_id_is_wur_relevant("c/null-dereference")


def test_wur_irrelevant_rule_ids():
    assert not _rule_id_is_wur_relevant("py/sql-injection")
    assert not _rule_id_is_wur_relevant("java/path-traversal")
    assert not _rule_id_is_wur_relevant("cpp/use-after-free")  # not WUR-class


# =====================================================================
# Verdict behaviour
# =====================================================================


def _finding(file_path: str, rule_id: str, snippet: str):
    return Finding(
        finding_id="test_finding",
        producer="codeql",
        rule_id=rule_id,
        message="test",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet=snippet, label="source"),
        sink=Step(file_path=file_path, line=2, column=1,
                  snippet="", label="sink"),
        intermediate_steps=(),
        raw={},
    )


def test_unresolvable_file_path_returns_uncertain(tmp_path):
    """Out-of-tree fixture not cloned yet → no target → UNCERTAIN.
    The corpus runner relies on this graceful handling for the 5 TPs
    that reference `out/dataflow-corpus-fixtures/` paths."""
    v = SourceIntelValidator(repo_root=tmp_path)
    finding = _finding(
        "out/dataflow-corpus-fixtures/missing/file.c",
        "cpp/null-dereference",
        "int x;",
    )
    assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_skipped_analyze_returns_uncertain(tmp_path):
    """When analyze skips (e.g. no spatch), validator MUST return
    UNCERTAIN — never collapse to EXPLOITABLE / NOT_EXPLOITABLE.
    UNCERTAIN keeps precision/recall metrics clean."""
    (tmp_path / "test.c").write_text("int foo(void){return 0;}\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference", "alloc_thing()")

    skipped = SourceIntelResult(skipped_reason="spatch_not_available")
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=skipped,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_non_wur_relevant_rule_returns_uncertain(tmp_path):
    """A use-after-free finding is not in the WUR-relevant set; even
    if analyze finds WUR evidence, we don't claim it supports the
    finding — UNCERTAIN.
    Phase 2 axis 1 only verdicts on the WUR-relevant CWE classes."""
    (tmp_path / "test.c").write_text("int foo(void){return 0;}\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/use-after-free", "free(p); p->x;")

    result_with_wur = SourceIntelResult(
        attributes=(WurEvidence(
            function_name="alloc_thing",
            location=("test.c", 1),
            match_source="literal",
            raw_match="__attribute__((warn_unused_result))",
        ),)
    )
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result_with_wur,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_wur_function_in_snippet_returns_exploitable(tmp_path):
    """When the finding's snippet mentions a function we have WUR
    evidence for AND the rule_id is WUR-relevant, return EXPLOITABLE.
    This is the only path that produces a confident verdict in Phase 2."""
    (tmp_path / "test.c").write_text("int alloc_thing(void){return 0;}\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference",
                       "p = alloc_thing();")

    result_with_wur = SourceIntelResult(
        attributes=(WurEvidence(
            function_name="alloc_thing",
            location=("test.c", 1),
            match_source="literal",
            raw_match="__attribute__((warn_unused_result))",
        ),)
    )
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result_with_wur,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_wur_function_not_mentioned_in_snippet_returns_uncertain(tmp_path):
    """WUR evidence exists but the finding's snippet doesn't reference
    that function — can't claim the evidence backs THIS finding."""
    (tmp_path / "test.c").write_text("int other(void){return 0;}\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference",
                       "p = unrelated_function();")

    result_with_wur = SourceIntelResult(
        attributes=(WurEvidence(
            function_name="alloc_thing",
            location=("test.c", 1),
            match_source="literal",
            raw_match="__attribute__((warn_unused_result))",
        ),)
    )
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result_with_wur,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_analyze_exception_returns_uncertain(tmp_path):
    """An unexpected exception in analyze MUST NOT crash the corpus
    runner — collapse to UNCERTAIN."""
    (tmp_path / "test.c").write_text("int foo(void){return 0;}\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference", "alloc()")

    with patch(
        "packages.source_intel.adapter.analyze",
        side_effect=RuntimeError("simulated failure"),
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


# =====================================================================
# Caching behaviour
# =====================================================================


def test_repeated_findings_in_same_target_hit_cache(tmp_path):
    """Two findings citing files in the same target directory should
    only trigger one analyze call — the second hits the cache."""
    (tmp_path / "a.c").write_text("int foo(void){return 0;}\n")
    (tmp_path / "b.c").write_text("int bar(void){return 0;}\n")
    (tmp_path / "Makefile").write_text("all:\n\techo\n")

    fa = _finding(str(tmp_path / "a.c"),
                  "cpp/null-dereference", "alloc()")
    fb = _finding(str(tmp_path / "b.c"),
                  "cpp/null-dereference", "alloc()")

    call_count = 0

    def counted_analyze(t):
        nonlocal call_count
        call_count += 1
        return SourceIntelResult(target=str(t))

    with patch(
        "packages.source_intel.adapter.analyze",
        side_effect=counted_analyze,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        v.validate(fa)
        v.validate(fb)

    assert call_count == 1, (
        "expected the second finding to hit the cache; "
        f"got {call_count} analyze calls"
    )


# =====================================================================
# Validator protocol compliance
# =====================================================================


def test_zero_arg_construction_works():
    """The --validator import spec instantiates with zero args."""
    v = SourceIntelValidator()
    assert v is not None


def test_validator_satisfies_runtime_protocol():
    """The Validator protocol is runtime-checkable."""
    from core.dataflow.validator import Validator
    v = SourceIntelValidator()
    assert isinstance(v, Validator)


# =====================================================================
# Nonnull kind dispatch (Phase 3a)
# =====================================================================


def test_nonnull_function_in_snippet_returns_exploitable_for_null_deref(tmp_path):
    """A nonnull-annotated function referenced in a CWE-476 finding's
    snippet should yield EXPLOITABLE — author marked the param
    non-nullable; passing NULL is an exploit precondition."""
    from packages.source_intel.analyze import KIND_NONNULL, AttributeEvidence

    (tmp_path / "test.c").write_text("int v(int *p) { return *p; }\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference", "v(NULL)")

    result = SourceIntelResult(attributes=(AttributeEvidence(
        kind=KIND_NONNULL,
        function_name="v",
        location=("test.c", 1),
        match_source="literal",
        raw_match="__attribute__((nonnull))",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_alloc_size_function_in_snippet_returns_exploitable_for_unbounded_write(tmp_path):
    """alloc_size on a buffer-returning function whose result is then
    written to without bounds-checking — CWE-120 finding gets verdict
    support from the annotation (annotation tells the LLM how big the
    buffer ACTUALLY is)."""
    from packages.source_intel.analyze import KIND_ALLOC_SIZE, AttributeEvidence

    (tmp_path / "test.c").write_text("void *alloc_buf(int sz);\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/unbounded-write",
                       "p = alloc_buf(8); memcpy(p, src, 100);")

    result = SourceIntelResult(attributes=(AttributeEvidence(
        kind=KIND_ALLOC_SIZE,
        function_name="alloc_buf",
        location=("test.c", 1),
        match_source="literal",
        raw_match="__attribute__((alloc_size(1)))",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_returns_nonnull_function_in_snippet_returns_exploitable_for_null_deref(tmp_path):
    """returns_nonnull on a function whose result is dereferenced
    without a null check — annotation tells the LLM the caller trusted
    the contract; if the function CAN return NULL erroneously, the
    finding is exploitable."""
    from packages.source_intel.analyze import (
        KIND_RETURNS_NONNULL, AttributeEvidence,
    )

    (tmp_path / "test.c").write_text("void *must_succeed(void);\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference",
                       "p = must_succeed(); p->field = 1;")

    result = SourceIntelResult(attributes=(AttributeEvidence(
        kind=KIND_RETURNS_NONNULL,
        function_name="must_succeed",
        location=("test.c", 1),
        match_source="literal",
        raw_match="__attribute__((returns_nonnull))",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_alloc_size_evidence_irrelevant_for_null_deref(tmp_path):
    """alloc_size relevance is unbounded-write / uncontrolled-* —
    NOT null-deref. Even with a matching function, CWE-476 stays
    UNCERTAIN."""
    from packages.source_intel.analyze import KIND_ALLOC_SIZE, AttributeEvidence

    (tmp_path / "test.c").write_text("void *alloc_buf(int sz);\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/null-dereference",
                       "p = alloc_buf(8); p->field = 1;")

    result = SourceIntelResult(attributes=(AttributeEvidence(
        kind=KIND_ALLOC_SIZE,
        function_name="alloc_buf",
        location=("test.c", 1),
        match_source="literal",
        raw_match="__attribute__((alloc_size(1)))",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_nonnull_evidence_irrelevant_for_use_after_free(tmp_path):
    """Nonnull does NOT speak to UAF — even with a perfect function
    match, the relevance check returns UNCERTAIN for CWE-416."""
    from packages.source_intel.analyze import KIND_NONNULL, AttributeEvidence

    (tmp_path / "test.c").write_text("int v(int *p) { return *p; }\n")
    finding = _finding(str(tmp_path / "test.c"),
                       "cpp/use-after-free", "v(p)")

    result = SourceIntelResult(attributes=(AttributeEvidence(
        kind=KIND_NONNULL,
        function_name="v",
        location=("test.c", 1),
        match_source="literal",
        raw_match="__attribute__((nonnull))",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        validator = SourceIntelValidator(repo_root=tmp_path)
        assert validator.validate(finding) == ValidatorVerdict.UNCERTAIN
