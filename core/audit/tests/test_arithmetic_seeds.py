"""Quality obligations originate in source, independently of model proposals."""

import pytest

from core.audit.context import format_context_for_prompt


def test_quality_glance_keeps_source_arithmetic_obligations():
    ctx = {
        "file": "math.c", "function": "Read", "line_start": 1, "line_end": 1,
        "source": "int Read(int Value, int Count) { return Value << Count; }",
        "review_mode": "quality", "triage_bucket": "glance",
        "injected_hypotheses": [{
            "mechanism": "Potential invalid shift count in `Value << Count`.",
            "confidence": "low", "source": "source_arithmetic",
        }],
    }
    prompt = format_context_for_prompt(ctx)
    assert "Mechanically derived hypotheses" in prompt
    assert "Potential invalid shift count" in prompt
    assert "Investigate each one" in prompt
    assert "potential defect" in prompt
    # No change to the security GLANCE contract.
    ctx["review_mode"] = "security"
    assert "Mechanically derived hypotheses" not in format_context_for_prompt(ctx)


@pytest.mark.parametrize("language,extension", [("c", "c"), ("cpp", "cpp")])
def test_seeded_obligations_reach_native_source_oracles(language, extension):
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.integer_division import check_integer_division
    from core.audit.integer_shift import check_shift_count
    from core.audit.hypothesis_mapping import hypothesis_to_smt_verb

    source = "int Read(int Value, int Count) { return Value / Count; }"
    gap = {"file": f"math.{extension}", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {gap["file"]: source}, mode="quality", integer_abi="lp64") == 2
    seeds = gap["injected_hypotheses"]
    assert {seed["arithmetic_site"]["claim_kind"] for seed in seeds} == {"zero-divisor", "signed-division-overflow"}
    for seed in seeds:
        assert hypothesis_to_smt_verb(seed["mechanism"]) == "check-integer-division"
        result = check_integer_division(source, seed["mechanism"], language=language, integer_abi="lp64")
        assert result["violation"] is True
        assert result["witness_validated"] is True
    shifted = source.replace("Value / Count", "Value << Count")
    gap.pop("injected_hypotheses")
    assert seed_arithmetic_hypotheses([gap], {gap["file"]: shifted}, mode="quality", integer_abi="lp64") == 1
    seed = gap["injected_hypotheses"][0]
    assert hypothesis_to_smt_verb(seed["mechanism"]) == "check-shift-count"
    result = check_shift_count(shifted, seed["mechanism"], language=language, integer_abi="lp64")
    assert result["violation"] is True
    assert result["witness_validated"] is True
    assert "verdict" not in seed and "confirmed" not in seed


def test_seeds_decline_absent_abi_security_dead_and_ambiguous_sites():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses

    source = "int Read(int Value, int Count) { return Value / Count; }"
    for overrides, mode, abi, text in [
        ({}, "security", "lp64", source),
        ({}, "quality", None, source),
        ({"dead": True}, "quality", "lp64", source),
        ({}, "quality", "lp64", source.replace("return Value / Count;", "return Value / Count + Value / Count;")),
        ({}, "quality", "lp64", "int Read(int Value, int Count) { return sizeof(Value / Count); }"),
    ]:
        gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1, **overrides}
        assert seed_arithmetic_hypotheses([gap], {"math.c": text}, mode=mode, integer_abi=abi) == 0
        assert not gap.get("injected_hypotheses")


def test_seed_identity_caps_and_idempotence():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from hashlib import sha256

    source = "// file header\nint Read(int Value, int Count) { return Value >> Count; }\n"
    gap = {"file": "math.c", "name": "Read", "line_start": 2, "line_end": 2}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 1
    first = list(gap["injected_hypotheses"])
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 0
    assert gap["injected_hypotheses"] == first
    site = first[0]["arithmetic_site"]
    assert site["source_sha256"] == sha256(source.splitlines()[1].encode()).hexdigest()
    assert site["file"] == "math.c" and site["line"] == 2
    assert site["integer_abi"]["name"] == "lp64"


def test_global_and_per_gap_caps_leave_other_seed_producers_untouched():
    from core.audit.arithmetic_seeds import (
        MAX_SEEDS_PER_GAP, MAX_SEEDS_PER_RUN, seed_arithmetic_hypotheses,
    )

    source = "int Read(int Value, int Count) { return Value / Count + Value % Count + Value >> Count; }"
    gaps = [{"file": f"math{i}.c", "name": "Read", "line_start": 1, "line_end": 1,
             "injected_hypotheses": [{"mechanism": "Existing unrelated lead", "source": "context_map_sink"}]}
            for i in range(15)]
    sources = {g["file"]: source for g in gaps}
    assert seed_arithmetic_hypotheses(gaps, sources, mode="quality", integer_abi="lp64") == MAX_SEEDS_PER_RUN
    assert all(len(g["injected_hypotheses"]) <= MAX_SEEDS_PER_GAP + 1 for g in gaps)
    assert all(g["injected_hypotheses"][0]["source"] == "context_map_sink" for g in gaps)
    assert seed_arithmetic_hypotheses(gaps, sources, mode="quality", integer_abi="lp64") == 0


def test_source_revision_replaces_stale_lead_without_publishing_a_verdict():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.integer_shift import check_shift_count

    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    old = "int Read(int Value, int Count) { return Value << Count; }"
    assert seed_arithmetic_hypotheses([gap], {"math.c": old}, mode="quality", integer_abi="lp64") == 1
    old_hash = gap["injected_hypotheses"][0]["arithmetic_site"]["source_sha256"]
    safe = "int Read(int Value, int Count) { if (Count >= 0 && Count < 32) return Value << Count; return 0; }"
    assert seed_arithmetic_hypotheses([gap], {"math.c": safe}, mode="quality", integer_abi="lp64") == 1
    assert len(gap["injected_hypotheses"]) == 1
    seed = gap["injected_hypotheses"][0]
    assert seed["arithmetic_site"]["source_sha256"] != old_hash
    assert "verdict" not in seed
    result = check_shift_count(safe, seed["mechanism"], language="c", integer_abi="lp64")
    assert result["violation"] is False


def test_existing_later_gap_seeds_reserve_the_run_budget_before_new_gaps():
    from core.audit.arithmetic_seeds import MAX_SEEDS_PER_RUN, seed_arithmetic_hypotheses

    source = "int Read(int Value, int Count) { return Value / Count + Value % Count; }"
    old = [{"file": f"old{i}.c", "name": "Read", "line_start": 1, "line_end": 1} for i in range(10)]
    sources = {g["file"]: source for g in old}
    assert seed_arithmetic_hypotheses(old, sources, mode="quality", integer_abi="lp64") == MAX_SEEDS_PER_RUN
    new = {"file": "new.c", "name": "Read", "line_start": 1, "line_end": 1}
    sources["new.c"] = source
    assert seed_arithmetic_hypotheses([new, *old], sources, mode="quality", integer_abi="lp64") == 0
    assert not new.get("injected_hypotheses")
    sources["old0.c"] = source.replace("Value % Count", "(Value >> Count)")
    assert seed_arithmetic_hypotheses(old, sources, mode="quality", integer_abi="lp64") == 3
    assert sum(len(g.get("injected_hypotheses", [])) for g in old) <= MAX_SEEDS_PER_RUN


def test_type_range_comparison_seed_reaches_the_source_bound_oracle():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
    from core.audit.integer_comparison import check_integer_comparison

    source = "int Read(unsigned Value){if(Value<0)return 1;return 0;}"
    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 1
    seed = gap["injected_hypotheses"][0]
    assert seed["arithmetic_site"]["claim_kind"] == "constant-comparison-false"
    assert hypothesis_to_smt_verb(seed["mechanism"]) == "check-integer-comparison"
    assert "verdict" not in seed and seed["confidence"] == "low"
    checked = check_integer_comparison(source, seed["mechanism"], language="c", integer_abi="lp64")
    assert checked["matches_claim"] is True
    assert checked["entry_witness_validated"] is True


@pytest.mark.parametrize("spelling,expression,expected", [
    ("int", "Value<0", None),
    ("unsigned char", "Value<128", None),
    ("signed char", "Value<128", True),
    ("unsigned", "Value>=0", True),
    ("unsigned", "Value== -1", None),
    ("int", "Value!=Value", False),
])
def test_only_type_constant_comparisons_create_quality_leads(spelling, expression, expected):
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.integer_comparison import check_integer_comparison

    source = f"int Read({spelling} Value){{if({expression})return 1;return 0;}}"
    gap = {"file": "math.cpp", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.cpp": source}, mode="quality", integer_abi="lp64") == (expected is not None)
    if expected is not None:
        seed = gap["injected_hypotheses"][0]
        checked = check_integer_comparison(source, seed["mechanism"], language="cpp", integer_abi="lp64")
        assert checked["matches_claim"] is True
        assert checked["constant_truth"] is expected


def test_many_ordinary_comparisons_do_not_evict_arithmetic_discovery():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses

    source = "int Read(int Value,int Count){" + "".join(f"if(Value>{i})return 0;" for i in range(25)) + "return Value/Count;}"
    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 2
    assert all(s["arithmetic_site"]["operator"] == "/" for s in gap["injected_hypotheses"])


@pytest.mark.parametrize("expression,verb", [("Value / 0", "division"), ("Value << 32", "shift")])
def test_literal_atoms_are_typed_without_requiring_a_parameter_declaration(expression, verb):
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.integer_division import check_integer_division
    from core.audit.integer_shift import check_shift_count

    source = f"int Read(int Value){{return {expression};}}"
    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") > 0
    seed = next(s for s in gap["injected_hypotheses"] if s["arithmetic_site"]["claim_kind"] == ("zero-divisor" if verb == "division" else "invalid-shift-count"))
    check = check_integer_division if verb == "division" else check_shift_count
    checked = check(source, seed["mechanism"], language="c", integer_abi="lp64")
    assert checked["violation"] is True and checked["witness_validated"] is True


def test_supported_fixed_array_read_is_discovered_without_a_model_proposal():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.array_bounds import check_array_bounds
    from core.audit.hypothesis_mapping import hypothesis_to_smt_verb

    source = "int Read(int Index){int Data[4]={0};if(Index<=4)return Data[Index];return 0;}"
    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 1
    seed = gap["injected_hypotheses"][0]
    site = seed["arithmetic_site"]
    assert site["claim_kind"] == "fixed-array-read"
    assert site["object_extent"] == 4 and site["access_kind"] == "read"
    assert hypothesis_to_smt_verb(seed["mechanism"]) == "check-array-bounds"
    checked = check_array_bounds(source, seed["mechanism"], language="c", integer_abi="lp64")
    assert checked["violation"] is True
    assert checked["witness_index"] < 0 or checked["witness_index"] >= 4
    assert "verdict" not in seed


@pytest.mark.parametrize("source", [
    "int Read(int Index,int *Data){return Data[Index];}",
    "int Read(int Index,int Data[4]){return Data[Index];}",
    "int Read(int Index,int Size){int Data[Size];return Data[Index];}",
    "int Read(int Index){int Data[4]={0};Data[Index]=1;return 0;}",
    "int Read(int Index){int Data[4]={0};return Data[Index]+Data[Index];}",
])
def test_unsupported_array_shapes_never_borrow_a_fixed_read_extent(source):
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses

    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.c": source}, mode="quality", integer_abi="lp64") == 0


def test_cpp_array_lead_still_requires_the_native_oracle_for_a_safe_read():
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.array_bounds import check_array_bounds

    source = "int Read(int Index){int Data[4]={0};if(Index>=0 && Index<4)return Data[Index];return 0;}"
    gap = {"file": "math.cpp", "name": "Read", "line_start": 1, "line_end": 1}
    assert seed_arithmetic_hypotheses([gap], {"math.cpp": source}, mode="quality", integer_abi="lp64") == 1
    seed = gap["injected_hypotheses"][0]
    assert seed["arithmetic_site"]["object_extent"] == 4
    assert "verdict" not in seed
    checked = check_array_bounds(source, seed["mechanism"], language="cpp", integer_abi="lp64")
    assert checked["violation"] is False
