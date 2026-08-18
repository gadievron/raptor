"""Tests for core.audit.sibling_analysis — sibling asymmetry detection."""

from __future__ import annotations

from core.audit.sibling_analysis import (
    Asymmetry,
    SiblingGroup,
    SiblingPath,
    SiblingType,
    check_operation_order,
    classify_sanitizer_strength,
    find_asymmetries,
    format_asymmetry_finding,
    format_asymmetry_report,
    format_for_prompt,
    identify_error_branches,
    identify_peer_groups,
)


class TestFindAsymmetries:
    def test_detects_basic_asymmetry(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"sanitizer_used": "strong"}),
                SiblingPath("b", "f.py", "b", properties={"sanitizer_used": "strong"}),
                SiblingPath("c", "f.py", "c", properties={"sanitizer_used": "weak"}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].majority_value == "strong"
        assert asymmetries[0].minority_value == "weak"
        assert asymmetries[0].minority_siblings == ["c"]

    def test_no_asymmetry_when_all_agree(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"auth": True}),
                SiblingPath("b", "f.py", "b", properties={"auth": True}),
            ],
        )
        assert find_asymmetries(group) == []

    def test_single_sibling_returns_empty(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"auth": True}),
            ],
        )
        assert find_asymmetries(group) == []

    def test_multiple_properties(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={
                    "sanitizer_used": "strong",
                    "validation_present": True,
                }),
                SiblingPath("b", "f.py", "b", properties={
                    "sanitizer_used": "strong",
                    "validation_present": True,
                }),
                SiblingPath("c", "f.py", "c", properties={
                    "sanitizer_used": "weak",
                    "validation_present": False,
                }),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 2
        props = {a.property_name for a in asymmetries}
        assert "sanitizer_used" in props
        assert "validation_present" in props

    def test_skips_equal_splits(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"style": "X"}),
                SiblingPath("b", "f.py", "b", properties={"style": "Y"}),
            ],
        )
        assert find_asymmetries(group) == []

    def test_confidence_proportional_to_majority(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"x": "safe"}),
                SiblingPath("b", "f.py", "b", properties={"x": "safe"}),
                SiblingPath("c", "f.py", "c", properties={"x": "safe"}),
                SiblingPath("d", "f.py", "d", properties={"x": "unsafe"}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].confidence == 0.75

    def test_property_missing_from_some_siblings(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"x": "safe"}),
                SiblingPath("b", "f.py", "b", properties={"x": "safe"}),
                SiblingPath("c", "f.py", "c", properties={}),
            ],
        )
        assert find_asymmetries(group) == []

    def test_bool_normalization(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"env_handling": True}),
                SiblingPath("b", "f.py", "b", properties={"env_handling": True}),
                SiblingPath("c", "f.py", "c", properties={"env_handling": False}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].majority_value == "true"
        assert asymmetries[0].minority_value == "false"

    def test_list_normalization(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"ops": ["strip", "escape"]}),
                SiblingPath("b", "f.py", "b", properties={"ops": ["escape", "strip"]}),
                SiblingPath("c", "f.py", "c", properties={"ops": ["strip"]}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].minority_siblings == ["c"]


class TestSeverityEscalation:
    def test_error_branch_escalates_severity(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.ERROR_VS_NORMAL,
            description="test",
            siblings=[
                SiblingPath("normal", "f.py", "f", properties={"guard_present": True}),
                SiblingPath("except", "f.py", "f", is_error_path=True,
                            properties={"guard_present": False}),
                SiblingPath("normal2", "f.py", "f", properties={"guard_present": True}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].severity == "high"

    def test_high_confidence_escalates(self):
        siblings = [
            SiblingPath(f"s{i}", "f.py", f"f{i}", properties={"validation_present": True})
            for i in range(9)
        ]
        siblings.append(
            SiblingPath("odd", "f.py", "odd", properties={"validation_present": False})
        )
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=siblings,
        )
        asymmetries = find_asymmetries(group)
        assert len(asymmetries) == 1
        assert asymmetries[0].confidence == 0.9
        assert asymmetries[0].severity == "high"

    def test_return_on_error_always_high(self):
        group = SiblingGroup(
            group_id="test",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="test",
            siblings=[
                SiblingPath("a", "f.py", "a", properties={"return_on_error": True}),
                SiblingPath("b", "f.py", "b", properties={"return_on_error": True}),
                SiblingPath("c", "f.py", "c", properties={"return_on_error": False}),
            ],
        )
        asymmetries = find_asymmetries(group)
        assert asymmetries[0].severity == "high"


class TestIdentifyPeerGroups:
    def test_groups_by_verb_prefix(self):
        functions = [
            {"name": "render_html", "file": "views.py", "line": 10},
            {"name": "render_json", "file": "views.py", "line": 30},
            {"name": "render_xml", "file": "views.py", "line": 50},
            {"name": "unrelated_func", "file": "other.py", "line": 1},
        ]
        groups = identify_peer_groups(functions)
        assert len(groups) == 1
        assert groups[0].sibling_type == SiblingType.PEER_FUNCTIONS
        assert len(groups[0].siblings) == 3

    def test_multiple_verb_groups(self):
        functions = [
            {"name": "parse_json", "file": "io.py"},
            {"name": "parse_xml", "file": "io.py"},
            {"name": "validate_email", "file": "v.py"},
            {"name": "validate_phone", "file": "v.py"},
        ]
        groups = identify_peer_groups(functions)
        assert len(groups) == 2

    def test_single_function_no_group(self):
        functions = [
            {"name": "render_html", "file": "views.py"},
            {"name": "something_else", "file": "other.py"},
        ]
        groups = identify_peer_groups(functions)
        assert len(groups) == 0

    def test_handle_group(self):
        functions = [
            {"name": "handle_login", "file": "auth.py"},
            {"name": "handle_logout", "file": "auth.py"},
            {"name": "handle_register", "file": "auth.py"},
        ]
        groups = identify_peer_groups(functions)
        assert len(groups) == 1
        assert groups[0].group_id == "handle_group"

    def test_sanitize_group(self):
        functions = [
            {"name": "sanitize_html", "file": "s.py"},
            {"name": "sanitize_url", "file": "s.py"},
        ]
        groups = identify_peer_groups(functions)
        assert len(groups) == 1


class TestIdentifyErrorBranches:
    def test_creates_group_with_error_branch(self):
        branches = [
            {"label": "normal_path", "properties": {"env_handling": True}},
            {"label": "except_handler", "properties": {"env_handling": False}},
        ]
        group = identify_error_branches("run_cmd", "exec.py", branches)
        assert group is not None
        assert group.sibling_type == SiblingType.ERROR_VS_NORMAL
        assert len(group.siblings) == 2
        assert group.siblings[1].is_error_path

    def test_returns_none_without_error_branch(self):
        branches = [
            {"label": "if_true_branch", "properties": {}},
            {"label": "if_false_branch", "properties": {}},
        ]
        group = identify_error_branches("f", "f.py", branches)
        assert group is None

    def test_returns_none_with_single_branch(self):
        assert identify_error_branches("f", "f.py", [{"label": "only"}]) is None

    def test_recognizes_catch_label(self):
        branches = [
            {"label": "try_body"},
            {"label": "catch_block", "properties": {"cleanup": True}},
        ]
        group = identify_error_branches("process", "p.py", branches)
        assert group is not None
        assert any(s.is_error_path for s in group.siblings)


class TestClassifySanitizerStrength:
    def test_strong(self):
        assert classify_sanitizer_strength("escape_html") == "strong"
        assert classify_sanitizer_strength("htmlspecialchars") == "strong"
        assert classify_sanitizer_strength("bleach.clean") == "strong"

    def test_weak(self):
        assert classify_sanitizer_strength("strip_tags") == "weak"
        assert classify_sanitizer_strength("basic_escape") == "weak"
        assert classify_sanitizer_strength("replace") == "weak"

    def test_unknown(self):
        assert classify_sanitizer_strength("custom_filter") == "unknown"

    def test_case_insensitive(self):
        assert classify_sanitizer_strength("ESCAPE_HTML") == "strong"
        assert classify_sanitizer_strength("Strip_Tags") == "weak"


class TestCheckOperationOrder:
    def test_detects_swap(self):
        ops_a = ["strip_html", "normalize_unicode"]
        ops_b = ["normalize_unicode", "strip_html"]
        result = check_operation_order(ops_a, ops_b)
        assert result is not None
        assert "swapped" in result

    def test_same_order_ok(self):
        ops_a = ["strip_html", "normalize_unicode"]
        ops_b = ["strip_html", "normalize_unicode"]
        assert check_operation_order(ops_a, ops_b) is None

    def test_single_op_ok(self):
        assert check_operation_order(["a"], ["a"]) is None

    def test_no_common_ops(self):
        assert check_operation_order(["a", "b"], ["c", "d"]) is None

    def test_empty_ops(self):
        assert check_operation_order([], ["a"]) is None
        assert check_operation_order(["a"], []) is None


class TestFormatting:
    def test_format_asymmetry_finding(self):
        a = Asymmetry(
            group_id="test",
            property_name="sanitizer_used",
            majority_value="strong",
            minority_value="weak",
            majority_count=3,
            minority_count=1,
            minority_siblings=["render_xml"],
            confidence=0.75,
            severity="medium",
            explanation="3/4 siblings have sanitizer_used=strong; render_xml has weak",
        )
        result = format_asymmetry_finding(a)
        assert "sanitizer_used" in result
        assert "75%" in result
        assert "strong convention" in result

    def test_format_asymmetry_report_empty(self):
        result = format_asymmetry_report([])
        assert "no asymmetries" in result

    def test_format_asymmetry_report_with_findings(self):
        a = Asymmetry(
            group_id="test",
            property_name="auth",
            majority_value="present",
            minority_value="absent",
            majority_count=5,
            minority_count=1,
            minority_siblings=["handler_x"],
            confidence=0.83,
            severity="high",
            explanation="5/6 siblings have auth=present",
        )
        result = format_asymmetry_report([a])
        assert "1 asymmetries" in result
        assert "1 high" in result

    def test_format_for_prompt_empty(self):
        assert format_for_prompt([], []) == ""

    def test_format_for_prompt_low_confidence_excluded(self):
        a = Asymmetry(
            group_id="test",
            property_name="x",
            majority_value="a",
            minority_value="b",
            majority_count=2,
            minority_count=1,
            minority_siblings=["c"],
            confidence=0.5,
            severity="low",
            explanation="test",
        )
        assert format_for_prompt([], [a]) == ""

    def test_format_for_prompt_high_confidence_included(self):
        a = Asymmetry(
            group_id="test",
            property_name="x",
            majority_value="a",
            minority_value="b",
            majority_count=3,
            minority_count=1,
            minority_siblings=["c"],
            confidence=0.75,
            severity="high",
            explanation="test explanation",
        )
        result = format_for_prompt([], [a])
        assert "SIBLING ASYMMETRIES" in result
        assert "test explanation" in result


class TestSiblingPathSerialization:
    def test_to_dict(self):
        sp = SiblingPath(
            label="render_html",
            file="views.py",
            function="render_html",
            line=42,
            properties={"sanitizer": "strong"},
        )
        d = sp.to_dict()
        assert d["label"] == "render_html"
        assert d["properties"]["sanitizer"] == "strong"
        assert d["line"] == 42

    def test_group_to_dict(self):
        group = SiblingGroup(
            group_id="render_group",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description="Renderers",
            siblings=[
                SiblingPath("a", "f.py", "a"),
                SiblingPath("b", "f.py", "b"),
            ],
        )
        d = group.to_dict()
        assert d["group_id"] == "render_group"
        assert d["sibling_type"] == "peer_functions"
        assert len(d["siblings"]) == 2

    def test_asymmetry_to_dict(self):
        a = Asymmetry(
            group_id="test",
            property_name="auth",
            majority_value="present",
            minority_value="absent",
            majority_count=3,
            minority_count=1,
            minority_siblings=["x"],
            confidence=0.75,
            severity="high",
            explanation="test",
        )
        d = a.to_dict()
        assert d["property"] == "auth"
        assert d["confidence"] == 0.75
        assert d["severity"] == "high"

    def test_is_high_confidence(self):
        assert Asymmetry(
            group_id="", property_name="", majority_value="",
            minority_value="", majority_count=0, minority_count=0,
            minority_siblings=[], confidence=0.75,
        ).is_high_confidence

        assert not Asymmetry(
            group_id="", property_name="", majority_value="",
            minority_value="", majority_count=0, minority_count=0,
            minority_siblings=[], confidence=0.5,
        ).is_high_confidence


class TestSemanticFindingsToMechanical:
    def test_converts_to_detector_shape(self):
        from core.audit.sibling_analysis import semantic_findings_to_mechanical

        findings = [{
            "file": "handlers.py",
            "function": "handle_delta",
            "siblings": ["handle_alpha", "handle_beta"],
            "inconsistency": "2/3 siblings perform auth checks; handle_delta does not",
            "confidence": 0.67,
            "cwe": "CWE-862",
        }]
        out = semantic_findings_to_mechanical(findings)
        assert len(out) == 1
        mf = out[0]
        assert mf["file"] == "handlers.py"
        assert mf["function"] == "handle_delta"
        assert mf["detector"] == "semantic_consistency"
        assert mf["line"] == 0
        assert "CWE-862" in mf["description"]
        assert "confidence 0.67" in mf["description"]

    def test_skips_malformed_entries(self):
        from core.audit.sibling_analysis import semantic_findings_to_mechanical

        out = semantic_findings_to_mechanical([
            "not-a-dict",
            {"file": "a.py", "inconsistency": "no function key"},
        ])
        assert out == []
