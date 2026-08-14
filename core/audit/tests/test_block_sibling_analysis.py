"""Tests for core.audit.block_sibling_analysis — block-level sibling asymmetries."""

import pytest
try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(not _HAS_TS, reason="tree-sitter not installed")

import textwrap  # noqa: E402

from core.audit.block_sibling_analysis import (  # noqa: E402
    BlockSiblingFinding,
    detect_block_sibling_asymmetries,
    format_block_sibling_findings_for_prompt,
    _extract_branch_properties,
)


class TestExtractBranchProperties:
    def test_validates_input(self):
        props = _extract_branch_properties("validate(data)")
        assert props["validates_input"] is True

    def test_sanitizes_input(self):
        props = _extract_branch_properties("sanitize(data)")
        assert props["sanitizes_input"] is True

    def test_checks_auth(self):
        props = _extract_branch_properties("check_auth(user)")
        assert props["checks_auth"] is True

    def test_handles_error(self):
        props = _extract_branch_properties("raise ValueError('bad')")
        assert props["handles_error"] is True

    def test_logs_action(self):
        props = _extract_branch_properties("logger.info('did it')")
        assert props["logs_action"] is True

    def test_no_properties(self):
        props = _extract_branch_properties("result = process(x)")
        assert not any(props.values())


class TestDetectPythonIfElif:
    def test_missing_validation_in_one_branch(self):
        src = textwrap.dedent("""\
            def dispatch(action, data):
                if action == "create":
                    validate(data)
                    db.insert(data)
                elif action == "update":
                    validate(data)
                    db.update(data)
                elif action == "delete":
                    db.delete(data)
                elif action == "read":
                    validate(data)
                    return db.query(data)
        """)
        findings = detect_block_sibling_asymmetries({"handler.py": src})
        val_findings = [f for f in findings if f.property_name == "validates_input"]
        assert len(val_findings) >= 1
        assert any(f.branch_label.startswith("action") or "delete" in f.branch_label.lower()
                    for f in val_findings)

    def test_all_branches_agree_no_finding(self):
        src = textwrap.dedent("""\
            def dispatch(action, data):
                if action == "create":
                    validate(data)
                    db.insert(data)
                elif action == "update":
                    validate(data)
                    db.update(data)
                elif action == "delete":
                    validate(data)
                    db.delete(data)
        """)
        findings = detect_block_sibling_asymmetries({"handler.py": src})
        val_findings = [f for f in findings if f.property_name == "validates_input"]
        assert len(val_findings) == 0

    def test_two_branches_not_flagged(self):
        """Need ≥ 3 branches for statistical signal."""
        src = textwrap.dedent("""\
            def dispatch(action, data):
                if action == "create":
                    validate(data)
                    db.insert(data)
                else:
                    db.delete(data)
        """)
        findings = detect_block_sibling_asymmetries({"handler.py": src})
        assert len(findings) == 0


class TestDetectCSwitchCase:
    def test_missing_sanitization_in_c_switch(self):
        src = textwrap.dedent("""\
            void handle(int type, char *data) {
                switch (type) {
                    case TYPE_A:
                        sanitize(data);
                        process_a(data);
                        break;
                    case TYPE_B:
                        sanitize(data);
                        process_b(data);
                        break;
                    case TYPE_C:
                        process_c(data);
                        break;
                    case TYPE_D:
                        sanitize(data);
                        process_d(data);
                        break;
                }
            }
        """)
        findings = detect_block_sibling_asymmetries({"handler.c": src})
        san_findings = [f for f in findings if f.property_name == "sanitizes_input"]
        assert len(san_findings) >= 1

    def test_all_cases_sanitize(self):
        src = textwrap.dedent("""\
            void handle(int type, char *data) {
                switch (type) {
                    case TYPE_A:
                        sanitize(data);
                        process_a(data);
                        break;
                    case TYPE_B:
                        sanitize(data);
                        process_b(data);
                        break;
                    case TYPE_C:
                        sanitize(data);
                        process_c(data);
                        break;
                }
            }
        """)
        findings = detect_block_sibling_asymmetries({"handler.c": src})
        san_findings = [f for f in findings if f.property_name == "sanitizes_input"]
        assert len(san_findings) == 0


class TestDetectGoSwitch:
    def test_missing_error_handling_in_go_switch(self):
        src = textwrap.dedent("""\
            package main

            func process(kind string, data []byte) error {
                switch kind {
                case "alpha":
                    validate(data)
                    return nil
                case "beta":
                    validate(data)
                    return nil
                case "gamma":
                    return nil
                case "delta":
                    validate(data)
                    return nil
                }
                return nil
            }
        """)
        findings = detect_block_sibling_asymmetries({"handler.go": src})
        val_findings = [f for f in findings if f.property_name == "validates_input"]
        assert len(val_findings) >= 1


class TestDetectJsSwitch:
    def test_missing_auth_check_in_js_switch(self):
        src = textwrap.dedent("""\
            function handleAction(action, user, data) {
                switch (action) {
                    case "create":
                        check_auth(user);
                        create(data);
                        break;
                    case "update":
                        check_auth(user);
                        update(data);
                        break;
                    case "delete":
                        delete_record(data);
                        break;
                    case "archive":
                        check_auth(user);
                        archive(data);
                        break;
                }
            }
        """)
        findings = detect_block_sibling_asymmetries({"handler.js": src})
        auth_findings = [f for f in findings if f.property_name == "checks_auth"]
        assert len(auth_findings) >= 1


class TestSeverityEscalation:
    def test_validation_boosted_to_high(self):
        src = textwrap.dedent("""\
            def dispatch(action, data):
                if action == "a":
                    validate(data)
                    process(data)
                elif action == "b":
                    validate(data)
                    process(data)
                elif action == "c":
                    validate(data)
                    process(data)
                elif action == "d":
                    process(data)
        """)
        findings = detect_block_sibling_asymmetries({"handler.py": src})
        val_findings = [f for f in findings if f.property_name == "validates_input"]
        assert len(val_findings) >= 1
        assert any(f.severity == "high" for f in val_findings)


class TestBlockSiblingFinding:
    def test_to_dict(self):
        f = BlockSiblingFinding(
            file="a.py", function="dispatch", line=10,
            branch_label="delete", property_name="validates_input",
            majority_count=3, total_branches=4,
            explanation="3/4 validate, delete does not",
            severity="high", confidence=0.75,
        )
        d = f.to_dict()
        assert d["file"] == "a.py"
        assert d["severity"] == "high"
        assert d["confidence"] == 0.75


class TestFormatForPrompt:
    def test_empty(self):
        assert format_block_sibling_findings_for_prompt([]) == ""

    def test_formatting_includes_check(self):
        findings = [BlockSiblingFinding(
            file="a.py", function="dispatch", line=10,
            branch_label="delete", property_name="validates_input",
            majority_count=3, total_branches=4,
            explanation="3/4 have validates_input=true",
            severity="high", confidence=0.75,
        )]
        text = format_block_sibling_findings_for_prompt(findings)
        assert "Block-level sibling" in text
        assert "CHECK" in text
        assert "validates_input" in text
        assert "dispatch" in text

    def test_non_boost_property_no_check(self):
        findings = [BlockSiblingFinding(
            file="a.py", function="f", line=1,
            branch_label="else", property_name="logs_action",
            majority_count=3, total_branches=4,
            explanation="3/4 log",
            severity="medium", confidence=0.75,
        )]
        text = format_block_sibling_findings_for_prompt(findings)
        assert "CHECK" not in text
