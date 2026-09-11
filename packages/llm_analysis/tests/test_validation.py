"""Tests for LLM response semantic validation."""

from packages.llm_analysis.validation import check_self_contradiction


class TestCheckSelfConsistency:

    def test_flags_fp_reasoning_with_tp_verdict(self):
        results = {"F1": {
            "is_true_positive": True, "is_exploitable": False,
            "reasoning": "This is a false positive because the input is sanitized."
        }}
        flagged = check_self_contradiction(results)
        assert flagged == 1
        assert results["F1"]["self_contradictory"] is True
        assert "false positive" in results["F1"]["contradictions"][0]

    def test_flags_safe_reasoning_with_exploitable_verdict(self):
        results = {"F1": {
            "is_true_positive": True, "is_exploitable": True,
            "reasoning": "The code is safe and has no security impact."
        }}
        flagged = check_self_contradiction(results)
        assert flagged == 1
        assert "safe" in results["F1"]["contradictions"][0] or "no security impact" in results["F1"]["contradictions"][0]

    def test_no_flag_when_consistent(self):
        results = {"F1": {
            "is_true_positive": True, "is_exploitable": True,
            "reasoning": "The buffer overflow is exploitable via argv[1]."
        }}
        flagged = check_self_contradiction(results)
        assert flagged == 0
        assert "self_contradictory" not in results["F1"]

    def test_skips_errors(self):
        results = {"F1": {"error": "timeout", "reasoning": "false positive"}}
        flagged = check_self_contradiction(results)
        assert flagged == 0

    def test_skips_empty_reasoning(self):
        results = {"F1": {"is_true_positive": True, "is_exploitable": True, "reasoning": ""}}
        flagged = check_self_contradiction(results)
        assert flagged == 0

    def test_multiple_findings(self):
        results = {
            "F1": {"is_true_positive": True, "is_exploitable": True,
                   "reasoning": "This is not exploitable in practice."},
            "F2": {"is_true_positive": True, "is_exploitable": True,
                   "reasoning": "Trivial buffer overflow."},
            "F3": {"is_true_positive": False,
                   "reasoning": "Not a real vulnerability."},
        }
        flagged = check_self_contradiction(results)
        assert flagged == 1  # Only F1 (exploitable but says "not exploitable")
        assert results["F1"]["self_contradictory"] is True
        assert "self_contradictory" not in results["F2"]
        assert "self_contradictory" not in results["F3"]  # FP verdict matches FP reasoning


class TestNonStringShapes:
    """generate_structured's descriptive schema is not enforced —
    ruling can come back as a dict ({'status': ...}) and reasoning as
    a list; the check must adjudicate them, not crash the retry
    stage."""

    def test_dict_ruling_status_still_flags(self):
        results = {
            "f1": {
                "is_true_positive": True,
                "is_exploitable": True,
                "ruling": {"status": "false_positive"},
                "reasoning": "solid reasoning",
            },
        }
        assert check_self_contradiction(results) == 1
        assert results["f1"]["self_contradictory"] is True

    def test_dict_ruling_consistent_not_flagged(self):
        results = {
            "f1": {
                "is_true_positive": True,
                "is_exploitable": True,
                "ruling": {"status": "exploitable"},
                "reasoning": "solid reasoning",
            },
        }
        assert check_self_contradiction(results) == 0

    def test_non_string_reasoning_does_not_crash(self):
        results = {
            "f1": {
                "is_true_positive": True,
                "is_exploitable": True,
                "ruling": "exploitable",
                "reasoning": ["bullet one", "bullet two"],
            },
        }
        assert check_self_contradiction(results) == 0
