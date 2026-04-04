"""Tests for CVSS v3.1 base score calculator.

Test vectors sourced from NVD and the CVSS v3.1 specification examples.
"""

import pytest
from packages.cvss.calculator import (
    compute_base_score,
    parse_vector,
    validate_vector,
    compute_score_safe,
)


class TestValidateVector:
    def test_valid_full(self):
        assert validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_valid_v30(self):
        assert validate_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_invalid_prefix(self):
        assert not validate_vector("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_invalid_metric_value(self):
        assert not validate_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_missing_metric(self):
        assert not validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_empty_string(self):
        assert not validate_vector("")

    def test_garbage(self):
        assert not validate_vector("not a vector")


class TestParseVector:
    def test_parse_all_metrics(self):
        m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_vector("garbage")


class TestComputeBaseScore:
    """Test against known CVSS v3.1 scores from NVD.

    Scores verified at https://www.first.org/cvss/calculator/3.1
    """

    def test_critical_9_8(self):
        # CVE-2021-44228 (Log4Shell) - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0
        assert label == "Critical"

    def test_critical_9_8_scope_unchanged(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8
        assert label == "Critical"

    def test_high_7_8(self):
        # AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8
        score, label = compute_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert score == 7.8
        assert label == "High"

    def test_medium_6_1(self):
        # AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert score == 6.1
        assert label == "Medium"

    def test_low_3_7(self):
        # AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N = 3.7
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")
        assert score == 3.7
        assert label == "Low"

    def test_none_all_none_impact(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N = 0.0
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0
        assert label == "None"

    def test_physical_access(self):
        # AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 6.8
        score, label = compute_base_score("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 6.8
        assert label == "Medium"

    def test_high_complexity(self):
        # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.1
        score, label = compute_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 8.1
        assert label == "High"

    def test_scope_changed_xss(self):
        # Typical reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
        score, _ = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert score == 6.1

    def test_local_info_leak(self):
        # AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 5.5
        score, label = compute_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
        assert score == 5.5
        assert label == "Medium"

    def test_invalid_vector_raises(self):
        with pytest.raises(ValueError):
            compute_base_score("not a vector")


class TestComputeScoreSafe:
    def test_none_input(self):
        assert compute_score_safe(None) == (None, None)

    def test_empty_string(self):
        assert compute_score_safe("") == (None, None)

    def test_invalid_vector(self):
        assert compute_score_safe("garbage") == (None, None)

    def test_valid_vector(self):
        score, label = compute_score_safe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8
        assert label == "Critical"


class TestScoreFinding:
    """Tests for score_finding — single finding dict."""

    def test_sets_score_and_severity(self):
        from packages.cvss import score_finding
        f = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        score_finding(f)
        assert f["cvss_score_estimate"] == 9.8
        assert f["severity_assessment"] == "critical"

    def test_no_vector_unchanged(self):
        from packages.cvss import score_finding
        f = {"rule_id": "test"}
        score_finding(f)
        assert "cvss_score_estimate" not in f
        assert "severity_assessment" not in f

    def test_none_vector_unchanged(self):
        from packages.cvss import score_finding
        f = {"cvss_vector": None}
        score_finding(f)
        assert "cvss_score_estimate" not in f

    def test_invalid_vector_unchanged(self):
        from packages.cvss import score_finding
        f = {"cvss_vector": "not-a-vector"}
        score_finding(f)
        assert "cvss_score_estimate" not in f

    def test_overwrites_existing_score(self):
        from packages.cvss import score_finding
        f = {"cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "cvss_score_estimate": 0.0}
        score_finding(f)
        assert f["cvss_score_estimate"] == 7.8


class TestScoreFindings:
    """Tests for score_findings — list of finding dicts."""

    def test_scores_all(self):
        from packages.cvss import score_findings
        findings = [
            {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
        ]
        score_findings(findings)
        assert findings[0]["cvss_score_estimate"] == 9.8
        assert findings[1]["cvss_score_estimate"] == 7.8

    def test_skips_missing_vectors(self):
        from packages.cvss import score_findings
        findings = [
            {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"no_vector": True},
        ]
        score_findings(findings)
        assert findings[0]["cvss_score_estimate"] == 9.8
        assert "cvss_score_estimate" not in findings[1]

    def test_empty_list(self):
        from packages.cvss import score_findings
        score_findings([])  # Should not raise
