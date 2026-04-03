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
