"""Tests for SCA finding routing in ExploitTask and PatchTask."""

from __future__ import annotations

import pytest

from packages.llm_analysis.tasks import (
    ExploitTask,
    PatchTask,
    _build_sca_exploit_prompt,
    _build_sca_patch_prompt,
    _is_sca_finding,
    _sca_exploit_priority,
)


def _make_sca_finding(
    finding_id: str = "SCA-001",
    *,
    reachability: str = "likely_called",
    in_kev: bool = False,
    epss: float | None = None,
    cvss_score: float | None = None,
    fixed_version: str | None = "2.0.0",
) -> dict:
    return {
        "finding_id": finding_id,
        "source_type": "dependency",
        "vuln_type": "sca:vulnerable_dependency",
        "severity": "high",
        "description": "Known vulnerability in test-pkg",
        "file_path": "requirements.txt",
        "sca": {
            "ecosystem": "PyPI",
            "name": "test-pkg",
            "version": "1.0.0",
            "reachability": reachability,
            "in_kev": in_kev,
            "epss": epss,
            "cvss_score": cvss_score,
            "fixed_version": fixed_version,
        },
    }


def _make_code_finding(finding_id: str = "F-001", exploitable: bool = True) -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": "sqli",
        "file_path": "db.py",
        "start_line": 42,
        "end_line": 45,
        "level": "error",
        "message": "SQL injection",
        "code": "bad()",
        "surrounding_context": "context",
    }


class TestIsSCAFinding:
    def test_source_type_dependency(self):
        assert _is_sca_finding({"source_type": "dependency"})

    def test_vuln_type_sca_prefix(self):
        assert _is_sca_finding({"vuln_type": "sca:vulnerable_dependency"})

    def test_code_finding(self):
        assert not _is_sca_finding(_make_code_finding())

    def test_empty_dict(self):
        assert not _is_sca_finding({})


class TestSCAExploitPriority:
    def test_kev_adds_fifty(self):
        f = _make_sca_finding(in_kev=True)
        assert _sca_exploit_priority(f) >= 50.0

    def test_epss_scaled(self):
        f = _make_sca_finding(epss=0.5)
        score = _sca_exploit_priority(f)
        assert 15.0 <= score <= 50.0  # 0.5 * 30 + reachability

    def test_likely_called_adds_twenty(self):
        f = _make_sca_finding(reachability="likely_called")
        base = _sca_exploit_priority(_make_sca_finding(reachability="not_evaluated"))
        assert _sca_exploit_priority(f) - base == pytest.approx(20.0)

    def test_imported_adds_ten(self):
        f = _make_sca_finding(reachability="imported")
        base = _sca_exploit_priority(_make_sca_finding(reachability="not_evaluated"))
        assert _sca_exploit_priority(f) - base == pytest.approx(10.0)

    def test_cvss_adds_score(self):
        f = _make_sca_finding(cvss_score=9.8, reachability="not_evaluated")
        assert _sca_exploit_priority(f) == pytest.approx(9.8)

    def test_combined_priority(self):
        f = _make_sca_finding(
            in_kev=True, epss=0.8, reachability="likely_called", cvss_score=9.0,
        )
        score = _sca_exploit_priority(f)
        assert score == pytest.approx(50.0 + 0.8 * 30 + 20.0 + 9.0)


class TestExploitTaskSCA:
    def test_selects_reachable_sca(self):
        task = ExploitTask()
        findings = [
            _make_sca_finding("SCA-001", reachability="likely_called"),
            _make_sca_finding("SCA-002", reachability="not_reachable"),
        ]
        selected = task.select_items(findings, {})
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "SCA-001"

    def test_selects_kev_regardless_of_reachability(self):
        task = ExploitTask()
        findings = [
            _make_sca_finding("SCA-001", reachability="not_evaluated", in_kev=True),
        ]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_selects_imported_sca(self):
        task = ExploitTask()
        findings = [
            _make_sca_finding("SCA-001", reachability="imported"),
        ]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_skips_not_reachable_non_kev(self):
        task = ExploitTask()
        findings = [
            _make_sca_finding("SCA-001", reachability="not_reachable", in_kev=False),
        ]
        selected = task.select_items(findings, {})
        assert selected == []

    def test_skips_existing_exploit(self):
        task = ExploitTask()
        findings = [_make_sca_finding("SCA-001")]
        prior = {"SCA-001": {"exploit_code": "# existing"}}
        selected = task.select_items(findings, prior)
        assert selected == []

    def test_sorts_by_priority(self):
        task = ExploitTask()
        low = _make_sca_finding("SCA-LOW", reachability="imported")
        high = _make_sca_finding("SCA-HIGH", reachability="likely_called", in_kev=True)
        selected = task.select_items([low, high], {})
        assert selected[0]["finding_id"] == "SCA-HIGH"

    def test_builds_sca_prompt(self):
        task = ExploitTask()
        finding = _make_sca_finding()
        prompt = task.build_prompt(finding)
        assert "test-pkg" in prompt
        assert "PyPI" in prompt
        assert "proof-of-concept" in prompt.lower()

    def test_mixed_code_and_sca(self):
        task = ExploitTask()
        code = _make_code_finding("F-001")
        sca = _make_sca_finding("SCA-001", reachability="likely_called")
        prior = {"F-001": {"is_exploitable": True}}
        selected = task.select_items([code, sca], prior)
        assert len(selected) == 2


class TestPatchTaskSCA:
    def test_selects_sca_with_fixed_version(self):
        task = PatchTask()
        findings = [
            _make_sca_finding("SCA-001", fixed_version="2.0.0"),
            _make_sca_finding("SCA-002", fixed_version=None),
        ]
        selected = task.select_items(findings, {})
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "SCA-001"

    def test_skips_existing_patch(self):
        task = PatchTask()
        findings = [_make_sca_finding("SCA-001")]
        prior = {"SCA-001": {"patch_code": "# existing"}}
        selected = task.select_items(findings, prior)
        assert selected == []

    def test_builds_sca_patch_prompt(self):
        task = PatchTask()
        finding = _make_sca_finding(fixed_version="2.0.0")
        prompt = task.build_prompt(finding)
        assert "test-pkg" in prompt
        assert "2.0.0" in prompt
        assert "upgrade" in prompt.lower()


class TestBuildSCAPrompts:
    def test_exploit_prompt_includes_kev(self):
        f = _make_sca_finding(in_kev=True)
        prompt = _build_sca_exploit_prompt(f)
        assert "KEV" in prompt

    def test_exploit_prompt_includes_epss(self):
        f = _make_sca_finding(epss=0.75)
        prompt = _build_sca_exploit_prompt(f)
        assert "EPSS" in prompt

    def test_patch_prompt_no_fixed_version(self):
        f = _make_sca_finding(fixed_version=None)
        prompt = _build_sca_patch_prompt(f)
        assert "workaround" in prompt.lower() or "alternative" in prompt.lower()

    def test_patch_prompt_with_fixed_version(self):
        f = _make_sca_finding(fixed_version="3.1.0")
        prompt = _build_sca_patch_prompt(f)
        assert "3.1.0" in prompt
