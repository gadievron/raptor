"""Tests for the dependency satisfaction matrix."""

from __future__ import annotations

from core.broker.deps import (
    DEPENDENCIES,
    Dependency,
    DepCheckResult,
    InstallGuide,
    MatrixResult,
    Platform,
    Tier,
    check_all,
    format_matrix,
)


class TestPlatformDetect:
    def test_returns_a_platform(self):
        plat = Platform.detect()
        assert isinstance(plat, Platform)


class TestDependencyCatalog:
    def test_all_dependencies_have_names(self):
        for dep in DEPENDENCIES:
            assert dep.name, f"dependency missing name: {dep}"

    def test_all_dependencies_have_tiers(self):
        for dep in DEPENDENCIES:
            assert isinstance(dep.tier, Tier)

    def test_required_deps_exist(self):
        required = [d for d in DEPENDENCIES if d.required]
        assert len(required) >= 2
        names = {d.name for d in required}
        assert "python3" in names
        assert "git" in names

    def test_each_dep_has_detection_method(self):
        for dep in DEPENDENCIES:
            has_method = dep.binary is not None or dep.python_package is not None
            assert has_method, f"{dep.name} has no detection method"

    def test_install_guides_reference_valid_platforms(self):
        for dep in DEPENDENCIES:
            for guide in dep.install_guides:
                assert isinstance(guide.platform, Platform)
                assert guide.command, f"{dep.name} guide for {guide.platform} has empty command"


class TestCheckAll:
    def test_returns_matrix(self):
        result = check_all()
        assert isinstance(result, MatrixResult)
        assert result.total_count == len(DEPENDENCIES)

    def test_python_is_met(self):
        result = check_all()
        python_results = [r for r in result.results if r.dep.name == "python3"]
        assert len(python_results) == 1
        assert python_results[0].met

    def test_git_is_met(self):
        result = check_all()
        git_results = [r for r in result.results if r.dep.name == "git"]
        assert len(git_results) == 1
        assert git_results[0].met

    def test_by_tier_groups_correctly(self):
        result = check_all()
        grouped = result.by_tier()
        assert Tier.CORE in grouped
        core_names = {r.dep.name for r in grouped[Tier.CORE]}
        assert "python3" in core_names

    def test_platform_override(self):
        result = check_all(platform=Platform.WINDOWS_X86_64)
        assert result.platform == Platform.WINDOWS_X86_64


class TestFormatMatrix:
    def test_produces_output(self):
        result = check_all()
        text = format_matrix(result)
        assert "RAPTOR Dependency Matrix" in text
        assert "Score:" in text

    def test_shows_met_and_not_met(self):
        result = check_all()
        text = format_matrix(result)
        assert "[  MET  ]" in text or "[NOT MET]" in text

    def test_shows_tier_headers(self):
        result = check_all()
        text = format_matrix(result)
        assert "CORE" in text
        assert "SCANNING" in text


class TestMatrixResultScoring:
    def test_required_scoring(self):
        dep_met = Dependency(
            name="a", description="a", tier=Tier.CORE,
            binary="python3", required=True,
        )
        dep_not = Dependency(
            name="b", description="b", tier=Tier.CORE,
            binary="nonexistent_binary_xyz", required=True,
        )
        results = (
            DepCheckResult(dep=dep_met, met=True),
            DepCheckResult(dep=dep_not, met=False),
        )
        matrix = MatrixResult(platform=Platform.detect(), results=results)
        assert matrix.required_met == 1
        assert matrix.required_total == 2
        assert matrix.met_count == 1
        assert matrix.total_count == 2
