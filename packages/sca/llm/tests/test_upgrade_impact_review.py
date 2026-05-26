"""Tests for LLM upgrade-impact review stage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from packages.sca.llm.upgrade_impact_review import (
    _grep_call_sites,
    _import_patterns,
    assess_upgrade_impact,
)
from packages.sca.llm.schemas import (
    BreakingChange,
    UpgradeImpactVerdict,
)
from packages.sca.models import Confidence, Dependency, PinStyle


def _make_dep(
    name: str = "requests",
    ecosystem: str = "PyPI",
    version: str = "2.28.0",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/fake/requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence(level="high"),
    )


class TestImportPatterns:
    def test_pypi_import(self):
        dep = _make_dep("requests", "PyPI")
        patterns = _import_patterns(dep)
        assert len(patterns) == 1
        assert patterns[0].search("import requests")
        assert patterns[0].search("from requests import Session")
        assert not patterns[0].search("import unrequests")

    def test_pypi_hyphenated_name(self):
        dep = _make_dep("my-package", "PyPI")
        patterns = _import_patterns(dep)
        assert patterns[0].search("import my_package")
        assert patterns[0].search("from my_package import foo")

    def test_npm_require(self):
        dep = _make_dep("express", "npm")
        patterns = _import_patterns(dep)
        assert any(p.search("require('express')") for p in patterns)
        assert any(p.search('from "express"') for p in patterns)

    def test_npm_scoped(self):
        dep = _make_dep("@babel/core", "npm")
        patterns = _import_patterns(dep)
        assert any(p.search("require('@babel/core')") for p in patterns)
        assert any(p.search('from "@babel/core"') for p in patterns)

    def test_go_import(self):
        dep = _make_dep("github.com/gin-gonic/gin", "Go")
        patterns = _import_patterns(dep)
        assert patterns[0].search('"github.com/gin-gonic/gin"')

    def test_cargo_use(self):
        dep = _make_dep("serde-json", "Cargo")
        patterns = _import_patterns(dep)
        assert patterns[0].search("use serde_json")

    def test_rubygems_require(self):
        dep = _make_dep("nokogiri", "RubyGems")
        patterns = _import_patterns(dep)
        assert patterns[0].search("require 'nokogiri'")

    def test_maven_import(self):
        dep = _make_dep("org.apache.commons:commons-lang3", "Maven")
        patterns = _import_patterns(dep)
        assert patterns[0].search("import org.apache.commons.StringUtils;")

    def test_unknown_ecosystem_empty(self):
        dep = _make_dep("foo", "UnknownEco")
        patterns = _import_patterns(dep)
        assert patterns == []


class TestGrepCallSites:
    def test_finds_python_imports(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("import requests\nresponse = requests.get('http://example.com')\n")
        dep = _make_dep("requests", "PyPI")
        sites = _grep_call_sites(tmp_path, dep)
        assert len(sites) >= 1
        assert "app.py:1:" in sites[0]

    def test_skips_non_source_files(self, tmp_path):
        txt = tmp_path / "notes.txt"
        txt.write_text("import requests\n")
        dep = _make_dep("requests", "PyPI")
        sites = _grep_call_sites(tmp_path, dep)
        assert sites == []

    def test_skips_excluded_dirs(self, tmp_path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "requests.py").write_text("import requests\n")
        dep = _make_dep("requests", "PyPI")
        sites = _grep_call_sites(tmp_path, dep)
        assert sites == []

    def test_respects_cap(self, tmp_path):
        for i in range(600):
            f = tmp_path / f"mod_{i}.py"
            f.write_text("import requests\n")
        dep = _make_dep("requests", "PyPI")
        sites = _grep_call_sites(tmp_path, dep)
        assert len(sites) <= 501


class TestAssessUpgradeImpact:
    def test_same_version_returns_none(self):
        dep = _make_dep("requests", "PyPI", "2.28.0")
        result = assess_upgrade_impact(MagicMock(), dep, "2.28.0", Path("/fake"))
        assert result is None

    def test_no_version_returns_none(self):
        dep = _make_dep("requests", "PyPI")
        dep = Dependency(
            ecosystem="PyPI", name="requests", version=None,
            declared_in=Path("/fake/req.txt"), scope="main",
            is_lockfile=False, pin_style=PinStyle.UNKNOWN,
            direct=True, purl="pkg:pypi/requests",
            parser_confidence=Confidence(level="high"),
        )
        result = assess_upgrade_impact(MagicMock(), dep, "3.0.0", Path("/fake"))
        assert result is None

    def test_no_call_sites_returns_safe(self, tmp_path):
        dep = _make_dep("requests", "PyPI", "2.28.0")
        result = assess_upgrade_impact(MagicMock(), dep, "2.31.0", tmp_path)
        assert result is not None
        assert result.verdict == "safe"

    @patch("packages.sca.llm.upgrade_impact_review.run_stage")
    def test_llm_returns_verdict(self, mock_run_stage, tmp_path):
        (tmp_path / "app.py").write_text("import requests\nrequests.get('http://x')\n")

        verdict = UpgradeImpactVerdict(
            verdict="minor_migration",
            confidence="medium",
            breaking_changes=[
                BreakingChange(
                    site="app.py:2",
                    what_breaks="requests.get() timeout default changed",
                    suggested_fix="Add explicit timeout parameter",
                ),
            ],
            summary="Timeout default change affects 1 call site",
        )
        mock_run_stage.return_value = MagicMock(
            error=None, model=verdict, preflight_hit=False,
        )

        dep = _make_dep("requests", "PyPI", "2.28.0")
        result = assess_upgrade_impact(MagicMock(), dep, "3.0.0", tmp_path)

        assert result is not None
        assert result.verdict == "minor_migration"
        assert len(result.breaking_changes) == 1
        assert result.breaking_changes[0].site == "app.py:2"

    @patch("packages.sca.llm.upgrade_impact_review.run_stage")
    def test_llm_error_returns_none(self, mock_run_stage, tmp_path):
        (tmp_path / "app.py").write_text("import requests\n")
        mock_run_stage.return_value = MagicMock(
            error="LLM down", model=None, preflight_hit=False,
        )

        dep = _make_dep("requests", "PyPI", "2.28.0")
        result = assess_upgrade_impact(MagicMock(), dep, "3.0.0", tmp_path)
        assert result is None

    @patch("packages.sca.llm.upgrade_impact_review.run_stage")
    def test_preflight_hit_caps_confidence(self, mock_run_stage, tmp_path):
        (tmp_path / "app.py").write_text("import requests\n")

        verdict = UpgradeImpactVerdict(
            verdict="safe",
            confidence="high",
            summary="No breaking changes",
        )
        mock_run_stage.return_value = MagicMock(
            error=None, model=verdict, preflight_hit=True,
        )

        dep = _make_dep("requests", "PyPI", "2.28.0")
        result = assess_upgrade_impact(MagicMock(), dep, "2.31.0", tmp_path)
        assert result is not None
        assert result.confidence == "medium"


class TestUpgradeImpactSchemas:
    def test_breaking_change_valid(self):
        bc = BreakingChange(
            site="src/foo.py:42",
            what_breaks="Method signature changed",
            suggested_fix="Update call to new API",
        )
        assert bc.site == "src/foo.py:42"

    def test_verdict_safe(self):
        v = UpgradeImpactVerdict(verdict="safe", confidence="high")
        assert v.breaking_changes == []
        assert v.summary == ""

    def test_verdict_major_migration(self):
        v = UpgradeImpactVerdict(
            verdict="major_migration",
            confidence="high",
            breaking_changes=[
                BreakingChange(site="a.py:1", what_breaks="removed API"),
            ],
            summary="Major rewrite needed",
        )
        assert v.verdict == "major_migration"
        assert len(v.breaking_changes) == 1
