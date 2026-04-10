"""Tests for packages/sca/agent.py."""

import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.sca.agent import (
    find_dependency_files,
    parse_pom,
    parse_requirements,
    parse_package_json,
    get_out_dir,
)


# ---------------------------------------------------------------------------
# find_dependency_files()
# ---------------------------------------------------------------------------

class TestFindDependencyFiles:

    def test_empty_directory(self, tmp_path):
        assert find_dependency_files(tmp_path) == []

    def test_finds_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0")
        results = find_dependency_files(tmp_path)
        assert any(p.name == "requirements.txt" for p in results)

    def test_finds_pom_xml(self, tmp_path):
        (tmp_path / "pom.xml").write_text("<project/>")
        results = find_dependency_files(tmp_path)
        assert any(p.name == "pom.xml" for p in results)

    def test_finds_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text('{"dependencies": {}}')
        results = find_dependency_files(tmp_path)
        assert any(p.name == "package.json" for p in results)

    def test_finds_build_gradle(self, tmp_path):
        (tmp_path / "build.gradle").write_text("dependencies {}")
        results = find_dependency_files(tmp_path)
        assert any(p.name == "build.gradle" for p in results)

    def test_finds_pyproject_toml(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.poetry]\n")
        results = find_dependency_files(tmp_path)
        assert any(p.name == "pyproject.toml" for p in results)

    def test_finds_nested_files(self, tmp_path):
        sub = tmp_path / "backend" / "api"
        sub.mkdir(parents=True)
        (sub / "requirements.txt").write_text("flask==2.0.0")
        results = find_dependency_files(tmp_path)
        assert any(p.name == "requirements.txt" for p in results)

    def test_does_not_find_unrelated_files(self, tmp_path):
        (tmp_path / "README.md").write_text("# project")
        (tmp_path / "main.py").write_text("print('hi')")
        results = find_dependency_files(tmp_path)
        assert results == []

    def test_finds_multiple_manifest_types(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests")
        (tmp_path / "package.json").write_text('{"dependencies": {}}')
        results = find_dependency_files(tmp_path)
        assert len(results) == 2

    def test_returns_path_objects(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask")
        results = find_dependency_files(tmp_path)
        for r in results:
            assert isinstance(r, Path)


# ---------------------------------------------------------------------------
# parse_pom()
# ---------------------------------------------------------------------------

class TestParsePom:

    def _write_pom(self, path: Path, deps):
        """Write a minimal Maven POM with the given dependencies."""
        dep_xml = ""
        for g, a, v in deps:
            dep_xml += f"""
            <dependency>
                <groupId>{g}</groupId>
                <artifactId>{a}</artifactId>
                {'<version>' + v + '</version>' if v else ''}
            </dependency>"""
        content = f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>{dep_xml}
    </dependencies>
</project>"""
        path.write_text(content)

    def test_parses_single_dependency(self, tmp_path):
        pom = tmp_path / "pom.xml"
        self._write_pom(pom, [("org.springframework", "spring-core", "5.3.0")])
        result = parse_pom(pom)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["group"] == "org.springframework"
        assert result[0]["artifact"] == "spring-core"
        assert result[0]["version"] == "5.3.0"

    def test_parses_multiple_dependencies(self, tmp_path):
        pom = tmp_path / "pom.xml"
        self._write_pom(pom, [
            ("com.google.guava", "guava", "31.0"),
            ("junit", "junit", "4.13"),
        ])
        result = parse_pom(pom)
        assert len(result) == 2

    def test_handles_missing_version(self, tmp_path):
        pom = tmp_path / "pom.xml"
        self._write_pom(pom, [("org.apache", "commons", None)])
        result = parse_pom(pom)
        assert result[0]["version"] is None

    def test_returns_error_dict_on_invalid_xml(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text("this is not xml <<<")
        result = parse_pom(pom)
        assert isinstance(result, dict)
        assert "error" in result

    def test_returns_error_dict_on_missing_file(self, tmp_path):
        result = parse_pom(tmp_path / "nonexistent.xml")
        assert isinstance(result, dict)
        assert "error" in result

    def test_empty_pom_returns_empty_list(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
</project>""")
        result = parse_pom(pom)
        assert result == []


# ---------------------------------------------------------------------------
# parse_requirements()
# ---------------------------------------------------------------------------

class TestParseRequirements:

    def test_parses_simple_deps(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\nflask>=2.0.0\n")
        result = parse_requirements(req)
        assert "requests==2.28.0" in result
        assert "flask>=2.0.0" in result

    def test_skips_comments(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# this is a comment\nrequests==2.28.0\n")
        result = parse_requirements(req)
        assert len(result) == 1
        assert result[0] == "requests==2.28.0"

    def test_skips_blank_lines(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("\nrequests==2.28.0\n\nflask>=2.0\n\n")
        result = parse_requirements(req)
        assert len(result) == 2

    def test_empty_file(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("")
        result = parse_requirements(req)
        assert result == []

    def test_strips_whitespace(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("  requests==2.28.0  \n")
        result = parse_requirements(req)
        assert result == ["requests==2.28.0"]

    def test_preserves_extras_and_markers(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests[security]>=2.27.0;python_version>='3.7'\n")
        result = parse_requirements(req)
        assert len(result) == 1
        assert "requests" in result[0]


# ---------------------------------------------------------------------------
# parse_package_json()
# ---------------------------------------------------------------------------

class TestParsePackageJson:

    def test_parses_dependencies(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "my-app",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "^4.17.21",
            }
        }))
        result = parse_package_json(pkg)
        assert isinstance(result, list)
        names = [d["name"] for d in result]
        assert "express" in names
        assert "lodash" in names

    def test_returns_name_and_version(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"react": "^18.0.0"}}))
        result = parse_package_json(pkg)
        assert result[0]["name"] == "react"
        assert result[0]["version"] == "^18.0.0"

    def test_empty_dependencies(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {}}))
        result = parse_package_json(pkg)
        assert result == []

    def test_no_dependencies_key(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "my-app", "version": "1.0.0"}))
        result = parse_package_json(pkg)
        assert result == []

    def test_returns_error_dict_on_invalid_json(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text("{not valid json}")
        result = parse_package_json(pkg)
        assert isinstance(result, dict)
        assert "error" in result

    def test_returns_error_dict_on_missing_file(self, tmp_path):
        result = parse_package_json(tmp_path / "missing.json")
        assert isinstance(result, dict)
        assert "error" in result


# ---------------------------------------------------------------------------
# get_out_dir()
# ---------------------------------------------------------------------------

class TestGetOutDir:

    def test_respects_raptor_out_dir(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            assert get_out_dir() == tmp_path.resolve()

    def test_defaults_to_out(self):
        env = {k: v for k, v in os.environ.items() if k != "RAPTOR_OUT_DIR"}
        with patch.dict(os.environ, env, clear=True):
            assert get_out_dir().name == "out"
