"""Tests for .github/scripts/codeql_scope.py — import-graph-based
CodeQL scoping for Python PRs."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from codeql_scope import (
    build_graph,
    discover_py_files,
    extract_imports,
    file_to_module,
    init_imports,
    load_base_config,
    module_to_files,
    transitive_dependents,
    write_scoped_config,
)


class TestFileToModule:
    def test_regular_file(self):
        assert file_to_module(Path("core/llm/client.py")) == "core.llm.client"

    def test_init_file(self):
        assert file_to_module(Path("core/llm/__init__.py")) == "core.llm"

    def test_top_level(self):
        assert file_to_module(Path("raptor.py")) == "raptor"

    def test_deep_path(self):
        assert file_to_module(Path("packages/sca/resolvers/pip.py")) == "packages.sca.resolvers.pip"

    def test_empty_path(self):
        assert file_to_module(Path("")) is None


class TestModuleToFiles:
    def test_exact_match(self):
        mod_map = {"core.llm.client": Path("core/llm/client.py")}
        assert module_to_files("core.llm.client", mod_map) == [Path("core/llm/client.py")]

    def test_no_match(self):
        mod_map = {"core.llm.client": Path("core/llm/client.py")}
        assert module_to_files("core.llm.nonexistent", mod_map) == []


class TestExtractImports:
    def test_absolute_import(self, tmp_path):
        (tmp_path / "test.py").write_text(
            "from core.json import load_json\n",
            encoding="utf-8",
        )
        imports = extract_imports(Path("test.py"), tmp_path)
        assert "core.json" in imports
        assert "core.json.load_json" in imports

    def test_relative_import(self, tmp_path):
        pkg = tmp_path / "core" / "llm"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "client.py").write_text(
            "from .config import LLMConfig\n",
            encoding="utf-8",
        )
        imports = extract_imports(Path("core/llm/client.py"), tmp_path)
        assert "core.llm.config" in imports

    def test_filters_stdlib(self, tmp_path):
        (tmp_path / "test.py").write_text(
            "import json\nimport os\nfrom pathlib import Path\n",
            encoding="utf-8",
        )
        imports = extract_imports(Path("test.py"), tmp_path)
        assert imports == []

    def test_syntax_error_returns_none(self, tmp_path):
        (tmp_path / "bad.py").write_text(
            "def f(\n  # incomplete\n",
            encoding="utf-8",
        )
        assert extract_imports(Path("bad.py"), tmp_path) is None

    def test_lazy_import_inside_function(self, tmp_path):
        (tmp_path / "test.py").write_text(textwrap.dedent("""\
            def do_work():
                from core.annotations.storage import write_annotation
                write_annotation()
        """), encoding="utf-8")
        imports = extract_imports(Path("test.py"), tmp_path)
        assert "core.annotations.storage" in imports
        assert "core.annotations.storage.write_annotation" in imports


class TestBuildGraph:
    def _make_repo(self, tmp_path):
        """Create a minimal repo structure for graph tests."""
        # core/base.py — no internal imports
        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "core" / "base.py").write_text(
            "VALUE = 42\n", encoding="utf-8"
        )
        # core/mid.py — imports core.base
        (tmp_path / "core" / "mid.py").write_text(
            "from core.base import VALUE\n", encoding="utf-8"
        )
        # core/leaf.py — imports core.mid
        (tmp_path / "core" / "leaf.py").write_text(
            "from core.mid import VALUE\n", encoding="utf-8"
        )
        # packages/tool.py — imports core.mid
        (tmp_path / "packages").mkdir()
        (tmp_path / "packages" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "packages" / "tool.py").write_text(
            "from core.mid import VALUE\n", encoding="utf-8"
        )

        files = [
            Path("core/__init__.py"),
            Path("core/base.py"),
            Path("core/mid.py"),
            Path("core/leaf.py"),
            Path("packages/__init__.py"),
            Path("packages/tool.py"),
        ]
        return files

    def test_reverse_graph_structure(self, tmp_path):
        files = self._make_repo(tmp_path)
        reverse, failures = build_graph(files, tmp_path)
        assert failures == 0

        # core/base.py should be depended on by core/mid.py
        base_deps = reverse.get(Path("core/base.py"), set())
        assert Path("core/mid.py") in base_deps

        # core/mid.py should be depended on by core/leaf.py and packages/tool.py
        mid_deps = reverse.get(Path("core/mid.py"), set())
        assert Path("core/leaf.py") in mid_deps
        assert Path("packages/tool.py") in mid_deps

    def test_transitive_closure(self, tmp_path):
        files = self._make_repo(tmp_path)
        reverse, _ = build_graph(files, tmp_path)

        # Changing core/base.py should pull in core/mid.py (direct),
        # then core/leaf.py and packages/tool.py (transitive).
        closure = transitive_dependents({Path("core/base.py")}, reverse)
        assert Path("core/base.py") in closure
        assert Path("core/mid.py") in closure
        assert Path("core/leaf.py") in closure
        assert Path("packages/tool.py") in closure

    def test_leaf_change_minimal_closure(self, tmp_path):
        files = self._make_repo(tmp_path)
        reverse, _ = build_graph(files, tmp_path)

        # Changing core/leaf.py should only include itself (nobody imports it).
        closure = transitive_dependents({Path("core/leaf.py")}, reverse)
        assert closure == {Path("core/leaf.py")}


class TestInitImports:
    def test_init_change_pulls_package(self):
        all_files = [
            Path("core/llm/__init__.py"),
            Path("core/llm/client.py"),
            Path("core/llm/config.py"),
            Path("core/llm/tests/test_client.py"),
            Path("core/json/__init__.py"),
        ]
        changed = {Path("core/llm/__init__.py")}
        extra = init_imports(changed, all_files)
        assert Path("core/llm/client.py") in extra
        assert Path("core/llm/config.py") in extra
        assert Path("core/llm/tests/test_client.py") in extra
        assert Path("core/json/__init__.py") not in extra

    def test_non_init_change_no_expansion(self):
        all_files = [
            Path("core/llm/__init__.py"),
            Path("core/llm/client.py"),
            Path("core/llm/config.py"),
        ]
        changed = {Path("core/llm/client.py")}
        extra = init_imports(changed, all_files)
        assert extra == set()


class TestLoadBaseConfig:
    def test_parse_paths_ignore(self, tmp_path):
        config_file = tmp_path / "config.yml"
        config_file.write_text(textwrap.dedent("""\
            name: Test config

            paths-ignore:
              - test/data/**
              - "**/fixtures/**"
        """), encoding="utf-8")
        config = load_base_config(config_file)
        assert config["name"] == "Test config"
        assert "test/data/**" in config["paths-ignore"]
        assert "**/fixtures/**" in config["paths-ignore"]

    def test_missing_file(self, tmp_path):
        config = load_base_config(tmp_path / "nope.yml")
        assert "paths-ignore" in config


class TestWriteScopedConfig:
    def test_scoped_output(self, tmp_path):
        out = tmp_path / "scoped.yml"
        write_scoped_config(
            out,
            {"name": "Test", "paths-ignore": ["test/**"]},
            ["core/llm/client.py", "core/json/utils.py"],
        )
        text = out.read_text(encoding="utf-8")
        assert "paths:" in text
        assert "  - core/json/utils.py" in text
        assert "  - core/llm/client.py" in text
        assert "paths-ignore:" in text
        assert "  - 'test/**'" in text

    def test_full_scan_no_paths(self, tmp_path):
        out = tmp_path / "full.yml"
        write_scoped_config(
            out,
            {"name": "Test", "paths-ignore": ["test/**"]},
            None,
        )
        text = out.read_text(encoding="utf-8")
        assert "paths:" not in text
        assert "paths-ignore:" in text


@pytest.mark.slow
class TestOnRealRepo:
    """Integration tests against the actual RAPTOR codebase."""

    @pytest.fixture()
    def repo(self):
        repo = Path(__file__).resolve().parents[2]
        if not (repo / "core").is_dir():
            pytest.skip("not running from RAPTOR repo root")
        return repo

    def test_discover_finds_files(self, repo):
        files = discover_py_files(repo)
        assert len(files) > 100

    def test_graph_builds_without_failures(self, repo):
        files = discover_py_files(repo)
        _, failures = build_graph(files, repo)
        assert failures == 0

    def test_leaf_file_has_small_closure(self, repo):
        files = discover_py_files(repo)
        reverse, _ = build_graph(files, repo)
        # A leaf package file should have a small closure.
        leaf = Path("packages/web/scanner.py")
        if leaf not in set(files):
            pytest.skip("packages/web/scanner.py not found")
        closure = transitive_dependents({leaf}, reverse)
        assert len(closure) < 50

    def test_hub_file_has_large_closure(self, repo):
        files = discover_py_files(repo)
        reverse, _ = build_graph(files, repo)
        hub = Path("core/config/__init__.py")
        if hub not in set(files):
            pytest.skip("core/config/__init__.py not found")
        changed = {hub}
        changed |= init_imports(changed, files)
        closure = transitive_dependents(changed, reverse)
        assert len(closure) > len(files) * 0.3
