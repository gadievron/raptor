"""Tests for .github/scripts/codeql_scope.py — import-graph-based
CodeQL scoping for Python PRs."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import sys
from contextlib import nullcontext as _path_nullcontext
from unittest.mock import patch as _path_patch
import pytest as _path_pytest

with (_path_patch.object(sys, "path", sys.path.copy())
      if __name__ != "__main__" else _path_nullcontext()):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

    from codeql_scope import (
        build_graph,
        discover_py_files,
        discover_root_modules,
        extract_imports,
        file_to_module,
        init_imports,
        is_root_module_path,
        load_base_config,
        missing_graph_covered_py,
        module_to_files,
        transitive_dependents,
        write_scoped_config,
    )




@_path_pytest.fixture(autouse=True)
def _scoped_helper_import_path(monkeypatch):
    """Keep lazy helper imports available without modifying borrowed path lists."""
    monkeypatch.setattr(sys, "path", sys.path.copy())
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


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

    def _nested_pkg(self, tmp_path, source):
        """core/a/b.py with *source*, inside a real nested package."""
        pkg = tmp_path / "core" / "a"
        pkg.mkdir(parents=True)
        (tmp_path / "core" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "core" / "client.py").write_text("", encoding="utf-8")
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "b.py").write_text(source, encoding="utf-8")
        return extract_imports(Path("core/a/b.py"), tmp_path)

    def test_bare_relative_import_current_package(self, tmp_path):
        # `from . import x` (module=None, level=1) — current package.
        imports = self._nested_pkg(tmp_path, "from . import sibling\n")
        assert "core.a" in imports
        assert "core.a.sibling" in imports

    def test_bare_relative_import_parent_package(self, tmp_path):
        # `from .. import client` (module=None, level=2) must resolve
        # against the PARENT package, not the current one — the wrong
        # edges under-scoped PR scans and test dispatch.
        imports = self._nested_pkg(tmp_path, "from .. import client\n")
        assert "core" in imports
        assert "core.client" in imports
        assert "core.a.client" not in imports

    def test_module_relative_import_parent_package(self, tmp_path):
        # `from ..client import X` (module set, level=2) — the
        # already-working branch keeps working.
        imports = self._nested_pkg(tmp_path, "from ..client import X\n")
        assert "core.client" in imports

    def test_filters_stdlib(self, tmp_path):
        (tmp_path / "test.py").write_text(
            "import json\nimport os\nfrom pathlib import Path\n",
            encoding="utf-8",
        )
        imports = extract_imports(Path("test.py"), tmp_path)
        assert imports == []

    def test_root_module_import_kept(self, tmp_path):
        # ``import entrymod`` targeting a repo-root entry module must
        # survive the scan-root filter — dropping it left root modules
        # with zero reverse-dependents and PRs editing them dispatched
        # zero test tiers.
        (tmp_path / "entrymod.py").write_text("X = 1\n", encoding="utf-8")
        (tmp_path / "test.py").write_text(
            "import entrymod\n", encoding="utf-8",
        )
        imports = extract_imports(Path("test.py"), tmp_path)
        assert "entrymod" in imports

    def test_single_name_without_root_file_filtered(self, tmp_path):
        # Both directions: a bare third-party name with no matching
        # repo-root module stays out of the graph.
        (tmp_path / "test.py").write_text(
            "import requests\n", encoding="utf-8",
        )
        assert extract_imports(Path("test.py"), tmp_path) == []

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
    @pytest.mark.parametrize("parsed_consumer", [False, True])
    def test_divisions_share_each_parsed_source_and_keep_graph(self, tmp_path, parsed_consumer):
        import ast

        files = self._make_repo(tmp_path)
        leaf = tmp_path / "core/leaf.py"
        leaf.write_text(leaf.read_text() + "VALUE = Path(__file__).parent / 'fixtures' / 'nested'\n"
                        "def make(arg=Path(__file__).parent / 'fixtures'): pass\n")
        broken = Path("core/broken.py")
        (tmp_path / broken).write_text("def broken(\n")
        files.append(broken)
        expected = build_graph(files, tmp_path)
        events, trees = [], {}

        def parsed(path, source, tree):
            events.append((path, "parsed"))
            trees[path] = (tree, ast.dump(tree, include_attributes=True))

        def divisions(path, source, nodes):
            events.append((path, "divisions"))
            assert source == (tmp_path / path).read_text()
            tree = trees[path][0] if parsed_consumer else ast.parse(source)
            expected_nodes = [node for node in ast.walk(tree)
                              if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)]
            assert [ast.dump(node) for node in nodes] == [ast.dump(node) for node in expected_nodes]
            if parsed_consumer:
                assert nodes == expected_nodes
                assert ast.dump(tree, include_attributes=True) == trees[path][1]

        actual = build_graph(files, tmp_path, on_parsed=parsed if parsed_consumer else None,
                             on_divisions=divisions)
        assert actual == expected
        assert actual[1] == 1
        kinds = ["parsed", "divisions"] if parsed_consumer else ["divisions"]
        assert events == [(path, kind) for path in files if path != broken for kind in kinds]

    @pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
    def test_division_consumer_failure_is_not_a_parse_failure(self, tmp_path, error):
        files = self._make_repo(tmp_path)

        def refuse(*args):
            raise error("consumer failed")

        with pytest.raises(error, match="consumer failed"):
            build_graph(files, tmp_path, on_divisions=refuse)

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

    def test_dangling_symlink_counts_as_parse_failure(self, tmp_path):
        # A dangling .py symlink under a scan root is discovered by
        # rglob but unreadable; uncaught, the FileNotFoundError from
        # extract_imports crashed build_graph — and with it the whole
        # dispatch job — on every PR while the symlink existed.
        files = self._make_repo(tmp_path)
        link = tmp_path / "core" / "dangling.py"
        try:
            link.symlink_to(tmp_path / "core" / "no_such_target.py")
        except OSError:
            pytest.skip("platform cannot create symlinks")
        files = [*files, Path("core/dangling.py")]
        reverse, failures = build_graph(files, tmp_path)
        assert failures == 1
        # The healthy edges are unaffected.
        assert Path("core/mid.py") in reverse.get(Path("core/base.py"), set())

    def test_root_module_acquires_reverse_dependents(self, tmp_path):
        # A repo-root entry module must be able to acquire reverse-
        # dependents; with the import filter erasing its edges it was
        # a permanently isolated node and PRs editing it dispatched
        # zero tiers.
        files = self._make_repo(tmp_path)
        (tmp_path / "entrymod.py").write_text("MAIN = 1\n", encoding="utf-8")
        (tmp_path / "core" / "uses_entry.py").write_text(
            "import entrymod\n", encoding="utf-8",
        )
        files = [*files, Path("entrymod.py"), Path("core/uses_entry.py")]
        reverse, failures = build_graph(files, tmp_path)
        assert failures == 0
        assert Path("core/uses_entry.py") in reverse.get(
            Path("entrymod.py"), set()
        )


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


class TestRootModuleDiscovery:
    def test_pattern_covers_any_root_py(self):
        # Pattern-based, not a name list: coverage must hold for root
        # modules a PR deleted (no disk entry) and for entry points
        # added after this code was written.
        assert is_root_module_path("raptor.py")
        assert is_root_module_path("raptor_codeql.py")
        assert is_root_module_path("some_new_entrypoint.py")

    def test_pattern_excludes_nested_and_non_py(self):
        assert not is_root_module_path("core/x.py")
        assert not is_root_module_path("docs/example.py")
        assert not is_root_module_path("README.md")
        assert not is_root_module_path(".py")

    def test_discovery_derives_from_tree(self, tmp_path):
        (tmp_path / "entrymod.py").write_text("X = 1\n")
        (tmp_path / "core").mkdir()
        (tmp_path / "core/nested.py").write_text("Y = 2\n")
        assert discover_root_modules(tmp_path) == [Path("entrymod.py")]


class TestMissingGraphCoveredPy:
    def test_deleted_scan_root_module_reported(self, tmp_path):
        (tmp_path / "core").mkdir()
        (tmp_path / "core/present.py").write_text("X = 1\n")
        missing = missing_graph_covered_py(
            {Path("core/present.py"), Path("core/deleted.py")}, tmp_path,
        )
        assert missing == ["core/deleted.py"]

    @pytest.mark.parametrize("root_module", [
        "raptor.py",
        # Deletion coverage is the pattern, not a list: these two sat
        # outside the old hand-list, so DELETING them stayed "outside
        # graph → inert" and dispatched zero tiers.
        "raptor_codeql.py",
        "future_entrypoint.py",
    ])
    def test_deleted_root_module_reported(self, tmp_path, root_module):
        missing = missing_graph_covered_py({Path(root_module)}, tmp_path)
        assert missing == [root_module]

    def test_missing_file_outside_graph_ignored(self, tmp_path):
        # A deleted .py the graph never covered proves nothing about
        # lost import edges — it must not trigger a full scan.
        missing = missing_graph_covered_py(
            {Path("docs/example.py"), Path("libexec/tool.py")}, tmp_path,
        )
        assert missing == []

    def test_non_py_paths_ignored(self, tmp_path):
        missing = missing_graph_covered_py(
            {Path("core/data/rules.json")}, tmp_path,
        )
        assert missing == []


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
        # write_scoped_config deduplicates to parent directories
        assert "  - core/json" in text
        assert "  - core/llm" in text
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

    @pytest.fixture(scope="class")
    @staticmethod
    def repo():
        repo = Path(__file__).resolve().parents[2]
        if not (repo / "core").is_dir():
            pytest.skip("not running from RAPTOR repo root")
        return repo

    @pytest.fixture(scope="class")
    @staticmethod
    def repo_graph(repo, whole_repo_import_graph):
        """Use the same real-tree graph as the dispatch suite."""
        assert whole_repo_import_graph[4] == repo
        return whole_repo_import_graph[:3]

    def test_discover_finds_files(self, repo):
        files = discover_py_files(repo)
        assert len(files) > 100

    def test_graph_builds_without_failures(self, repo_graph):
        _, _, failures = repo_graph
        assert failures == 0

    def test_leaf_file_has_small_closure(self, repo_graph):
        files, reverse, _ = repo_graph
        # A leaf package file should have a small closure.
        leaf = Path("packages/web/scanner.py")
        if leaf not in set(files):
            pytest.skip("packages/web/scanner.py not found")
        closure = transitive_dependents({leaf}, reverse)
        assert len(closure) < 50

    def test_hub_file_has_large_closure(self, repo_graph):
        files, reverse, _ = repo_graph
        hub = Path("core/config/__init__.py")
        if hub not in set(files):
            pytest.skip("core/config/__init__.py not found")
        changed = {hub}
        changed |= init_imports(changed, files)
        closure = transitive_dependents(changed, reverse)
        assert len(closure) > len(files) * 0.3


def test_preparsed_import_extraction_matches_disk_tree(tmp_path):
    import ast
    path = Path("core/example.py")
    (tmp_path / path).parent.mkdir()
    text = 'from .json import loads\nimport importlib\nimportlib.import_module("packages.web.browser")\n'
    (tmp_path / path).write_text(text)
    expected = extract_imports(path, tmp_path)
    assert extract_imports(path, tmp_path, source_tree=ast.parse(text)) == expected


def test_import_passes_keep_late_aliases_exports_and_literal_references(tmp_path):
    """Conservative dependency discovery must retain every extraction arm."""
    path = Path("core/example/__init__.py")
    (tmp_path / path).parent.mkdir(parents=True)
    (tmp_path / path).write_text(textwrap.dedent('''\
        import core.json
        from . import helpers
        dynamic("core.audit.executor")
        from importlib import import_module as dynamic
        importlib.import_module("packages.web.browser")
        __import__("engine.coccinelle")
        _LAZY_EXPORTS = {"run": ("core.audit.orchestrator", "run_orchestrator")}
        patch_target = "core.llm.client.generate"
        runner = "libexec/raptor-audit"
    '''))
    references = {"libexec/raptor-audit": set(), "unrelated-script": set()}
    assert set(extract_imports(path, tmp_path, literal_references=references)) == {
        "core.json", "core.example", "core.example.helpers",
        "core.audit.executor", "packages.web.browser", "engine.coccinelle",
        "core.audit.orchestrator", "core.llm.client.generate",
    }
    assert references == {
        "libexec/raptor-audit": {path}, "unrelated-script": set(),
    }


@pytest.mark.parametrize("expression", [
    "value = f\"{delayed('core.json.utils')}\"",
    "value = [delayed('core.json.utils') for item in inputs]",
    "value = lambda: delayed('core.json.utils')",
    "def f(arg: delayed('core.json.utils')): pass",
    "def f(arg=delayed('core.json.utils')): pass",
    "class C(delayed('core.json.utils')): pass",
    "value = {'module': delayed('core.json.utils')}",
], ids=["fstring", "comprehension", "lambda", "annotation", "default", "class-base", "dict"])
def test_import_collection_keeps_expression_children_and_borrowed_tree(tmp_path, expression):
    import ast

    source = (expression + "\nfrom importlib import import_module as delayed\n"
              "def entry(script: 'libexec/raptor-session-init'): pass\n")
    tree = ast.parse(source)
    original = ast.dump(tree, include_attributes=True)
    path = Path("core/consumer.py")
    references = {"libexec/raptor-session-init": set(), "other-script": set()}
    assert extract_imports(path, tmp_path, frozenset(), references, source_tree=tree) == [
        "core.json.utils", "core.json.utils",
    ]
    assert references == {"libexec/raptor-session-init": {path}, "other-script": set()}
    assert ast.dump(tree, include_attributes=True) == original


def test_import_collection_preserves_kind_order(tmp_path):
    import ast

    source = ("value = (delayed('core.first.module'), delayed('core.second.module'))\n"
              "from importlib import import_module as delayed\n")
    assert extract_imports(Path("core/consumer.py"), tmp_path, frozenset(),
                           source_tree=ast.parse(source)) == [
        "core.first.module", "core.second.module",
        "core.first.module", "core.second.module",
    ]


def test_import_filter_keeps_roots_and_rejects_lookalikes(tmp_path):
    import ast

    source = ("import core, packages, engine\n"
              "import core.extra, packages.tool, engine.rule\n"
              "import corex, packagesx, enginex\n"
              "import root_entry, root_entry.child\n")
    assert extract_imports(Path("consumer.py"), tmp_path, frozenset({"root_entry"}),
                           source_tree=ast.parse(source)) == [
        "core", "packages", "engine", "core.extra", "packages.tool",
        "engine.rule", "root_entry",
    ]
