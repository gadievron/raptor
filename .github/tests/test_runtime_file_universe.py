"""Two-direction pins for the shared runtime-source universe.

The helper (`.github/scripts/runtime_universe.py`) is the single
derivation every tree-walking oracle consumes; a defect here would
silently narrow or widen ALL of them at once, so both directions are
pinned on a planted synthetic tree AND on the real checkout:

* inclusion — a new runtime file (package module, libexec python
  launcher, plugin hook, repo-root entry module) joins the universe
  with no registration step;
* exclusion — test files, fixtures, conftest.py, dev ``scripts/``
  harnesses, bash launchers, and dot-dirs stay out.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

from contextlib import nullcontext as _path_nullcontext
from unittest.mock import patch as _path_patch
import pytest as _path_pytest

with (_path_patch.object(sys, "path", sys.path.copy())
      if __name__ != "__main__" else _path_nullcontext()):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

    from runtime_universe import (  # noqa: E402
        EXCLUDED_PARTS,
        RUNTIME_ROOTS,
        is_runtime_python_file,
        repo_root,
        runtime_file_universe,
    )

    REPO = repo_root()




@_path_pytest.fixture(autouse=True)
def _scoped_helper_import_path(monkeypatch):
    """Keep lazy helper imports available without modifying borrowed path lists."""
    monkeypatch.setattr(sys, "path", sys.path.copy())
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


def _plant(root: Path, rel: str, text: str = "x = 1\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class TestSyntheticTree:
    @_path_pytest.mark.parametrize("excluded", [
        "core/pkg/tests", "core/pkg/fixtures", "core/.venv",
        "core/testing", "packages/pkg/scripts", "plugins/node_modules",
    ])
    def test_excluded_subtrees_are_not_walked(self, tmp_path, monkeypatch, excluded):
        live = _plant(tmp_path, "core/pkg/mod.py")
        _plant(tmp_path, excluded + "/deep/ignored.py")
        real_scandir = os.scandir

        def scandir(path):
            assert Path(path) != tmp_path / excluded, "descended into excluded subtree"
            return real_scandir(path)

        monkeypatch.setattr(os, "scandir", scandir)
        assert runtime_file_universe(tmp_path) == [live]

    def test_file_symlinks_remain_members_but_directory_links_are_not_followed(self, tmp_path):
        target = _plant(tmp_path, "outside/target.py")
        live = _plant(tmp_path, "core/pkg/mod.py")
        link = live.parent / "linked.py"
        link.symlink_to(target)
        (live.parent / "directory").symlink_to(target.parent, target_is_directory=True)
        (live.parent / "broken.py").symlink_to(tmp_path / "missing")
        assert runtime_file_universe(tmp_path) == sorted([live, link])

    def test_extra_exclusion_can_name_a_runtime_root(self, tmp_path):
        _plant(tmp_path, "core/pkg/mod.py")
        live = _plant(tmp_path, "packages/pkg/mod.py")
        assert runtime_file_universe(tmp_path, extra_excluded_parts=("core",)) == [live]

    def test_planted_runtime_files_appear(self, tmp_path):
        expected = {
            _plant(tmp_path, "core/newpkg/mod.py"),
            _plant(tmp_path, "core/testing_helpers/runtime.py"),
            _plant(tmp_path, "packages/testing/runtime.py"),
            _plant(tmp_path, "packages/newpkg/deep/mod.py"),
            _plant(tmp_path, "engine/rules/render.py"),
            _plant(tmp_path, "libexec/raptor-new-tool",
                   "#!/usr/bin/env python3\nx = 1\n"),
            _plant(tmp_path, "plugins/newplug/hooks/hook.py"),
            _plant(tmp_path, "raptor_newentry.py"),
        }
        got = set(runtime_file_universe(tmp_path))
        assert expected <= got, sorted(expected - got)

    def test_planted_non_runtime_files_stay_out(self, tmp_path):
        _plant(tmp_path, "core/pkg/mod.py")  # keep the walk non-empty
        planted = [
            _plant(tmp_path, "core/pkg/tests/test_mod.py"),
            _plant(tmp_path, "core/testing/expected_crash.py"),
            _plant(tmp_path, "core/testing/nested/helper.py"),
            _plant(tmp_path, "core/pkg/test/probe.py"),
            _plant(tmp_path, "core/pkg/fixtures/sample.py"),
            _plant(tmp_path, "core/pkg/conftest.py"),
            _plant(tmp_path, "conftest.py"),
            _plant(tmp_path, "core/pkg/scripts/harness.py"),
            _plant(tmp_path, "core/pkg/__pycache__/mod.py"),
            _plant(tmp_path, "core/.venv/lib/site.py"),
            _plant(tmp_path, "libexec/raptor-bash-tool",
                   "#!/usr/bin/env bash\necho hi\n"),
            _plant(tmp_path, "docs/example.py"),
            _plant(tmp_path, "out/run/artifact.py"),
        ]
        got = set(runtime_file_universe(tmp_path))
        offenders = [p for p in planted if p in got]
        assert not offenders, offenders

    def test_dev_scripts_opt_in(self, tmp_path):
        harness = _plant(tmp_path, "core/pkg/scripts/harness.py")
        assert harness not in set(runtime_file_universe(tmp_path))
        assert harness in set(
            runtime_file_universe(tmp_path, include_dev_scripts=True)
        )
        # The opt-in widens only the scripts/ dimension.
        helper = _plant(tmp_path, "core/testing/expected_crash.py")
        assert helper not in set(
            runtime_file_universe(tmp_path, include_dev_scripts=True)
        )
        test_file = _plant(tmp_path, "core/pkg/tests/test_mod.py")
        assert test_file not in set(
            runtime_file_universe(tmp_path, include_dev_scripts=True)
        )

    def test_extra_excluded_parts_are_gate_local(self, tmp_path):
        data = _plant(tmp_path, "packages/pkg/data/gen.py")
        assert data in set(runtime_file_universe(tmp_path))
        assert data not in set(
            runtime_file_universe(tmp_path, extra_excluded_parts=("data",))
        )


#: Quick text prescreen before parsing: a file can only import
#: excluded-dir code if an excluded name appears in its source.
_EXCLUDED_TOKEN_RE = re.compile(
    r"\b(?:" + "|".join(sorted(EXCLUDED_PARTS)) + r")\b")


def _excluded_import_offenders(repo: Path, universe: list[Path]) -> list[str]:
    """Universe members whose imports resolve to a repo module living
    under an EXCLUDED_PARTS directory.

    The universe's name-based exclusion assumes those directories hold
    no runtime-imported code; this cross-check turns the assumption
    into a verified invariant — runtime logic hosted in e.g.
    ``core/pkg/fixtures/helper.py`` would execute in production while
    every universe-derived gate ignored it.
    """
    offenders: list[str] = []
    for path in universe:
        text = path.read_text(encoding="utf-8", errors="replace")
        if not _EXCLUDED_TOKEN_RE.search(text):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        rel = path.relative_to(repo)
        package = list(rel.parts[:-1])
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    base = node.module or ""
                else:
                    prefix = package[:len(package) - node.level + 1]
                    base = ".".join(
                        prefix + ([node.module] if node.module else []))
                if base:
                    modules.append(base)
                modules.extend(
                    f"{base}.{item.name}" if base else item.name
                    for item in node.names)
            for module in modules:
                parts = tuple(module.split("."))
                if not EXCLUDED_PARTS.intersection(parts):
                    continue
                if any((repo / candidate).is_file() for candidate in (
                    Path(*parts).with_suffix(".py"),
                    Path(*parts, "__init__.py"),
                )):
                    # One report per import statement.
                    offenders.append(f"{rel}: import {module}")
                    break
    return offenders


class TestExcludedDirsHostNoRuntimeImportedCode:
    def test_planted_import_of_excluded_code_is_detected(self, tmp_path):
        _plant(tmp_path, "core/pkg/mod.py",
               "from core.pkg.fixtures.helper import run\n")
        _plant(tmp_path, "core/pkg/fixtures/__init__.py")
        _plant(tmp_path, "core/pkg/fixtures/helper.py",
               "def run():\n    return 1\n")
        offenders = _excluded_import_offenders(
            tmp_path, runtime_file_universe(tmp_path))
        assert offenders == [
            "core/pkg/mod.py: import core.pkg.fixtures.helper",
        ]

    def test_planted_relative_import_of_excluded_code_is_detected(self, tmp_path):
        _plant(tmp_path, "core/pkg/mod.py",
               "from .fixtures import helper\n")
        _plant(tmp_path, "core/pkg/fixtures/__init__.py")
        _plant(tmp_path, "core/pkg/fixtures/helper.py")
        offenders = _excluded_import_offenders(
            tmp_path, runtime_file_universe(tmp_path))
        assert offenders == [
            "core/pkg/mod.py: import core.pkg.fixtures",
        ]

    def test_unresolvable_excluded_names_do_not_fire(self, tmp_path):
        # Mentioning an excluded token (prose, a third-party module,
        # a nonexistent path) is not an offence — only imports that
        # RESOLVE to a repo file under an excluded dir count.
        _plant(tmp_path, "core/pkg/mod.py",
               "import pytest  # used by the test fixtures\n")
        offenders = _excluded_import_offenders(
            tmp_path, runtime_file_universe(tmp_path))
        assert offenders == []

    def test_live_tree_runtime_code_never_imports_excluded_dirs(self):
        offenders = _excluded_import_offenders(REPO, runtime_file_universe())
        assert not offenders, offenders


class TestRealTree:
    def test_core_build_is_in_the_universe(self):
        """Regression pin: the guardrails' bare ``build`` skip-name
        dropped the runtime package core/build from four gates."""
        uni = set(runtime_file_universe())
        assert REPO / "core/build/build_detector.py" in uni

    def test_entry_modules_and_launchers_present(self):
        uni = set(runtime_file_universe())
        assert REPO / "raptor.py" in uni
        assert REPO / "raptor_agentic.py" in uni
        assert REPO / "libexec/raptor-validation-helper" in uni

    def test_known_non_members_absent(self):
        uni = set(runtime_file_universe())
        assert REPO / "conftest.py" not in uni
        assert REPO / "core/json/tests/test_utils.py" not in uni
        # bash launcher, not python source
        assert REPO / "libexec/raptor-agentic" not in uni

    def test_roots_exist(self):
        for root in RUNTIME_ROOTS:
            assert (REPO / root).is_dir(), root

    def test_shebang_probe(self, tmp_path):
        py = tmp_path / "t"
        py.write_bytes(b"#!/usr/bin/env python3\n")
        assert is_runtime_python_file(py)
        sh = tmp_path / "s"
        sh.write_bytes(b"#!/usr/bin/env bash\n")
        assert not is_runtime_python_file(sh)
        # no shebang at all: data file, not runtime source
        raw = tmp_path / "r"
        raw.write_bytes(b"python\n")
        assert not is_runtime_python_file(raw)
