"""Verify path-filter globs in tests.yml cover real import dependencies.

Why this test exists
--------------------
``.github/workflows/tests.yml`` declares per-subsystem path filters
(e.g. ``sandbox:``, ``exploit_feasibility:``) that scope which test
jobs fire on a given PR. If a subsystem's source code gains an import
to a module whose path is not covered by its filter glob, an
indirect-breakage refactor in that path won't trigger the subsystem's
tests on a normal PR — only on the weekly cron, up to 7 days late.

This test parses the filter block, collects every ``core.*`` /
``packages.*`` import made by the subsystem's source, resolves each
import to a file path, and fails if any path is not covered by a
glob in the corresponding filter.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TESTS_YML = REPO / ".github/workflows/tests.yml"

# (filter_name_in_tests_yml, package_dir_relative_to_repo)
SUBSYSTEMS: list[tuple[str, str]] = [
    ("sandbox", "core/sandbox"),
    ("exploit_feasibility", "packages/exploit_feasibility"),
]


def _parse_filter_globs(name: str) -> list[str]:
    """Extract globs for the named filter from the dorny/paths-filter
    block in tests.yml without depending on PyYAML.

    The block looks like::

        <name>:
          - 'glob1'
          - 'glob2'

    nested under ``filters: |`` inside the ``changes`` job.
    """
    globs: list[str] = []
    in_filter = False
    filter_indent: int | None = None
    item_re = re.compile(r"-\s*['\"]([^'\"]+)['\"]\s*$")
    for line in TESTS_YML.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if not in_filter:
            if stripped == f"{name}:":
                in_filter = True
                filter_indent = len(line) - len(stripped)
            continue
        if not stripped:
            continue
        cur_indent = len(line) - len(stripped)
        assert filter_indent is not None
        if cur_indent <= filter_indent:
            break
        m = item_re.match(stripped)
        if m:
            globs.append(m.group(1))
    return globs


def _collect_external_imports(pkg_dir: Path) -> set[str]:
    """Imported ``core.*`` / ``packages.*`` modules outside pkg_dir."""
    pkg_module = ".".join(pkg_dir.relative_to(REPO).parts)
    imports: set[str] = set()
    for py in pkg_dir.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
            elif isinstance(node, ast.Import):
                mods.extend(alias.name for alias in node.names)
            for m in mods:
                if not m.startswith(("core.", "packages.")):
                    continue
                if m == pkg_module or m.startswith(pkg_module + "."):
                    continue
                imports.add(m)
    return imports


def _module_to_path(module: str) -> Path | None:
    """Resolve a dotted module to a repo-relative path, or None."""
    rel = module.replace(".", "/")
    f = REPO / (rel + ".py")
    if f.is_file():
        return f.relative_to(REPO)
    init = REPO / rel / "__init__.py"
    if init.is_file():
        return (REPO / rel).relative_to(REPO)
    return None


def _glob_covers(rel_path: Path, globs: list[str]) -> bool:
    """Approximate dorny/paths-filter (minimatch) coverage."""
    s = str(rel_path)
    for g in globs:
        if g.endswith("/**"):
            prefix = g[: -len("/**")]
            if s == prefix or s.startswith(prefix + "/"):
                return True
        elif "*" in g:
            if fnmatch.fnmatch(s, g):
                return True
        elif s == g:
            return True
    return False


class CIFilterCoverageTests(unittest.TestCase):
    """Every external import a subsystem makes must be covered by its
    path-filter glob in tests.yml."""

    def test_tests_yml_exists(self):
        self.assertTrue(
            TESTS_YML.is_file(),
            msg=f"workflow file missing: {TESTS_YML}",
        )

    def test_each_subsystem_filter_covers_its_imports(self):
        problems: list[str] = []
        for filter_name, pkg_rel in SUBSYSTEMS:
            pkg_dir = REPO / pkg_rel
            self.assertTrue(
                pkg_dir.is_dir(),
                msg=f"subsystem dir missing: {pkg_dir}",
            )
            globs = _parse_filter_globs(filter_name)
            self.assertTrue(
                globs,
                msg=f"filter `{filter_name}:` not found in {TESTS_YML}",
            )

            uncovered: list[tuple[str, Path]] = []
            for imp in sorted(_collect_external_imports(pkg_dir)):
                path = _module_to_path(imp)
                if path is None:
                    continue
                if not _glob_covers(path, globs):
                    uncovered.append((imp, path))

            if uncovered:
                problems.append(
                    f"`{filter_name}:` filter does not cover imports made by"
                    f" {pkg_rel}/:"
                )
                for imp, path in uncovered:
                    problems.append(f"  {imp}  ->  {path}")

        if problems:
            problems.append("")
            problems.append(
                "Fix: add globs covering each path to the relevant filter"
                " in .github/workflows/tests.yml, or narrow the import."
            )
            self.fail("\n".join(problems))


if __name__ == "__main__":
    unittest.main()
