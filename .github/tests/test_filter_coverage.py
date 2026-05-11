"""Verify path-filter globs cover real import dependencies.

Why this test exists
--------------------
``.github/scripts/compute_filters.py`` declares per-subsystem path
filters in its ``FILTERS`` dict. If a subsystem's source code gains
an import to a module whose path is not covered by its filter glob,
an indirect-breakage refactor in that path won't trigger the
subsystem's tests on a normal PR — only on the daily cron, up to a
day late.

This test imports ``FILTERS`` directly, walks each subsystem's source
tree, collects every ``core.*`` / ``packages.*`` import, resolves
each to a file path, and fails if any path is not covered by a glob
in the corresponding filter. The same ``match_glob`` helper used by
the workflow does the matching, so the test and the runtime stay
aligned automatically.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / ".github" / "scripts"))
import compute_filters  # noqa: E402

# (filter_name_in_FILTERS, package_dir_relative_to_repo)
SUBSYSTEMS: list[tuple[str, str]] = [
    ("sandbox", "core/sandbox"),
    ("exploit_feasibility", "packages/exploit_feasibility"),
    # Heavy-subdir tiers carved out of the broad ``python`` fast tier.
    # When test_filter_coverage fails for one of these, add the missing
    # import path to the corresponding filter in compute_filters.FILTERS.
    ("codeql", "packages/codeql"),
    ("llm_analysis", "packages/llm_analysis"),
    ("cve_diff", "packages/cve_diff"),
    ("fuzzing", "packages/fuzzing"),
    ("sage", "core/sage"),
    ("orchestration", "core/orchestration"),
    ("zkpox", "packages/zkpox"),
]


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


class CIFilterCoverageTests(unittest.TestCase):
    """Every external import a subsystem makes must be covered by its
    path-filter glob in compute_filters.FILTERS."""

    def test_compute_filters_importable(self):
        self.assertTrue(
            hasattr(compute_filters, "FILTERS"),
            msg="compute_filters.py is missing the FILTERS dict",
        )

    def test_each_subsystem_filter_covers_its_imports(self):
        problems: list[str] = []
        for filter_name, pkg_rel in SUBSYSTEMS:
            pkg_dir = REPO / pkg_rel
            self.assertTrue(
                pkg_dir.is_dir(),
                msg=f"subsystem dir missing: {pkg_dir}",
            )
            globs = compute_filters.FILTERS.get(filter_name)
            self.assertTrue(
                globs,
                msg=f"filter `{filter_name}` not in compute_filters.FILTERS",
            )

            uncovered: list[tuple[str, Path]] = []
            for imp in sorted(_collect_external_imports(pkg_dir)):
                path = _module_to_path(imp)
                if path is None:
                    continue
                if not any(
                    compute_filters.match_glob(str(path), g) for g in globs
                ):
                    uncovered.append((imp, path))

            if uncovered:
                problems.append(
                    f"`{filter_name}` filter does not cover imports made by"
                    f" {pkg_rel}/:"
                )
                for imp, path in uncovered:
                    problems.append(f"  {imp}  ->  {path}")

        if problems:
            problems.append("")
            problems.append(
                "Fix: add globs covering each path to the relevant filter"
                " in .github/scripts/compute_filters.py, or narrow the import."
            )
            self.fail("\n".join(problems))


class PromptAuditFilterCoverageTests(unittest.TestCase):
    """The ``prompt_audit`` filter's globs must cover every file
    registered in ``_PROMPT_CONSTRUCTION_FILES`` plus the audit module
    and its test. Drift between the hardcoded list in
    compute_filters.py and the runtime registry would silently shrink
    the audit's CI coverage."""

    def test_prompt_audit_covers_registered_files(self):
        sys.path.insert(0, str(REPO))
        try:
            from core.security.prompt_envelope_audit import (  # noqa: E402
                _PROMPT_CONSTRUCTION_FILES,
            )
        finally:
            sys.path.pop(0)

        globs = compute_filters.FILTERS.get("prompt_audit")
        self.assertTrue(
            globs,
            msg="filter `prompt_audit` not in compute_filters.FILTERS",
        )

        # The audit module itself + the test file must be covered too —
        # editing the audit logic / allowlist must trigger the job.
        required = list(_PROMPT_CONSTRUCTION_FILES) + [
            "core/security/prompt_envelope_audit.py",
            "core/security/tests/test_prompt_envelope_audit.py",
        ]

        uncovered: list[str] = []
        for rel in required:
            if not any(
                compute_filters.match_glob(rel, g) for g in globs
            ):
                uncovered.append(rel)

        if uncovered:
            msg_lines = [
                "`prompt_audit` filter does not cover the following "
                "registered prompt-builder files / audit modules:",
            ]
            msg_lines.extend(f"  {p}" for p in uncovered)
            msg_lines.append("")
            msg_lines.append(
                "Fix: add globs covering each path to the "
                "`prompt_audit` entry in "
                ".github/scripts/compute_filters.py (the list there "
                "must mirror _PROMPT_CONSTRUCTION_FILES in "
                "core/security/prompt_envelope_audit.py)."
            )
            self.fail("\n".join(msg_lines))


if __name__ == "__main__":
    unittest.main()
