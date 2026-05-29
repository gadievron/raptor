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
    ("sca", "packages/sca"),
    ("source_intel", "packages/source_intel"),
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

    def test_each_subsystem_filter_is_canonical(self):
        """Each dependency filter must be deduped/collapsed and laid out
        in the canonical within-group order (own package, then alpha
        ``packages/*`` → ``core/*`` → ``libexec/*``, then tails). Keeps
        diffs small and ordering predictable. Fix with
        ``python .github/tests/test_filter_coverage.py --update`` (it also
        adds any missing import globs in the same pass)."""
        problems: list[str] = []
        for filter_name, pkg_rel in SUBSYSTEMS:
            globs = compute_filters.FILTERS.get(filter_name)
            if not globs:
                continue
            canonical = _canonical_order(
                set(_normalise_globs(set(globs))), pkg_rel
            )
            if list(globs) != canonical:
                problems.append(
                    f"`{filter_name}` is not canonical:\n"
                    f"    have: {list(globs)}\n"
                    f"    want: {canonical}"
                )
        if problems:
            problems.append("")
            problems.append(
                "Fix: run `python .github/tests/test_filter_coverage.py"
                " --update`."
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


class NormaliseGlobsTests(unittest.TestCase):
    """`_normalise_globs` dedups subsumed file globs and summarises
    multiple same-package imports into one whole-package ``**``."""

    def test_dedup_file_under_sibling_star(self):
        # bare ``import core.inventory`` -> ``**`` and
        # ``core.inventory.reachability`` -> file; the file is redundant.
        self.assertEqual(
            _normalise_globs(
                {"core/inventory/**", "core/inventory/reachability.py"}
            ),
            ["core/inventory/**"],
        )

    def test_collapse_multiple_files_one_package(self):
        self.assertEqual(
            _normalise_globs({
                "core/dataflow/finding.py",
                "core/dataflow/label.py",
                "core/dataflow/validator.py",
            }),
            ["core/dataflow/**"],
        )

    def test_single_file_import_stays_precise(self):
        # One module from a big sibling package must NOT broaden to **.
        self.assertEqual(
            _normalise_globs({"packages/codeql/dataflow_validator.py"}),
            ["packages/codeql/dataflow_validator.py"],
        )

    def test_mixed_set(self):
        self.assertEqual(
            _normalise_globs({
                "core/dataflow/finding.py",      # 2 files -> collapse
                "core/dataflow/label.py",
                "core/inventory/**",             # ** present -> absorb file
                "core/inventory/reachability.py",
                "core/llm/client.py",            # lone file -> stays precise
            }),
            ["core/dataflow/**", "core/inventory/**", "core/llm/client.py"],
        )

    def test_idempotent(self):
        once = _normalise_globs({
            "core/dataflow/finding.py", "core/dataflow/label.py",
        })
        self.assertEqual(_normalise_globs(set(once)), once)

    def test_canonical_order_groups_own_packages_core_tails(self):
        # Own package first, then packages/* alpha, core/* alpha, tails.
        self.assertEqual(
            _canonical_order(
                {
                    "core/llm/**", "packages/coccinelle/**",
                    ".github/workflows/tests.yml",
                    "packages/source_intel/**", "core/build/**",
                    "requirements*.txt",
                },
                "packages/source_intel",
            ),
            [
                "packages/source_intel/**",   # own first
                "packages/coccinelle/**",     # packages/* alpha
                "core/build/**",              # core/* alpha
                "core/llm/**",
                "requirements*.txt",          # tails
                ".github/workflows/tests.yml",
            ],
        )

    def test_canonical_order_is_idempotent(self):
        ordered = _canonical_order(
            {"core/b/**", "core/a/**", "packages/x/**"}, "packages/x"
        )
        self.assertEqual(
            _canonical_order(set(ordered), "packages/x"), ordered
        )


def _glob_for(path: Path) -> str:
    """Convert a resolved module path to a sensible filter glob.

    File path → glob is the file itself (`packages/codeql/smt_path_
    validator.py`). Directory path (package) → broad whole-package
    glob (`core/json/**`), matching the convention every existing
    entry in compute_filters.FILTERS already uses.
    """
    s = str(path)
    if s.endswith(".py"):
        return s
    return s + "/**"


# When a filter pulls in this many or more modules from a single depth-2
# package (``core/dataflow``, ``packages/codeql``, ...), _normalise_globs
# folds the per-file globs into one whole-package ``pkg/**`` — the
# convention the hand-maintained filters already use. A SINGLE
# cross-package import stays precise (cf. exploit_feasibility's
# ``packages/codeql/smt_path_validator.py``), so this never silently
# over-broadens a one-off dependency.
_PACKAGE_COLLAPSE_THRESHOLD = 2


def _package_root(glob: str) -> "str | None":
    """Depth-2 package root of a path glob (``core/dataflow`` for
    ``core/dataflow/finding.py``), or None for a non-path glob like
    ``requirements*.txt`` that has no directory structure."""
    parts = glob.split("/")
    if len(parts) < 2:
        return None
    return "/".join(parts[:2])


def _normalise_globs(globs: set[str]) -> list[str]:
    """Dedup + summarise an additive glob set for one filter.

    1. Collapse: per-file globs sharing a depth-2 package root fold into
       ``root/**`` when a ``root/**`` is already in the set OR at least
       ``_PACKAGE_COLLAPSE_THRESHOLD`` files share that root.
    2. Dedup: drop any glob subsumed by a ``root/**`` kept in the set
       (e.g. ``core/inventory/reachability.py`` under ``core/inventory/**``).

    Single-file imports from a package (below threshold, no sibling
    ``**``) keep their precise file glob. Operates only on the freshly
    computed additive set — existing filter entries are never rewritten,
    so the insert-only minimal-diff contract still holds.
    """
    from collections import Counter

    present_roots = {
        _package_root(g) for g in globs if g.endswith("/**")
    }
    present_roots.discard(None)
    file_roots = [
        _package_root(g) for g in globs if not g.endswith("/**")
    ]
    file_root_counts = Counter(r for r in file_roots if r is not None)
    collapse = present_roots | {
        r for r, n in file_root_counts.items()
        if n >= _PACKAGE_COLLAPSE_THRESHOLD
    }

    folded = {
        (_package_root(g) + "/**") if _package_root(g) in collapse else g
        for g in globs
    }

    # Drop anything strictly under a kept root's ``**``.
    roots = {g[: -len("/**")] for g in folded if g.endswith("/**")}
    result: list[str] = []
    for g in sorted(folded):
        target = g[: -len("/**")] if g.endswith("/**") else g
        if any(
            root != target and (target == root or target.startswith(root + "/"))
            for root in roots
        ):
            continue
        result.append(g)
    return result


def _canonical_key(glob: str, own_prefix: str) -> "tuple[int, str]":
    """Sort key for the canonical within-group glob order.

    Groups, in order: the subsystem's OWN package first, then
    ``packages/*`` (alphabetical), ``core/*`` (alphabetical),
    ``libexec/*`` (alphabetical), then the conventional tails
    (``requirements*.txt`` → ``pyproject.toml`` → ``.github/...``).
    Ordering is purely cosmetic — ``match_glob`` is order-independent —
    but a deterministic layout keeps diffs small and the lists readable.
    """
    if glob == own_prefix + "/**" or glob == own_prefix:
        return (0, "")
    if glob.startswith("packages/"):
        return (1, glob)
    if glob.startswith("core/"):
        return (2, glob)
    if glob.startswith("libexec/"):
        return (3, glob)
    if glob.startswith("requirements"):
        return (4, glob)
    if glob == "pyproject.toml":
        return (5, glob)
    if glob.startswith(".github/"):
        return (6, glob)
    return (7, glob)


def _canonical_order(globs: "set[str]", own_prefix: str) -> list[str]:
    """Return ``globs`` in the canonical within-group order."""
    return sorted(globs, key=lambda g: _canonical_key(g, own_prefix))


def _compute_per_filter_missing() -> dict[str, list[str]]:
    """Identify globs that need adding to each subsystem filter.

    Walks every subsystem the same way
    test_each_subsystem_filter_covers_its_imports does, but returns
    the missing entries instead of asserting. Returns dict mapping
    filter_name → sorted-unique list of globs to add.
    """
    missing: dict[str, set[str]] = {}
    for filter_name, pkg_rel in SUBSYSTEMS:
        pkg_dir = REPO / pkg_rel
        if not pkg_dir.is_dir():
            continue
        globs = compute_filters.FILTERS.get(filter_name)
        if not globs:
            continue
        for imp in sorted(_collect_external_imports(pkg_dir)):
            path = _module_to_path(imp)
            if path is None:
                continue
            if any(compute_filters.match_glob(str(path), g) for g in globs):
                continue
            missing.setdefault(filter_name, set()).add(_glob_for(path))
    return {k: _normalise_globs(v) for k, v in missing.items()}


def _rewrite_filter_block(source: str, filter_name: str,
                          ordered_globs: list[str]) -> str:
    """Replace FILTERS["<filter_name>"]'s list body with ordered_globs.

    Rewrites only the lines between the ``"name": [`` opener and its
    ``],`` closer; the leading comment (which sits ABOVE the key line)
    and every other filter are untouched. Safe only for lists with no
    inline comments between entries — i.e. the SUBSYSTEMS dependency
    filters. ``prompt_audit`` (inline comments + registry-mirror order)
    and the hand-curated specials (``python``, ``ci_lint``,
    ``codeql_*``) are never passed here.

    Raises RuntimeError if the block can't be located — treat that as
    "compute_filters.py shape has drifted, update by hand."
    """
    lines = source.splitlines(keepends=True)
    start_marker = f'    "{filter_name}": ['
    end_marker = "    ],"
    start: "int | None" = None
    end: "int | None" = None
    for i, line in enumerate(lines):
        if start is None and line.startswith(start_marker):
            start = i
            continue
        if start is not None and line.startswith(end_marker):
            end = i
            break
    if start is None or end is None:
        raise RuntimeError(
            f"Couldn't find list literal for filter {filter_name!r} in "
            f"compute_filters.py — file shape drift, update by hand."
        )
    body = [f'        "{g}",\n' for g in ordered_globs]
    return "".join(lines[: start + 1] + body + lines[end:])


def _update_compute_filters() -> dict[str, dict]:
    """Canonicalize every SUBSYSTEMS dependency filter + add missing globs.

    For each subsystem: take ``existing ∪ missing-import-globs``,
    dedup/collapse it (``_normalise_globs``), lay it out in the canonical
    within-group order (``_canonical_order``), and rewrite the list body
    when it differs from what's there. This makes one ``--update`` run do
    both jobs — fill coverage gaps AND normalize ordering/redundancy —
    and it's idempotent once a filter is canonical.

    Returns ``{name: {"added": [...], "removed": [...], "reordered":
    bool}}`` for the filters that changed (``removed`` = entries folded
    away by dedup/collapse).
    """
    missing = _compute_per_filter_missing()
    filter_file = REPO / ".github" / "scripts" / "compute_filters.py"
    source = filter_file.read_text(encoding="utf-8")
    changes: dict[str, dict] = {}
    for filter_name, pkg_rel in SUBSYSTEMS:
        existing = compute_filters.FILTERS.get(filter_name)
        if not existing:
            continue
        added = missing.get(filter_name, [])
        normalised = set(_normalise_globs(set(existing) | set(added)))
        ordered = _canonical_order(normalised, pkg_rel)
        if list(existing) == ordered:
            continue
        source = _rewrite_filter_block(source, filter_name, ordered)
        changes[filter_name] = {
            "added": sorted(set(ordered) - set(existing)),
            "removed": sorted(set(existing) - set(ordered)),
            "reordered": set(existing) == set(ordered),
        }
    if changes:
        filter_file.write_text(source, encoding="utf-8")
    return changes


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description=(
            "Filter-coverage test. With --update, surgically inserts "
            "missing globs into .github/scripts/compute_filters.py — "
            "review the diff before committing. Without --update, "
            "runs the test suite (the default CI mode)."
        ),
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help=(
            "Canonicalize the subsystem dependency filters in "
            "compute_filters.py and add any missing import globs, then "
            "exit 0. Mirrors the prompt-envelope audit --update workflow "
            "(PR #429): see test failure → run --update → review diff → "
            "commit. Adds coverage and normalizes ordering/redundancy; "
            "does NOT narrow a deliberately-broad glob or remove a dead "
            "entry whose import was deleted — those stay manual."
        ),
    )
    args, remaining = parser.parse_known_args()
    if args.update:
        changes = _update_compute_filters()
        if not changes:
            print(
                "✓ all subsystem filters cover their imports and are "
                "in canonical order — no changes"
            )
            sys.exit(0)
        for name in sorted(changes):
            c = changes[name]
            bits = []
            if c["added"]:
                bits.append(f"+{len(c['added'])}")
            if c["removed"]:
                bits.append(f"-{len(c['removed'])} folded")
            if c["reordered"]:
                bits.append("reordered")
            print(f"updated `{name}`: {', '.join(bits)}")
            for g in c["added"]:
                print(f"    + {g}")
            for g in c["removed"]:
                print(f"    - {g}")
        print()
        print(
            "Review the diff to .github/scripts/compute_filters.py "
            "before committing."
        )
        sys.exit(0)
    unittest.main(argv=[sys.argv[0]] + remaining)
