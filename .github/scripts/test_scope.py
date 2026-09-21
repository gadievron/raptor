"""Import-graph-based test dispatch for PR builds.

Replaces the manually-maintained glob lists in compute_filters.py's
subsystem filters.  Builds the same reverse import graph as
codeql_scope.py, computes the transitive closure from the changed-
file set, then maps affected test files to their CI tier.

Each tier still exists as a separate CI job (for runner selection,
dependency installation, and parallelism), but the gate condition
is now "does the graph show affected test files in this tier?"
instead of "did a glob match?"

Within each tier the job runs only the affected test files, not the
entire directory.  The ``python`` (fast) tier additionally outputs a
``python_matrix`` JSON so the CI job can fan out into dynamically-
sized parallel batches via ``strategy.matrix.include``.

Outputs to GITHUB_OUTPUT:
  - <tier>=true|false              per-tier gate
  - <tier>_files=<paths>           space-separated affected test files
  - python_matrix=<json>           dynamic batch matrix for fast tier
  - scope_mode=scoped|full         for observability
  - scope_summary=<text>           human-readable summary

Usage:
    python3 .github/scripts/test_scope.py \\
        --changed-files /tmp/changed_files.txt \\
        --repo .
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codeql_scope import (
    SCAN_ROOTS,
    build_graph,
    discover_py_files,
    init_imports,
    missing_graph_covered_py,
    transitive_dependents,
)


TIERS: dict[str, dict] = {
    "sandbox": {
        "test_dirs": ["core/sandbox/tests"],
        "env": "sandbox",
        "env_reason": "needs Linux namespaces / macOS sandbox-exec",
    },
    "exploit_feasibility": {
        "test_dirs": ["packages/exploit_feasibility/tests"],
        "env": "exploit_feasibility",
        "env_reason": "needs radare2, gcc, real binaries",
    },
    "codeql": {
        "test_dirs": ["packages/codeql/tests"],
    },
    "llm_analysis": {
        "test_dirs": ["packages/llm_analysis/tests"],
    },
    "cve_diff": {
        "test_dirs": ["packages/cve_diff/tests"],
    },
    "fuzzing": {
        "test_dirs": ["packages/fuzzing/tests"],
    },
    "sage": {
        "test_dirs": ["core/sage/tests"],
    },
    "orchestration": {
        "test_dirs": ["core/orchestration/tests"],
    },
    "sca": {
        "test_dirs": ["packages/sca"],
    },
    "source_intel": {
        "test_dirs": ["packages/source_intel/tests"],
        "env": "source_intel",
        "env_reason": "needs coccinelle (spatch)",
    },
    # The whole engine/ root: rule-precision suites (semgrep ReDoS
    # gate, per-rule coccinelle tests, vocab/api-pack renderers) that
    # previously ran in NO CI lane — engine/ was outside SCAN_ROOTS,
    # every tier's test_dirs, and the fast tier's core|packages bound,
    # so an engine-only PR dispatched zero tiers and a rule regression
    # merged green forever. Claimed as a directory (like sca's
    # packages/sca) so future engine/<subsystem>/tests dirs are
    # covered without a registry edit. The spatch-driven rule tests
    # run for real on the container path (the CI deps image bakes in
    # coccinelle — the source_intel precedent); the runner fallback
    # and toolless hosts skip them via their shutil.which guards.
    "engine": {
        "test_dirs": ["engine"],
        "env": "engine",
        "env_reason": "needs coccinelle (spatch) + semgrep for the "
                      "rule-precision gates",
    },
    "prompt_audit": {
        "test_files": ["core/security/tests/test_prompt_envelope_audit.py"],
        "trigger_files": [
            "core/security/prompt_envelope_audit.py",
            "core/security/tests/test_prompt_envelope_audit.py",
            "packages/llm_analysis/agent.py",
            "packages/llm_analysis/dataflow_validation.py",
            "packages/llm_analysis/orchestrator.py",
            "packages/llm_analysis/prefilter.py",
            "packages/llm_analysis/tasks.py",
            "packages/llm_analysis/crash_agent.py",
            "packages/llm_analysis/prompts/analysis.py",
            "packages/llm_analysis/prompts/exploit.py",
            "packages/llm_analysis/prompts/patch.py",
            "packages/hypothesis_validation/runner.py",
            "packages/codeql/autonomous_analyzer.py",
            "packages/codeql/dataflow_validator.py",
            "core/build/build_detector.py",
            "packages/web/fuzzer.py",
            "packages/autonomous/dialogue.py",
            "core/llm/multi_model/prompt_helpers.py",
            "packages/cve_diff/cve_diff/agent/loop.py",
            "packages/cve_diff/cve_diff/agent/prompt.py",
            "packages/cve_diff/cve_diff/analysis/analyzer.py",
            "packages/cve_env/cve_env/agent/loop.py",
            "packages/cve_env/cve_env/agent/prompts.py",
            "core/audit/llm_summaries.py",
            "core/audit/context.py",
            "core/audit/batch_glance.py",
            "core/audit/spec_inference.py",
            "core/audit/security_classifier.py",
            "core/audit/chain_detector.py",
            "core/audit/refinement.py",
            "core/audit/validate.py",
            "core/audit/sibling_analysis.py",
            "core/audit/checker_synthesis.py",
            "core/audit/adversarial_refute.py",
            "core/audit/dark_verify/_prompts.py",
            "packages/checker_synthesis/prompts.py",
            "packages/checker_synthesis/synthesise.py",
            "core/concepts/compiler.py",
            "packages/fuzzing/harness_generator.py",
            "packages/binary_analysis/radare2_understand.py",
        ],
        "outside_graph": True,
    },
    "ci_lint": {
        "test_dirs": [".github/tests", ".github/scripts/tests"],
        # .github/tests asserts workflow CONTENT (lint.yml step shapes,
        # workflow paths), pins CLAUDE.md / .claude/commands prose,
        # ruff config in pyproject.toml, README's self-check section,
        # and the libexec//bin launcher-preamble identity templates —
        # so edits to any of those must fire this tier too, not only
        # .github/scripts changes; otherwise a breaking edit merges
        # green and reddens the next scheduled full run, misattributed.
        #
        # Both directions: every entry here must be content-pinned by
        # a test this tier runs (TestCiLintTriggerClosure derives the
        # _read() targets mechanically); conversely, unpinned files
        # (LICENSE, docs/...) must NOT be added — dragging the tier in
        # for unrelated edits erodes the scoping this dispatch exists
        # to provide.
        "extra_triggers": [
            ".github/scripts",
            ".github/workflows",
            "CLAUDE.md",
            ".claude",
            "README.md",
            "pyproject.toml",
            "libexec",
            "bin",
        ],
        "outside_graph": True,
    },
}

FAST_TIER_IGNORES = {
    "core/sandbox/tests",
    "packages/exploit_feasibility/tests",
    "packages/codeql/tests",
    "packages/llm_analysis/tests",
    "packages/cve_diff/tests",
    "packages/fuzzing/tests",
    "packages/oss_forensics/tests",
    "packages/source_intel/tests",
    "packages/sca",
    "core/sage/tests",
    "core/orchestration/tests",
    "core/security/tests/test_prompt_envelope_audit.py",
}


#: Repo-relative paths of files that ARE the test harness — every
#: tier's execution flows through them, so a change to any one must
#: dispatch the FULL tier set.
#:
#: Root pytest harness (conftest.py, pytest.ini): every tier runs
#: under their configuration (fixtures, emulation/egress guards,
#: marker filters, addopts). The directory-tree conftest expansion
#: cannot express that blast radius (the root's prefix "./" matches
#: no relative path), pytest.ini is neither a .py file nor a
#: requirements/pyproject infra trigger, and the preflight
#: deliberately excludes conftest.py — so without this gate a PR
#: touching only these files dispatched ZERO tiers and merged green
#: with no tests run.
#:
#: CI dispatch harness (tests.yml / _tier.yml / preflight.yml and the
#: scope scripts they run): these define every tier's pytest
#: invocation, env guards, and gating. A PR touching only them fired
#: ci_lint at most — but GHA only executes the jobs that gate ON,
#: which was none, so a tier-command regression (wrong pytest args,
#: dropped env guard, an under-dispatching scope bug) merged green
#: and surfaced on the next real PR or the cron, misattributed —
#: the same delayed-failure shape as the root pytest case above.
ROOT_HARNESS_FILES = frozenset({
    "conftest.py",
    "pytest.ini",
    ".github/workflows/tests.yml",
    ".github/workflows/_tier.yml",
    ".github/workflows/preflight.yml",
    ".github/scripts/test_scope.py",
    ".github/scripts/codeql_scope.py",
    ".github/scripts/preflight_scope.py",
})


def is_dependency_manifest(path: str) -> bool:
    """Root-level dependency manifests: requirements*.txt and
    pyproject.toml.

    Every heavy tier installs from these files (the venv jobs and
    _tier.yml key their caches on ``hashFiles('requirements*.txt')``),
    so a manifest-only PR must dispatch the FULL tier set: scoping it
    to the fast tier let a pin bump that broke a carved-out tier merge
    green and redden that tier's next unrelated run, misattributed —
    the same delayed-failure shape as the root-harness case. The
    sibling CodeQL scoper already treats these files as
    full-scan-worthy. Root-level only: manifests inside test fixture
    trees are test data, not the CI install surface.

    Trade-off of the root-level restriction: if the install surface
    ever moves into a directory (e.g. a ``requirements/base.txt``
    layout), this pattern dispatches NOTHING for it — widen the
    pattern together with the workflows' hashFiles() keys when that
    happens. The tie is oracle-tested: every root-level file the
    workflows' hashFiles() expressions key caches on must be claimed
    here (test_hashfiles_manifests_are_claimed), so moving the venv
    cache keys without widening this pattern fails the suite.
    """
    return path == "pyproject.toml" or (
        "/" not in path and path.startswith("requirements")
    )


def expand_conftest(changed_py: set[Path], all_py: list[Path]) -> set[Path]:
    """Files affected by changed conftest.py files.

    A conftest applies to every test in its directory tree; the
    repo-root conftest's tree is the whole repo. Tier-dispatch callers
    additionally treat root-harness changes as full dispatch (see
    ``ROOT_HARNESS_FILES``); this expansion still covers the root case
    so import-graph consumers that skip that gate stay sound.
    """
    extra: set[Path] = set()
    for f in changed_py:
        if f.name != "conftest.py":
            continue
        pkg_dir = f.parent
        if pkg_dir == Path("."):
            extra.update(af for af in all_py if af != f)
            continue
        prefix = str(pkg_dir) + "/"
        for af in all_py:
            if af != f and str(af).startswith(prefix):
                extra.add(af)
    return extra


def is_test_file(path: Path) -> bool:
    """Heuristic: a .py file is a test if its name starts with test_ or
    ends with _test, or it lives under a tests/ directory.

    Files under ``fixtures/`` are excluded — they are test data (e.g.
    Flask apps) that pytest must not collect as test modules.
    """
    if not path.name.endswith(".py"):
        return False
    parts = path.parts
    if "fixtures" in parts:
        return False
    name = path.stem
    if name.startswith("test_") or name.endswith("_test"):
        return True
    return "tests/" in str(path) or "/tests/" in str(path)


def file_in_dir(path: Path, directory: str) -> bool:
    """Check if path is under directory (string prefix match)."""
    s = str(path)
    return s == directory or s.startswith(directory + "/")


def file_matches_tier(path: Path, tier: dict) -> bool:
    """Check if a file belongs to a tier."""
    if "test_files" in tier:
        return str(path) in tier["test_files"]
    for d in tier.get("test_dirs", []):
        if file_in_dir(path, d):
            return True
    return False


def file_in_fast_tier(path: Path) -> bool:
    """Check if a test file belongs to the fast tier (not carved out)."""
    if not is_test_file(path):
        return False
    s = str(path)
    for ignored in FAST_TIER_IGNORES:
        if s == ignored or s.startswith(ignored + "/"):
            return False
    return file_in_dir(path, "core") or file_in_dir(path, "packages")


# ---------------------------------------------------------------------------
# Non-Python resource files (runtime data, fixtures, templates)
# ---------------------------------------------------------------------------

_FIXTURE_DIR_NAMES = frozenset({"fixtures", "data", "testdata"})

_FIXTURE_PATTERNS = (
    "fixtures",
    "data",
    "testdata",
    "FIXTURE",
    "DATA_DIR",
    "fixture_dir",
    "data_dir",
    "test_data",
)


def _resolve_path_div_chain(node: ast.expr) -> list[str]:
    """Walk a ``Path(...) / "a" / "b"`` chain and return the string parts."""
    parts: list[str] = []
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        rhs = node.right
        if isinstance(rhs, ast.Constant) and isinstance(rhs.value, str):
            parts.append(rhs.value)
        else:
            break
        node = node.left
    parts.reverse()
    return parts


def _extract_fixture_dirs(path: Path, repo: Path) -> list[Path]:
    """Find fixture/data directories referenced by a test file.

    Parses the AST for ``Path(__file__).parent / "fixtures" / "sub"``
    chains, resolving the deepest directory that exists on disk.
    Falls back to scanning for sibling fixture directories when the
    AST doesn't yield results.
    """
    try:
        source = (repo / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not any(p in source for p in _FIXTURE_PATTERNS):
        return []

    dirs: set[Path] = set()
    test_dir = (repo / path).parent

    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []

    # Collect BinOp / nodes that are NOT the left child of another /.
    # This gives us only the outermost (longest) chain, not sub-chains.
    inner_lefts: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            inner_lefts.add(id(node.left))

    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
            continue
        if id(node) in inner_lefts:
            continue
        parts = _resolve_path_div_chain(node)
        if not parts or parts[0] not in _FIXTURE_DIR_NAMES:
            continue
        candidate = test_dir
        for part in parts:
            candidate = candidate / part
        if candidate.is_dir():
            dirs.add(candidate)

    if not dirs:
        for name in _FIXTURE_DIR_NAMES:
            candidate = test_dir / name
            if candidate.is_dir() and name in source:
                dirs.add(candidate)

    return list(dirs)


def _discover_data_files(dirs: list[Path], repo: Path) -> set[Path]:
    """Collect all non-Python files under fixture directories."""
    files: set[Path] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if p.is_file() and p.suffix != ".py" and p.suffix != ".pyc":
                try:
                    files.add(p.relative_to(repo))
                except ValueError:
                    pass
    return files


def build_data_file_map(
    test_files: list[Path], repo: Path,
) -> dict[Path, set[Path]]:
    """Map data files → test files that use them."""
    data_to_tests: dict[Path, set[Path]] = defaultdict(set)
    for tf in test_files:
        fixture_dirs = _extract_fixture_dirs(tf, repo)
        if not fixture_dirs:
            continue
        data_files = _discover_data_files(fixture_dirs, repo)
        for df in data_files:
            data_to_tests[df].add(tf)
    return dict(data_to_tests)


def _owning_package_seeds(path: Path, all_py: list[Path]) -> set[Path]:
    """The .py files of the package that owns a resource file.

    Walks up from the resource's directory to (but not including) its
    scan root, returning every known .py file under the nearest
    ancestor that has any: the code reading a bundled resource lives
    beside it (``core/x/data/foo.json`` → ``core/x``'s modules), and
    the import graph then finds that code's tests. Membership is
    checked against the discovered file list, not the disk, so a
    deleted resource whose directory went with it still resolves.

    Empty result = no owning package below the scan root; the caller
    must treat the file as unmappable.
    """
    for parent in path.parents:
        s = str(parent)
        if s == "." or s in SCAN_ROOTS:
            break
        prefix = s + "/"
        seeds = {af for af in all_py if str(af).startswith(prefix)}
        if seeds:
            return seeds
    return set()


# ---------------------------------------------------------------------------
# Dynamic batching
# ---------------------------------------------------------------------------

def batch_matrix(
    files: list[Path],
    *,
    max_batches: int = 8,
    target_per_batch: int = 25,
) -> list[dict]:
    """Partition test files into balanced batches for GHA matrix.

    Returns a list of ``{"batch": N, "files": "a.py b.py ..."}`` dicts
    suitable for ``strategy.matrix.include: ${{ fromJSON(...) }}``.

    Uses round-robin distribution so batch sizes differ by at most 1
    (26 files → 13+13, not 25+1).
    """
    if not files:
        return []
    sorted_files = sorted(str(f) for f in files)
    n = len(sorted_files)
    n_batches = min(max_batches, max(1, math.ceil(n / target_per_batch)))
    batches: list[list[str]] = [[] for _ in range(n_batches)]
    for i, f in enumerate(sorted_files):
        batches[i % n_batches].append(f)
    return [
        {"batch": i + 1, "files": " ".join(b)}
        for i, b in enumerate(batches)
    ]


def _discover_tier_files(tier_config: dict, repo: Path) -> list[Path]:
    """Discover all test files belonging to a tier from disk."""
    files = []
    for d in tier_config.get("test_dirs", []):
        dir_path = repo / d
        if dir_path.is_dir():
            for p in dir_path.rglob("*.py"):
                rp = p.relative_to(repo)
                if is_test_file(rp):
                    files.append(rp)
    for f in tier_config.get("test_files", []):
        fp = Path(f)
        if (repo / fp).is_file() and is_test_file(fp):
            files.append(fp)
    return files


def _discover_fast_tier_files(repo: Path) -> list[Path]:
    """Discover all fast-tier test files from disk."""
    all_py = discover_py_files(repo)
    return [f for f in all_py if file_in_fast_tier(f)]


def compute_tier_dispatch(
    changed_files: list[str],
    repo: Path,
) -> dict[str, dict]:
    """Compute per-tier dispatch from the changed-file list.

    Returns {tier_name: {"run": bool, "files": [Path, ...]}}.
    The ``python`` (fast) tier additionally includes a ``"matrix"``
    key with the ``batch_matrix()`` result.
    """
    # Root harness files reconfigure every tier's run — full dispatch.
    harness_hits = sorted(
        f for f in changed_files if f in ROOT_HARNESS_FILES
    )
    if harness_hits:
        print(
            f"Root harness change ({', '.join(harness_hits)}) — "
            "full tier dispatch (see ROOT_HARNESS_FILES)"
        )
        result = _force_all_dispatch(repo)
        n_all = len(discover_py_files(repo))
        result["_stats"] = {
            "closure": n_all,
            "total": n_all,
            "changed": len(changed_files),
            "dependents": 0,
        }
        return result

    # Dependency manifests reconfigure what every tier installs —
    # full dispatch, same rationale as the harness gate above (see
    # ``is_dependency_manifest``).
    manifest_hits = sorted(
        f for f in changed_files if is_dependency_manifest(f)
    )
    if manifest_hits:
        print(
            f"Dependency manifest change ({', '.join(manifest_hits)}) — "
            "every tier installs from these files; full tier dispatch"
        )
        result = _force_all_dispatch(repo)
        n_all = len(discover_py_files(repo))
        result["_stats"] = {
            "closure": n_all,
            "total": n_all,
            "changed": len(changed_files),
            "dependents": 0,
        }
        return result

    # Deleted / renamed graph-covered modules: the reverse graph is
    # keyed by on-disk files, so a changed .py that no longer exists
    # (a deletion, or the OLD path of a rename) has no key — every
    # importer the change broke drops out of the closure and the
    # ``(repo / f).is_file()`` tier filter then discards the path
    # itself, dispatching ZERO tiers for a PR that breaks its
    # importers. Cannot map → full dispatch, mirroring the harness
    # gate above.
    missing_py = missing_graph_covered_py(
        {Path(f) for f in changed_files if f.endswith(".py")}, repo
    )
    if missing_py:
        print(
            f"Changed Python file(s) missing from disk "
            f"({', '.join(missing_py)}) — deleted or renamed modules "
            "have no import-graph key, so their broken importers "
            "cannot be resolved; failing toward full tier dispatch"
        )
        result = _force_all_dispatch(repo)
        n_all = len(discover_py_files(repo))
        result["_stats"] = {
            "closure": n_all,
            "total": n_all,
            "changed": len(changed_files),
            "dependents": 0,
        }
        return result

    all_py = discover_py_files(repo)
    total = len(all_py)

    changed_py = {Path(f) for f in changed_files if f.endswith(".py")}
    changed_non_py = [f for f in changed_files if not f.endswith(".py")]

    # conftest.py changes affect all tests in their directory tree.
    changed_py |= expand_conftest(changed_py, all_py)

    # __init__.py expansion.
    changed_py |= init_imports(changed_py, all_py)

    print(f"Building import graph for {total} Python files...")
    reverse_graph, parse_failures = build_graph(all_py, repo)
    if parse_failures:
        print(f"  Parse failures: {parse_failures}")

    # Non-Python resource files under the scan roots are runtime
    # inputs (detector data lists, parser packs, templates, fixtures)
    # — a change to them must run the tests of the code that consumes
    # them, not zero tiers. Route each one through the first mapping
    # that claims it; a file NO mapping claims cannot be scoped, so
    # fail toward full dispatch rather than toward zero.
    resource_files = [
        f for f in changed_non_py
        if any(f.startswith(r + "/") for r in SCAN_ROOTS)
    ]
    forced_tiers: set[str] = set()
    resource_seeds: set[Path] = set()
    data_map: dict[Path, set[Path]] | None = None
    unmapped: list[str] = []
    for rf in resource_files:
        rp = Path(rf)
        # (1) Directory ownership: a resource inside a tier's test
        # tree belongs to that tier (packages/sca/data/* → sca).
        tier_hits = {
            name for name, cfg in TIERS.items()
            if any(file_in_dir(rp, d) for d in cfg.get("test_dirs", []))
        }
        if tier_hits:
            forced_tiers |= tier_hits
            continue
        # (2) Fixture data: tests that reference the file's fixture
        # directory (built lazily — it parses every test file).
        if data_map is None:
            data_map = build_data_file_map(
                [f for f in all_py if is_test_file(f)], repo,
            )
        mapped_tests = data_map.get(rp)
        if mapped_tests:
            resource_seeds |= mapped_tests
            continue
        # (3) Owning package: seed the .py files beside the resource
        # and let the import graph find their tests — but only when
        # it actually reaches a test, otherwise the seed proves
        # nothing and the file stays unmapped.
        seeds = _owning_package_seeds(rp, all_py)
        if seeds and any(
            is_test_file(t)
            for t in transitive_dependents(seeds, reverse_graph)
        ):
            resource_seeds |= seeds
            continue
        unmapped.append(rf)
    if unmapped:
        print(
            f"Changed resource file(s) with no owning tests "
            f"({', '.join(sorted(unmapped))}) — cannot scope a runtime "
            "data change to a tier; failing toward full tier dispatch"
        )
        result = _force_all_dispatch(repo)
        result["_stats"] = {
            "closure": total,
            "total": total,
            "changed": len(changed_files),
            "dependents": 0,
        }
        return result
    changed_py |= resource_seeds

    closure = transitive_dependents(changed_py, reverse_graph)

    pct = f"{len(closure) / total * 100:.0f}%" if total else "?"
    print(f"Closure: {len(closure)}/{total} files ({pct})")

    result: dict[str, dict] = {}

    # Per-tier dispatch.
    for tier_name, tier_config in TIERS.items():
        # Check extra_triggers (non-graph paths like .github/scripts).
        extra_triggered = False
        for trigger_dir in tier_config.get("extra_triggers", []):
            if any(f.startswith(trigger_dir + "/") or f == trigger_dir
                   for f in changed_files):
                extra_triggered = True
                break

        if extra_triggered or tier_config.get("outside_graph"):
            # Tier's tests live outside the import graph (e.g. .github/tests).
            # Discover directly from disk and run all of them when triggered.
            triggered = extra_triggered
            tier_files = _discover_tier_files(tier_config, repo)
            # Check trigger_files (explicit file list, e.g. prompt_audit).
            if not triggered:
                trigger_set = set(tier_config.get("trigger_files", []))
                if trigger_set:
                    triggered = any(f in trigger_set for f in changed_files)
            # If not triggered yet, check if any of the tier's own
            # test files are in the changed set.
            if not triggered:
                tier_file_strs = {str(tf) for tf in tier_files}
                triggered = any(
                    f in tier_file_strs for f in changed_files
                )
            result[tier_name] = {"run": triggered, "files": tier_files if triggered else []}
        else:
            affected = [f for f in closure
                        if file_matches_tier(f, tier_config)
                        and is_test_file(f)
                        and (repo / f).is_file()]
            if tier_name in forced_tiers:
                # A changed resource file lives in this tier's tree —
                # the data could drive any of the tier's tests, so run
                # them all (same shape as a full dispatch of the tier).
                affected = sorted(
                    set(affected) | set(_discover_tier_files(tier_config, repo))
                )
            result[tier_name] = {"run": bool(affected), "files": affected}

    # Fast tier: tests in core/ and packages/ that aren't carved out.
    # (Dependency manifests never reach this point — the
    # is_dependency_manifest gate above already forced full dispatch;
    # a fast-tier-only fallback here under-dispatched the carved-out
    # tiers that install from the same files.)
    fast_files = [f for f in closure
                  if file_in_fast_tier(f) and (repo / f).is_file()]
    result["python"] = {
        "run": bool(fast_files),
        "files": fast_files,
        "matrix": batch_matrix(fast_files),
    }

    # NOTE: deps-job gating lives in .github/workflows/tests.yml — it
    # ORs the python/sandbox/exploit_feasibility/sca tier outputs
    # directly. A "_deps" gate computed here was never emitted
    # (_emit_outputs skips underscore-prefixed keys) and read as if
    # this script drove the deps job; the workflow list is the single
    # live one, so no gate is computed here. When adding a venv tier,
    # extend the workflow's OR.
    n_changed = len(changed_py)
    n_dependents = len(closure) - n_changed
    result["_stats"] = {
        "closure": len(closure),
        "total": total,
        "changed": n_changed,
        "dependents": n_dependents,
    }

    return result


def _force_all_dispatch(repo: Path) -> dict[str, dict]:
    """Full dispatch: discover all test files from disk, produce
    complete file lists and matrices for every tier."""
    result: dict[str, dict] = {}

    for tier_name, tier_config in TIERS.items():
        tier_files = _discover_tier_files(tier_config, repo)
        result[tier_name] = {"run": True, "files": tier_files}

    fast_files = _discover_fast_tier_files(repo)
    result["python"] = {
        "run": True,
        "files": fast_files,
        "matrix": batch_matrix(fast_files),
    }
    return result


def _emit_outputs(
    result: dict[str, dict],
    set_output,
) -> None:
    """Write tier gates, file lists, and matrices to GITHUB_OUTPUT."""
    summary_parts = []
    for tier_name in sorted(result):
        if tier_name.startswith("_"):
            continue
        info = result[tier_name]
        gate = "true" if info["run"] else "false"
        set_output(tier_name, gate)
        files = info["files"]
        if files:
            file_list = " ".join(str(f) for f in sorted(files))
            set_output(f"{tier_name}_files", file_list)
            summary_parts.append(f"  {tier_name}: {len(files)} test files")
        else:
            summary_parts.append(f"  {tier_name}: skip")
        # Fast tier: emit the batch matrix as JSON.
        if "matrix" in info:
            set_output(f"{tier_name}_matrix", json.dumps(info["matrix"]))

    print("Tier dispatch:")
    for line in summary_parts:
        print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        help="File listing changed paths, one per line",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository root",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    gh_output = os.environ.get("GITHUB_OUTPUT")

    def set_output(key: str, val: str) -> None:
        if gh_output:
            with open(gh_output, "a", encoding="utf-8") as fh:
                fh.write(f"{key}={val}\n")

    # Full dispatch when no changed-file list is available.
    full_dispatch = False
    changed: list[str] = []

    if not args.changed_files:
        print("::notice::Test scope: full dispatch (no changed-file list)")
        full_dispatch = True
    else:
        cf_path = Path(args.changed_files)
        if not cf_path.is_file():
            print(f"::notice::Test scope: full dispatch (file not found: {cf_path})")
            full_dispatch = True
        else:
            changed = [
                line.strip()
                for line in cf_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            if not changed:
                print("::notice::Test scope: full dispatch (empty changed-file list)")
                full_dispatch = True

    if full_dispatch:
        set_output("scope_mode", "full")
        result = _force_all_dispatch(repo)
        _emit_outputs(result, set_output)
        return 0

    result = compute_tier_dispatch(changed, repo)
    set_output("scope_mode", "scoped")
    _emit_outputs(result, set_output)

    active = sum(1 for t, i in result.items()
                 if not t.startswith("_") and i["run"])
    total_tiers = len([t for t in result if not t.startswith("_")])
    stats = result.get("_stats", {})
    closure_n = stats.get("closure", 0)
    total_files = stats.get("total", 0)
    n_changed = stats.get("changed", 0)
    n_deps = stats.get("dependents", 0)
    pct = f"{closure_n / total_files * 100:.0f}%" if total_files else "?"
    notice = (f"scoped to {closure_n}/{total_files} files ({pct})"
              f" — {n_changed} changed, {n_deps} dependents"
              f"; {active}/{total_tiers} tiers active")
    print(f"::notice::Test scope: {notice}")
    set_output("scope_summary", notice)

    return 0


if __name__ == "__main__":
    sys.exit(main())
