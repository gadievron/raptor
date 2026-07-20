"""Import-graph-based test dispatch for PR builds.

Replaces the manually-maintained glob lists in compute_filters.py's
subsystem filters.  Builds the same reverse import graph as
codeql_scope.py, computes the transitive closure from the changed-
file set, then maps affected test files to their CI tier.

Each tier still exists as a separate CI job (for runner selection,
dependency installation, and parallelism), but the gate condition
is now "does the graph show affected test files in this tier?"
instead of "did a glob match?"

Outputs to GITHUB_OUTPUT:
  - tier_<name>=true|false       per-tier gate
  - tier_<name>_files=<paths>    space-separated affected test files
  - scope_mode=scoped|full       for observability
  - scope_summary=<text>         human-readable summary

Usage:
    python3 .github/scripts/test_scope.py \
        --changed-files /tmp/changed_files.txt \
        --repo .
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codeql_scope import (
    build_graph,
    discover_py_files,
    init_imports,
    transitive_dependents,
)


TIERS: dict[str, dict] = {
    "sandbox": {
        "test_dirs": ["core/sandbox/tests"],
    },
    "exploit_feasibility": {
        "test_dirs": ["packages/exploit_feasibility/tests"],
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
            "packages/codeql/build_detector.py",
            "packages/web/fuzzer.py",
            "packages/autonomous/dialogue.py",
            "core/llm/multi_model/prompt_helpers.py",
            "packages/cve_diff/cve_diff/agent/loop.py",
            "packages/cve_diff/cve_diff/agent/prompt.py",
            "packages/cve_diff/cve_diff/analysis/analyzer.py",
        ],
        "outside_graph": True,
    },
    "ci_lint": {
        "test_dirs": [".github/tests"],
        "extra_triggers": [".github/scripts"],
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


def is_test_file(path: Path) -> bool:
    """Heuristic: a .py file is a test if its name starts with test_ or
    ends with _test, or it lives under a tests/ directory."""
    if not path.name.endswith(".py"):
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


def compute_tier_dispatch(
    changed_files: list[str],
    repo: Path,
) -> dict[str, dict]:
    """Compute per-tier dispatch from the changed-file list.

    Returns {tier_name: {"run": bool, "files": [Path, ...]}}.
    """
    all_py = discover_py_files(repo)
    total = len(all_py)

    changed_py = {Path(f) for f in changed_files if f.endswith(".py")}
    changed_non_py = [f for f in changed_files if not f.endswith(".py")]

    # conftest.py changes affect all tests in their directory tree.
    conftest_extra: set[Path] = set()
    for f in changed_py:
        if f.name == "conftest.py":
            pkg_dir = f.parent
            for af in all_py:
                if af != f and str(af).startswith(str(pkg_dir) + "/"):
                    conftest_extra.add(af)
    changed_py |= conftest_extra

    # __init__.py expansion.
    changed_py |= init_imports(changed_py, all_py)

    print(f"Building import graph for {total} Python files...")
    reverse_graph, parse_failures = build_graph(all_py, repo)
    if parse_failures:
        print(f"  Parse failures: {parse_failures}")

    closure = transitive_dependents(changed_py, reverse_graph)

    print(f"Closure: {len(closure)}/{total} files "
          f"({len(closure) / total * 100:.0f}%)")

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
            tier_files = []
            for d in tier_config.get("test_dirs", []):
                dir_path = repo / d
                if dir_path.is_dir():
                    for p in dir_path.rglob("*.py"):
                        rp = p.relative_to(repo)
                        if is_test_file(rp):
                            tier_files.append(rp)
            for f in tier_config.get("test_files", []):
                fp = Path(f)
                if (repo / fp).is_file() and is_test_file(fp):
                    tier_files.append(fp)
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
                        if file_matches_tier(f, tier_config) and is_test_file(f)]
            result[tier_name] = {"run": bool(affected), "files": affected}

    # Fast tier: tests in core/ and packages/ that aren't carved out.
    fast_files = [f for f in closure if file_in_fast_tier(f)]
    # Also trigger fast tier for non-Python changes that affect the
    # test infrastructure (requirements, pyproject.toml, etc.).
    infra_changed = any(
        f.startswith("requirements") or f == "pyproject.toml"
        for f in changed_non_py
    )
    result["python"] = {
        "run": bool(fast_files) or infra_changed,
        "files": fast_files,
    }

    # The deps job should run if any tier with a venv needs to run.
    venv_tiers = {"python", "sandbox", "exploit_feasibility", "sca"}
    deps_needed = any(
        result.get(t, {}).get("run", False) for t in venv_tiers
    )
    result["_deps"] = {"run": deps_needed, "files": []}

    return result


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

    # Load changed files.
    def force_all() -> None:
        for tier_name in list(TIERS) + ["python"]:
            set_output(tier_name, "true")

    if not args.changed_files:
        print("::notice::Test scope: full dispatch (no changed-file list)")
        set_output("scope_mode", "full")
        force_all()
        return 0

    cf_path = Path(args.changed_files)
    if not cf_path.is_file():
        print(f"::notice::Test scope: full dispatch (file not found: {cf_path})")
        set_output("scope_mode", "full")
        force_all()
        return 0

    changed = [
        line.strip()
        for line in cf_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not changed:
        print("::notice::Test scope: full dispatch (empty changed-file list)")
        set_output("scope_mode", "full")
        force_all()
        return 0

    result = compute_tier_dispatch(changed, repo)
    set_output("scope_mode", "scoped")

    summary_parts = []
    for tier_name in sorted(result):
        if tier_name.startswith("_"):
            continue
        info = result[tier_name]
        gate = "true" if info["run"] else "false"
        # Output names match tests.yml's existing output names
        # (no prefix) so tier jobs don't need condition changes.
        set_output(tier_name, gate)
        files = info["files"]
        if files:
            file_list = " ".join(str(f) for f in sorted(files))
            set_output(f"{tier_name}_files", file_list)
            summary_parts.append(f"  {tier_name}: {len(files)} test files")
        else:
            summary_parts.append(f"  {tier_name}: skip")

    print("Tier dispatch:")
    for line in summary_parts:
        print(line)

    active = sum(1 for t, i in result.items()
                 if not t.startswith("_") and i["run"])
    total_tiers = len([t for t in result if not t.startswith("_")])
    notice = f"{active}/{total_tiers} tiers active"
    print(f"::notice::Test scope: {notice}")
    set_output("scope_summary", notice)

    return 0


if __name__ == "__main__":
    sys.exit(main())
