"""Evaluate file-level test impact analysis.

Builds the import graph, computes affected test files from a changeset,
and reports what would run vs what the current tier system runs.  Use
this to evaluate whether file-level selection can replace tier-based
test dispatch.

Usage:
    # What tests would a specific file change trigger?
    python3 .github/scripts/test_impact.py core/config/__init__.py

    # What tests does the current working-tree diff need?
    python3 .github/scripts/test_impact.py --diff

    # What tests does a range of commits need?
    python3 .github/scripts/test_impact.py --diff origin/main..HEAD

    # Compare file-level vs tier-level selection
    python3 .github/scripts/test_impact.py --diff --compare

    # Show the full affected-file closure (not just tests)
    python3 .github/scripts/test_impact.py --diff --closure

    # JSON output for tooling
    python3 .github/scripts/test_impact.py --diff --json

    # Skip graph cache (force rebuild)
    python3 .github/scripts/test_impact.py --diff --no-cache
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json as json_mod
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codeql_scope import (
    build_graph,
    discover_py_files,
    init_imports,
    transitive_dependents,
)
from test_scope import (
    TIERS,
    file_in_fast_tier,
    file_matches_tier,
    is_test_file,
)

_EXTRA_ROOTS = (".github",)


def _env_groups_from_tiers() -> dict[str, dict[str, str]]:
    """Derive environment groups from TIERS metadata."""
    groups: dict[str, dict[str, str]] = {}
    for tier_config in TIERS.values():
        env = tier_config.get("env")
        if not env:
            continue
        groups[env] = {
            "dirs": tier_config.get("test_dirs", []),
            "reason": tier_config.get("env_reason", ""),
        }
    return groups


def classify_env(path: Path, env_groups: dict[str, dict]) -> str:
    """Map a test file to its environment group."""
    s = str(path)
    for group, cfg in env_groups.items():
        for d in cfg["dirs"]:
            if s == d or s.startswith(d + "/"):
                return group
    return "standard"


def get_changed_files_from_diff(diff_spec: str | None) -> list[str]:
    """Get changed files from git diff (staged + unstaged)."""
    cmd = ["git", "diff", "--name-only"]
    if diff_spec:
        cmd.append(diff_spec)
    else:
        cmd.append("HEAD")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"git diff failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return [f for f in result.stdout.strip().splitlines() if f.strip()]


def tier_for_file(path: Path) -> str | None:
    """Which CI tier would run this test file?"""
    for tier_name, tier_config in TIERS.items():
        if file_matches_tier(path, tier_config):
            return tier_name
    if file_in_fast_tier(path):
        return "python (fast)"
    return None


def tier_test_count(
    repo: Path,
    slow_files: set[Path],
) -> dict[str, int]:
    """Count total non-slow test files per tier."""
    counts: dict[str, int] = defaultdict(int)
    for p in discover_py_files(repo, extra_roots=_EXTRA_ROOTS):
        if not is_test_file(p) or p in slow_files:
            continue
        tier = tier_for_file(p)
        if tier:
            counts[tier] += 1
    return dict(counts)


# -- Data-file dependencies ------------------------------------------------

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


# -- Slow-test detection --------------------------------------------------

def _is_entirely_slow(path: Path, repo: Path) -> bool:
    """True if a test file is module-level marked as slow.

    Detects ``pytestmark = pytest.mark.slow`` and list forms like
    ``pytestmark = [pytest.mark.slow, ...]``.
    """
    try:
        source = (repo / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if "slow" not in source:
        return False
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return False
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == "pytestmark"
            for t in node.targets
        ):
            continue
        val_src = ast.get_source_segment(source, node.value) or ""
        if "slow" in val_src:
            return True
    return False


def detect_slow_files(test_files: list[Path], repo: Path) -> set[Path]:
    """Return the subset that are entirely slow-marked."""
    return {f for f in test_files if _is_entirely_slow(f, repo)}


# -- Graph caching ---------------------------------------------------------

def _cache_path(repo: Path) -> Path:
    repo_hash = hashlib.md5(str(repo).encode()).hexdigest()[:12]
    return Path(f"/tmp/raptor-test-impact-{repo_hash}.json")


def _files_fingerprint(py_files: list[Path], repo: Path) -> str:
    """Hash of (path, mtime_ns) for cache invalidation."""
    entries = []
    for f in sorted(py_files):
        try:
            st = (repo / f).stat()
            entries.append(f"{f}\0{st.st_mtime_ns}")
        except OSError:
            entries.append(f"{f}\0missing")
    return hashlib.md5("\n".join(entries).encode()).hexdigest()


def _load_cached_graph(
    cache_file: Path, fingerprint: str,
) -> tuple[dict[Path, set[Path]], int] | None:
    try:
        data = json_mod.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json_mod.JSONDecodeError):
        return None
    if data.get("version") != 1 or data.get("fingerprint") != fingerprint:
        return None
    reverse: dict[Path, set[Path]] = {}
    for k, vs in data.get("reverse_graph", {}).items():
        reverse[Path(k)] = {Path(v) for v in vs}
    return reverse, data.get("parse_failures", 0)


def _save_graph_cache(
    cache_file: Path,
    fingerprint: str,
    reverse: dict[Path, set[Path]],
    parse_failures: int,
) -> None:
    data = {
        "version": 1,
        "fingerprint": fingerprint,
        "parse_failures": parse_failures,
        "reverse_graph": {
            str(k): sorted(str(v) for v in vs)
            for k, vs in reverse.items()
        },
    }
    try:
        cache_file.write_text(
            json_mod.dumps(data, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError:
        pass


# -- Test duration loading -------------------------------------------------

def _load_test_durations(repo: Path) -> dict[str, float] | None:
    """Load pytest-split durations and aggregate by file."""
    for name in (".test_durations", "test_durations"):
        dur_path = repo / name
        if dur_path.is_file():
            break
    else:
        return None
    try:
        raw = json_mod.loads(dur_path.read_text(encoding="utf-8"))
    except (OSError, json_mod.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    per_file: dict[str, float] = defaultdict(float)
    for node_id, duration in raw.items():
        if not isinstance(duration, (int, float)):
            continue
        file_part = node_id.split("::")[0]
        per_file[file_part] += duration
    return dict(per_file) if per_file else None


def _file_duration(
    path: Path, durations: dict[str, float] | None,
) -> float:
    if durations is None:
        return 0.0
    return durations.get(str(path), 0.0)


def _fmt_duration(seconds: float) -> str:
    if seconds >= 60:
        return f"{seconds / 60:.1f}m"
    return f"{seconds:.1f}s"


# -- Main ------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Changed files to analyse (relative to repo root)",
    )
    parser.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="RANGE",
        help="Use git diff to find changed files (optionally with a range)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare file-level selection against tier-level selection",
    )
    parser.add_argument(
        "--closure",
        action="store_true",
        help="Show all affected files, not just tests",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Force graph rebuild (ignore cache)",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository root (default: .)",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    env_groups = _env_groups_from_tiers()

    # Collect changed files.
    if args.diff is not None:
        changed = get_changed_files_from_diff(args.diff or None)
    elif args.files:
        changed = args.files
    else:
        parser.print_help()
        return 1

    if not changed:
        print("No changed files.")
        return 0

    changed_py = {Path(f) for f in changed if f.endswith(".py")}
    changed_non_py = [f for f in changed if not f.endswith(".py")]

    # Build graph (with caching).
    t0 = time.monotonic()
    all_py = discover_py_files(repo, extra_roots=_EXTRA_ROOTS)
    total_files = len(all_py)

    cache_file = _cache_path(repo)
    fingerprint = _files_fingerprint(all_py, repo)
    cached = None if args.no_cache else _load_cached_graph(cache_file, fingerprint)

    if cached is not None:
        reverse_graph, parse_failures = cached
        cache_status = "hit"
    else:
        reverse_graph, parse_failures = build_graph(all_py, repo)
        _save_graph_cache(cache_file, fingerprint, reverse_graph, parse_failures)
        cache_status = "miss"
    graph_time = time.monotonic() - t0

    # conftest.py changes affect all tests in their directory tree.
    conftest_extra: set[Path] = set()
    for f in list(changed_py):
        if f.name == "conftest.py":
            pkg_dir = f.parent
            for af in all_py:
                if af != f and str(af).startswith(str(pkg_dir) + "/"):
                    conftest_extra.add(af)
    changed_py |= conftest_extra

    changed_py |= init_imports(changed_py, all_py)

    # Compute closure.
    closure = transitive_dependents(changed_py, reverse_graph)

    # Outside-graph tiers: prompt_audit and ci_lint have trigger_files
    # or extra_triggers that the import graph can't see.
    outside_tests: set[Path] = set()
    for _tier_name, tier_config in TIERS.items():
        if not tier_config.get("outside_graph"):
            continue
        triggered = False
        for trigger_dir in tier_config.get("extra_triggers", []):
            if any(f.startswith(trigger_dir + "/") or f == trigger_dir
                   for f in changed):
                triggered = True
                break
        if not triggered:
            trigger_set = set(tier_config.get("trigger_files", []))
            if trigger_set and any(f in trigger_set for f in changed):
                triggered = True
        if not triggered:
            for f in changed:
                if file_matches_tier(Path(f), tier_config):
                    triggered = True
                    break
        if triggered:
            for d in tier_config.get("test_dirs", []):
                dir_path = repo / d
                if dir_path.is_dir():
                    for p in dir_path.rglob("*.py"):
                        rp = p.relative_to(repo)
                        if is_test_file(rp):
                            outside_tests.add(rp)
            for f in tier_config.get("test_files", []):
                fp = Path(f)
                if (repo / fp).is_file() and is_test_file(fp):
                    outside_tests.add(fp)

    # Non-Python infrastructure changes trigger the full fast tier.
    infra_triggered = any(
        f.startswith("requirements") or f == "pyproject.toml"
        for f in changed_non_py
    )

    # Data-file dependencies: if a fixture file changed, pull in
    # the test files that reference its directory.
    all_test_py = [f for f in all_py if is_test_file(f)]
    data_map = build_data_file_map(all_test_py, repo)
    data_triggered: set[Path] = set()
    changed_all = set(changed)
    for data_file, test_files in data_map.items():
        if str(data_file) in changed_all:
            data_triggered |= test_files

    # Collect candidate tests.
    all_affected = closure | outside_tests | data_triggered
    candidate_tests = sorted(
        f for f in all_affected
        if is_test_file(f) and f.name != "conftest.py"
    )
    if infra_triggered:
        for af in all_py:
            if file_in_fast_tier(af) and af not in all_affected:
                candidate_tests.append(af)
        candidate_tests = sorted(set(candidate_tests))

    # Exclude entirely-slow test files.
    slow_files = detect_slow_files(candidate_tests, repo)
    affected_tests = [f for f in candidate_tests if f not in slow_files]
    affected_source = sorted(f for f in all_affected if not is_test_file(f))

    # Load durations for time-weighted comparison.
    durations = _load_test_durations(repo)

    # Group tests by environment.
    by_env: dict[str, list[Path]] = defaultdict(list)
    for t in affected_tests:
        by_env[classify_env(t, env_groups)].append(t)

    if args.json:
        output: dict = {
            "changed_files": sorted(str(f) for f in changed_py) + changed_non_py,
            "graph_build_seconds": round(graph_time, 2),
            "graph_cache": cache_status,
            "total_python_files": total_files,
            "closure_size": len(closure),
            "slow_excluded": len(slow_files),
            "affected_tests": [str(t) for t in affected_tests],
            "affected_source": [str(s) for s in affected_source],
            "by_environment": {
                env: [str(t) for t in tests]
                for env, tests in sorted(by_env.items())
            },
        }
        if args.compare:
            tier_totals = tier_test_count(repo, slow_files)
            triggered_tiers: dict[str, list[str]] = defaultdict(list)
            for t in affected_tests:
                tier = tier_for_file(t)
                if tier:
                    triggered_tiers[tier].append(str(t))
            total_tier = sum(tier_totals.get(t, 0) for t in triggered_tiers)
            total_affected = len(affected_tests)
            comparison: dict = {
                "tier_totals": tier_totals,
                "triggered_tiers": {
                    tier: {
                        "affected": len(files),
                        "tier_total": tier_totals.get(tier, 0),
                    }
                    for tier, files in sorted(triggered_tiers.items())
                },
                "total_tier_tests": total_tier,
                "total_affected_tests": total_affected,
                "savings_percent": round(
                    (1 - total_affected / max(1, total_tier)) * 100, 1,
                ),
            }
            if durations:
                aff_dur = sum(_file_duration(Path(f), durations)
                              for f in affected_tests)
                tier_dur = sum(
                    sum(_file_duration(Path(f), durations)
                        for f in discover_py_files(repo, extra_roots=_EXTRA_ROOTS)
                        if is_test_file(f) and f not in slow_files
                        and tier_for_file(f) == tier)
                    for tier in triggered_tiers
                )
                comparison["affected_duration_s"] = round(aff_dur, 1)
                comparison["tier_duration_s"] = round(tier_dur, 1)
                if tier_dur > 0:
                    comparison["duration_savings_percent"] = round(
                        (1 - aff_dur / tier_dur) * 100, 1,
                    )
            output["comparison"] = comparison
        print(json_mod.dumps(output, indent=2))
        return 0

    # Text output.
    print(f"Graph: {total_files} Python files, built in {graph_time:.1f}s"
          f" ({parse_failures} parse failures, cache {cache_status})")
    print(f"Changed: {len(changed_py)} Python files"
          + (f", {len(changed_non_py)} non-Python" if changed_non_py else ""))
    print(f"Closure: {len(closure)} files "
          f"({len(closure) / max(1, total_files) * 100:.0f}% of codebase)")
    print(f"Affected tests: {len(affected_tests)}"
          + (f" ({len(slow_files)} slow-only files excluded)"
             if slow_files else ""))
    print()

    if args.closure:
        print("=== Affected source files ===")
        for s in affected_source:
            print(f"  {s}")
        print()

    print("=== Affected tests by environment ===")
    for env in sorted(by_env):
        tests = by_env[env]
        label = env
        reason = env_groups.get(env, {}).get("reason", "")
        if reason:
            label += f"  ({reason})"
        print(f"\n  {label}: {len(tests)} tests")
        for t in tests:
            dur = _file_duration(t, durations)
            suffix = f"  ({_fmt_duration(dur)})" if dur > 0 else ""
            print(f"    {t}{suffix}")

    # Emit pytest commands.
    seed = int(time.monotonic() * 1000) % 2**31
    print("\n=== Pytest commands ===")
    print(f"  # Set RAPTOR_RANDOMISE_TESTS={seed} to randomise test order")
    for env in sorted(by_env):
        tests = by_env[env]
        if not tests:
            continue
        file_args = " ".join(str(t) for t in tests)
        if env == "standard":
            print(f"\n  # Standard environment ({len(tests)} files)")
        else:
            print(f"\n  # {env} ({len(tests)} files)")
        print(f"  pytest -m \"not slow\" {file_args}")

    if args.compare:
        _print_comparison(repo, affected_tests, slow_files, durations)

    return 0


def _print_comparison(
    repo: Path,
    affected_tests: list[Path],
    slow_files: set[Path],
    durations: dict[str, float] | None,
) -> None:
    print("\n=== Tier comparison ===")
    tier_totals = tier_test_count(repo, slow_files)
    triggered_tiers: dict[str, list[Path]] = defaultdict(list)
    for t in affected_tests:
        tier = tier_for_file(t)
        if tier:
            triggered_tiers[tier].append(t)

    has_dur = durations is not None
    if has_dur:
        hdr = (f"  {'Tier':<28} {'Affected':>8} {'Total':>8}"
               f" {'Saving':>8}  {'Time aff.':>9} {'Time tot.':>9}"
               f" {'Time sav.':>9}")
        sep = f"  {'-' * 28} {'-' * 8} {'-' * 8} {'-' * 8}  " \
              f"{'-' * 9} {'-' * 9} {'-' * 9}"
    else:
        hdr = f"  {'Tier':<28} {'Affected':>8} {'Total':>8} {'Saving':>8}"
        sep = f"  {'-' * 28} {'-' * 8} {'-' * 8} {'-' * 8}"
    print(f"\n{hdr}")
    print(sep)

    total_tier_would_run = 0
    total_tier_dur = 0.0
    total_aff_dur = 0.0

    all_py = discover_py_files(repo, extra_roots=_EXTRA_ROOTS)

    for tier in sorted(triggered_tiers):
        affected = len(triggered_tiers[tier])
        total = tier_totals.get(tier, 0)
        total_tier_would_run += total
        saving = total - affected
        pct = (saving / max(1, total)) * 100

        if has_dur:
            aff_d = sum(_file_duration(f, durations) for f in triggered_tiers[tier])
            tier_d = sum(
                _file_duration(f, durations)
                for f in all_py
                if is_test_file(f)
                and f not in slow_files
                and tier_for_file(f) == tier
            )
            total_aff_dur += aff_d
            total_tier_dur += tier_d
            dur_save = tier_d - aff_d
            dur_pct = (dur_save / max(0.001, tier_d)) * 100
            print(f"  {tier:<28} {affected:>8} {total:>8}"
                  f" {saving:>5} ({pct:2.0f}%)"
                  f"  {_fmt_duration(aff_d):>9} {_fmt_duration(tier_d):>9}"
                  f" {_fmt_duration(dur_save):>6} ({dur_pct:2.0f}%)")
        else:
            print(f"  {tier:<28} {affected:>8} {total:>8}"
                  f" {saving:>5} ({pct:.0f}%)")

    total_affected = len(affected_tests)
    if total_tier_would_run > 0:
        overall = total_tier_would_run - total_affected
        overall_pct = (overall / total_tier_would_run) * 100
        print(f"\n  Total: {total_affected} tests (file-level) vs "
              f"{total_tier_would_run} tests (tier-level)")
        print(f"  Saving: {overall} tests ({overall_pct:.0f}%)")
        if has_dur and total_tier_dur > 0:
            dur_overall = total_tier_dur - total_aff_dur
            dur_overall_pct = (dur_overall / total_tier_dur) * 100
            print(f"  Time: {_fmt_duration(total_aff_dur)} (file-level) vs "
                  f"{_fmt_duration(total_tier_dur)} (tier-level)")
            print(f"  Time saving: {_fmt_duration(dur_overall)}"
                  f" ({dur_overall_pct:.0f}%)")


if __name__ == "__main__":
    sys.exit(main())
