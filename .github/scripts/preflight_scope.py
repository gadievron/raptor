#!/usr/bin/env python3
r"""Changed-test-file scoper for the PR preflight workflow.

test_scope.py answers "which tests does this change AFFECT?" (reverse
import graph, per-tier dispatch). The preflight asks a narrower
question: "which test files does this PR ITSELF touch?" — those are the
files re-run under the CI-reality simulations (hidden optional deps,
duration guard, shuffled order, tree hygiene), and bounding the run to
them keeps PR latency flat. Reuses ``test_scope.is_test_file`` so the
two scopers cannot disagree about what counts as a test file.

Deliberately excluded:
  * conftest.py — not directly runnable; its blast radius is covered
    by the main suite's dispatch (nested conftests expand to their
    directory tree; the repo-root conftest.py and pytest.ini force a
    full tier dispatch via ``test_scope.ROOT_HARNESS_FILES``);
  * deleted / renamed-away files (in the change list, absent on disk);
  * ``fixtures/`` trees and non-Python files (``is_test_file``).

CI uses --base to select the complete Git range and emits only run=true|false.
Unknown Git history fails selection rather than skipping the simulations.
--run passes the selected paths directly to pytest in this interpreter, so
filenames never travel through job outputs, environment variables or exec
arguments. Empty selections never invoke pytest with an unbounded target.

The legacy --changed-files line-list interface also emits a space-separated
``test_files`` output. Its missing/empty lists still skip for compatibility;
CI does not use that interface. No mode falls back to the entire suite.

Usage:
    python3 .github/scripts/preflight_scope.py \
        --changed-files /tmp/changed_files.txt --repo .
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_caller_path = sys.path
try:
    sys.path = [str(Path(__file__).resolve().parent), *_caller_path]
    from ci_change_scope import changed_paths
    from test_scope import is_test_file
finally:
    sys.path = _caller_path


def changed_test_files(changed: list[str], repo: Path) -> list[str]:
    """Filter a changed-path list to existing, runnable test files."""
    keep = set()
    for entry in changed:
        path = Path(entry)
        if path.name == "conftest.py":
            continue
        if not is_test_file(path):
            continue
        if not (repo / path).is_file():
            continue
        keep.add(str(path))
    return sorted(keep)


def run_tests(files: list[str], repo: Path) -> int:
    """Use pytest's argument-list API without an exec/environment size limit."""
    caller_path = sys.path
    caller_cwd = Path.cwd()
    try:
        sys.path = [str(repo), *caller_path]
        os.chdir(repo)
        import pytest
        return int(pytest.main(files))
    finally:
        sys.path = caller_path
        os.chdir(caller_cwd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scope the PR preflight to the changed test files."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--base", help="Immutable PR base commit (complete Git range)")
    source.add_argument(
        "--changed-files",
        help="File listing changed paths, one per line",
    )
    parser.add_argument("--repo", default=".", help="Repository root")
    parser.add_argument("--run", action="store_true", help="Run the selected files with pytest")
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()

    changed: list[str] = []
    if args.base is not None:
        selected = changed_paths(repo, args.base)
        if selected is None:
            print("Preflight scope: cannot determine complete Git changes; "
                  "refusing to skip simulations on unknown history", file=sys.stderr)
            return 2
        changed = selected
    elif args.changed_files:
        cf_path = Path(args.changed_files)
        if cf_path.is_file():
            changed = [
                line.strip()
                for line in cf_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

    files = changed_test_files(changed, repo)

    gh_output = os.environ.get("GITHUB_OUTPUT")

    def set_output(key: str, val: str) -> None:
        if gh_output:
            with open(gh_output, "a", encoding="utf-8") as fh:
                fh.write(f"{key}={val}\n")

    set_output("run", "true" if files else "false")
    if args.base is None:
        set_output("test_files", " ".join(files))

    if files:
        print(f"Preflight scope: {len(files)} changed test file(s):")
        for f in files:
            print(f"  {f}")
    else:
        print("Preflight scope: no changed test files — preflight skips")
    if args.run and files:
        return run_tests(files, repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
