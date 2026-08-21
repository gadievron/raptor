#!/usr/bin/env python3
"""Changed-test-file scoper for the PR preflight workflow.

test_scope.py answers "which tests does this change AFFECT?" (reverse
import graph, per-tier dispatch). The preflight asks a narrower
question: "which test files does this PR ITSELF touch?" — those are the
files re-run under the CI-reality simulations (hidden optional deps,
duration guard, shuffled order, tree hygiene), and bounding the run to
them keeps PR latency flat. Reuses ``test_scope.is_test_file`` so the
two scopers cannot disagree about what counts as a test file.

Deliberately excluded:
  * conftest.py — not directly runnable; its blast radius is already
    covered by the main suite's import-graph dispatch;
  * deleted / renamed-away files (in the change list, absent on disk);
  * ``fixtures/`` trees and non-Python files (``is_test_file``).

Outputs to GITHUB_OUTPUT:
  run=true|false     whether any changed test file survives the filter
  test_files=<paths> space-separated, sorted

A missing changed-file list, an empty list, or no surviving test files
all produce ``run=false`` — the preflight then skips cleanly. There is
no full-dispatch fallback on purpose: running the entire suite under
every simulation is exactly the latency the changed-file bound avoids.

Usage:
    python3 .github/scripts/preflight_scope.py \\
        --changed-files /tmp/changed_files.txt --repo .
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_scope import is_test_file


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scope the PR preflight to the changed test files."
    )
    parser.add_argument(
        "--changed-files",
        help="File listing changed paths, one per line",
    )
    parser.add_argument("--repo", default=".", help="Repository root")
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()

    changed: list[str] = []
    if args.changed_files:
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
    set_output("test_files", " ".join(files))

    if files:
        print(f"Preflight scope: {len(files)} changed test file(s):")
        for f in files:
            print(f"  {f}")
    else:
        print("Preflight scope: no changed test files — preflight skips")
    return 0


if __name__ == "__main__":
    sys.exit(main())
