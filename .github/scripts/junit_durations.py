"""Convert pytest junit XML into duration maps for CI batching.

Default mode writes the per-FILE map consumed by test_scope.py's
duration-aware ``batch_matrix()`` (env ``RAPTOR_TEST_DURATIONS``):

    {"core/llm/tests/test_client.py": 12.34, ...}

``--nodeids`` writes the per-TEST map pytest-split consumes via
``--durations-path`` (e.g. packages/sca/test-durations.json):

    {"packages/sca/tests/test_x.py::TestC::test_a[case]": 0.12, ...}

Classname → path mapping is derived from how this repo's pytest emits
junit (xunit2): ``classname`` is the dotted module path plus zero or
more nested class names ("packages.sca.tests.test_x.TestC"); rows
skipped at collection time carry an EMPTY classname and put the dotted
module path in ``name`` instead. A dotted string resolves to the
longest prefix that is a ``.py`` file on disk under ``--repo`` —
trailing class components fall away naturally, and module directories
never shadow (a package dir has no ``.py`` suffix). Unresolvable rows
(deleted/renamed modules from an old run) are dropped and counted in
the summary line, never guessed.

Aggregation across multiple XML inputs is the MEAN of each file's
per-run total (per-run sum of its testcases), computed over the runs
in which the file appears — a file added after an older run is not
diluted by absence. Per-nodeid mode averages the same way.

Usage:
    python3 .github/scripts/junit_durations.py <out.json> <junit.xml>...
    python3 .github/scripts/junit_durations.py --nodeids \\
        --prefix packages/sca <out.json> <junit.xml>...
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


def resolve_classname(dotted: str, repo: Path) -> tuple[str, list[str]] | None:
    """(repo-relative file path, trailing class components) for a
    junit dotted name, or None when no prefix is a file on disk."""
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        candidate = "/".join(parts[:i]) + ".py"
        if (repo / candidate).is_file():
            return candidate, parts[i:]
    return None


def collect_run(
    xml_path: Path, repo: Path,
) -> tuple[dict[str, float], dict[str, float], int]:
    """One junit XML → (per-file totals, per-nodeid times, dropped count)."""
    per_file: dict[str, float] = defaultdict(float)
    per_nodeid: dict[str, float] = defaultdict(float)
    dropped = 0
    root = ET.parse(xml_path).getroot()
    for tc in root.iter("testcase"):
        classname = tc.get("classname") or ""
        name = tc.get("name") or ""
        try:
            seconds = float(tc.get("time") or 0.0)
        except ValueError:
            dropped += 1
            continue
        if classname:
            resolved = resolve_classname(classname, repo)
        elif name:
            # Collection-skip rows: module dotted path rides in name.
            resolved = resolve_classname(name, repo)
            name = ""
        else:
            resolved = None
        if resolved is None:
            dropped += 1
            continue
        file_path, classes = resolved
        per_file[file_path] += seconds
        if name:
            nodeid = "::".join([file_path, *classes, name])
            per_nodeid[nodeid] += seconds
    return dict(per_file), dict(per_nodeid), dropped


def mean_across_runs(runs: list[dict[str, float]]) -> dict[str, float]:
    """Per-key mean over the runs in which the key appears."""
    sums: dict[str, float] = defaultdict(float)
    counts: dict[str, int] = defaultdict(int)
    for run in runs:
        for key, seconds in run.items():
            sums[key] += seconds
            counts[key] += 1
    return {key: sums[key] / counts[key] for key in sums}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", help="Output JSON path")
    parser.add_argument("xml", nargs="+", help="pytest junit XML input(s)")
    parser.add_argument(
        "--repo", default=".",
        help="Repository root used to resolve dotted names to files",
    )
    parser.add_argument(
        "--nodeids", action="store_true",
        help="Emit per-test nodeid→seconds (pytest-split format) "
             "instead of per-file totals",
    )
    parser.add_argument(
        "--prefix", default="",
        help="Keep only entries whose path starts with this repo-relative "
             "prefix (e.g. packages/sca)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    file_runs: list[dict[str, float]] = []
    nodeid_runs: list[dict[str, float]] = []
    total_dropped = 0
    for xml_path in args.xml:
        per_file, per_nodeid, dropped = collect_run(Path(xml_path), repo)
        file_runs.append(per_file)
        nodeid_runs.append(per_nodeid)
        total_dropped += dropped

    merged = mean_across_runs(nodeid_runs if args.nodeids else file_runs)
    if args.prefix:
        merged = {
            k: v for k, v in merged.items()
            if k == args.prefix or k.startswith(args.prefix.rstrip("/") + "/")
        }
    if not merged:
        print(
            "junit_durations: zero entries resolved — wrong --repo root "
            "or empty junit input; refusing to write an empty map",
            file=sys.stderr,
        )
        return 1

    out_path = Path(args.out)
    out_path.write_text(
        json.dumps(dict(sorted(merged.items())), indent=4) + "\n",
        encoding="utf-8",
    )
    kind = "nodeid" if args.nodeids else "file"
    print(
        f"junit_durations: wrote {len(merged)} {kind} entries to "
        f"{out_path} ({total_dropped} unresolvable row(s) dropped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
