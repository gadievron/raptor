#!/usr/bin/env python3
"""Review partition-closure gate — every reviewable file owned exactly once.

A full review is only as good as its partition: compressed unit labels have
repeatedly shed whole directories, leaving files — including files CHANGED
since the previous review base — reviewed by nobody. This gate proves the
partition mechanically:

1. CLOSURE — every reviewable file is claimed by exactly one unit
   (unclaimed = a partition hole; multi-claimed = an ownership conflict).
2. LIVENESS — every map token matches at least one reviewable file (a dead
   token is a typo or a directory that quietly vanished; blanket carries must
   enumerate real directories, so each enumerated entry is checked).
3. CHANGED-FILE COVERAGE — every file changed since the previous review base
   is claimed, and its owning unit is printed as a ``REVIEW <unit>\\t<file>``
   flag line so the unit is dispatched with the change in scope. A changed
   file with no owner is the classic drop shape and fails the gate.

Unit map format (``--map``), one claim set per line, repeatable per unit:

    # comment (full-line or trailing)
    U08: packages/sca/ test/data/sca-e2e/
    U30: core/sentinels/ core/status/ core/__init__.py
    U33: docs/*.md

Tokens: ``dir/`` claims every file under the directory; a token containing
``*``/``?``/``[`` is an fnmatch glob over full repo-relative paths (note:
fnmatch ``*`` crosses ``/``); anything else is an exact file path.

File universes come from git or from explicit lists (lists win when both are
given; ``--files-from``/``--changed-from`` read one path per line, blank lines
and ``#`` comments ignored):

    --tree DIR [--changed-since REV]     # git ls-files / git diff --name-only
    --files-from LIST --changed-from LIST

Changed files no longer present in the reviewable set (deleted or excluded)
are reported as informational, not errors. ``--exclude GLOB`` (repeatable)
removes vendored/out-of-scope subtrees from the reviewable universe.
``--claims-out TSV`` writes the full ``file<TAB>unit`` claim table for the
coordinator's records. Exit is non-zero on any hole, conflict, or dead token.

Typical invocation, from the coordinator, at prep AND at the cross-cut wave:

    review_partition_closure.py --map /tmp/review-next/unit-map.txt \\
        --tree /tmp/wt-review-base --changed-since <prev-review-base-sha> \\
        --exclude '.claude/skills/SecOpsAgentKit/*'
"""

from __future__ import annotations

import argparse
import collections
import fnmatch
import subprocess
import sys
from pathlib import Path

GLOB_CHARS = ("*", "?", "[")


def read_list_file(path: Path) -> list[str]:
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def git_lines(tree: str, *args: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", tree, *args], capture_output=True, text=True, check=True
    )
    return [line for line in out.stdout.splitlines() if line]


def parse_map(path: Path) -> dict[str, list[str]]:
    """Return unit -> claim tokens, preserving order; accumulate repeated units."""
    units: dict[str, list[str]] = collections.defaultdict(list)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        unit, sep, body = line.partition(":")
        unit = unit.strip()
        if not sep or not unit or " " in unit:
            raise SystemExit(f"error: {path}:{lineno}: expected 'UNIT: token ...', got '{raw}'")
        tokens = body.split()
        if not tokens:
            raise SystemExit(f"error: {path}:{lineno}: unit '{unit}' lists no tokens")
        units[unit].extend(tokens)
    if not units:
        raise SystemExit(f"error: {path}: empty unit map")
    return dict(units)


def match_token(token: str, files: list[str]) -> list[str]:
    if token.endswith("/"):
        return [f for f in files if f.startswith(token)]
    if any(ch in token for ch in GLOB_CHARS):
        return [f for f in files if fnmatch.fnmatch(f, token)]
    return [f for f in files if f == token]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--map", required=True, help="unit map file (see format above)")
    parser.add_argument("--tree", help="git worktree; reviewable files = git ls-files")
    parser.add_argument(
        "--changed-since", metavar="REV",
        help="flag files from 'git diff --name-only REV' (requires --tree)",
    )
    parser.add_argument(
        "--files-from", metavar="LIST",
        help="explicit reviewable-file list (overrides git ls-files)",
    )
    parser.add_argument(
        "--changed-from", metavar="LIST",
        help="explicit changed-file list (overrides --changed-since)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="drop matching paths from the reviewable universe (repeatable)",
    )
    parser.add_argument(
        "--claims-out", metavar="TSV", help="write the file<TAB>unit claim table here"
    )
    args = parser.parse_args(argv)

    if not args.files_from and not args.tree:
        parser.error("one of --tree or --files-from is required")
    if args.changed_since and not args.tree:
        parser.error("--changed-since requires --tree")

    if args.files_from:
        all_files = read_list_file(Path(args.files_from))
    else:
        all_files = git_lines(args.tree, "ls-files")
    excluded = [
        f for f in all_files
        if any(fnmatch.fnmatch(f, pat) for pat in args.exclude)
    ]
    files = [f for f in all_files if f not in set(excluded)]

    changed: list[str] = []
    if args.changed_from:
        changed = read_list_file(Path(args.changed_from))
    elif args.changed_since:
        changed = git_lines(args.tree, "diff", "--name-only", args.changed_since)

    units = parse_map(Path(args.map))
    claims: dict[str, list[str]] = collections.defaultdict(list)
    errors: list[str] = []
    for unit, tokens in units.items():
        for token in tokens:
            matched = match_token(token, files)
            if not matched:
                errors.append(f"DEAD TOKEN: unit {unit} token '{token}' matches no reviewable file")
            for f in matched:
                if unit not in claims[f]:
                    claims[f].append(unit)

    unclaimed = [f for f in files if f not in claims]
    for f in unclaimed:
        errors.append(f"UNCLAIMED: {f}")
    for f, owners in sorted(claims.items()):
        if len(owners) > 1:
            errors.append(f"MULTI-CLAIMED: {f} owned by {', '.join(sorted(owners))}")

    fileset = set(files)
    review_flags: list[tuple[str, str]] = []
    changed_gone: list[str] = []
    for f in changed:
        if f not in fileset:
            changed_gone.append(f)
        elif f in claims:
            review_flags.append((claims[f][0], f))
        else:
            errors.append(f"CHANGED-UNCLAIMED: {f} changed since base but owned by no unit")

    print(
        f"reviewable {len(files)} (excluded {len(excluded)})  units {len(units)}  "
        f"claimed {len(claims)}  unclaimed {len(unclaimed)}  changed {len(changed)}"
    )
    if unclaimed:
        agg = collections.Counter(
            "/".join(f.split("/")[:2]) if "/" in f else f for f in unclaimed
        )
        print("== UNCLAIMED by top-2 dirs ==")
        for d, n in agg.most_common(40):
            print(f"  {n:4d}  {d}")
    if review_flags:
        print("== changed since base — flagged for review ==")
        for unit, f in sorted(review_flags):
            print(f"REVIEW {unit}\t{f}")
    for f in changed_gone:
        print(f"note: changed file not in reviewable set (deleted/excluded): {f}")
    if args.claims_out:
        with open(args.claims_out, "w", encoding="utf-8") as fh:
            for f in sorted(claims):
                fh.write(f"{f}\t{','.join(sorted(claims[f]))}\n")
    if errors:
        print(f"\nPARTITION FAILED — {len(errors)} problem(s):")
        for err in errors:
            print("  " + err)
        return 1
    print("\nPARTITION CLEAN — every reviewable file owned exactly once.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
