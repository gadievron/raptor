"""Per-lane skip-count budget gate.

Self-contained, stdlib-only. Compares the skip count a pytest lane
just reported (its junit XML) against the count recorded for that
lane in ``skip_budget_baseline.json`` next to this script, and fails
when the count grew without a baseline update.

Lanes are the CI dispatch units that run pytest with a deterministic
collection shape: the ``_tier.yml`` tiers (keyed ``<tier>/image`` and
``<tier>/runner`` — the two execution paths run under different
provisioning, so their counts are recorded separately), the nightly
full-collection lanes (``nightly-default``, ``nightly-slow``,
``nightly-integration``), and this gate's own home suite
(``ci-lint``). Finer granularity (per test file, per
matrix batch) was rejected: batch partitions are dynamic per run, so
their counts are not stable keys.

Input is the junit XML pytest already writes (``--junitxml``) — the
run's own artifact, no second collection pass and no terminal-output
parsing. A collection pass was rejected because it cannot observe
runtime ``pytest.skip()`` calls; terminal parsing because the summary
line's shape varies with verbosity and plugins.

CI semantics (baseline pattern, cf. ``check_vocab_lists.py``):

* lane recorded, observed count ABOVE the recorded count — fail.
* lane recorded, observed count below it — with ``--full`` (the lane
  ran its complete collection: nightly lanes, force-full dispatch),
  warn that the recorded count is stale headroom; without ``--full``
  (a path-filtered run collects a subset, so a lower count is
  expected) stay silent.
* lane not recorded — print the observed count with the exact
  refresh command; never fail. This is the adoption path: counts are
  runner-environment facts, so they are seeded from a CI run's own
  output rather than hand-typed.

Note that without ``--full`` the growth check compares a subset's
count against the full-collection baseline, so growth inside a
filtered run only trips once it exceeds the whole recorded count —
the full-dispatch events (merge queue, scheduled full suite, the
nightlies) provide the exact enforcement.

Usage:
    python3 .github/scripts/check_skip_budget.py \
        --lane <name> --junit-xml <file> [--junit-xml <file> ...] \
        [--full] [--write-baseline] [--baseline <path>]

Multiple ``--junit-xml`` files sum (a lane split across attempts or
batches). Exit codes: 0 clean / warn / unrecorded lane, 1 growth
over the recorded count, 2 usage error — missing or unparseable
XML, and a PRESENT but unreadable/misshapen baseline (an absent
baseline is the pre-adoption state; a corrupt one must not fall
open to "nothing recorded"). A gate that passes on bad input is a
hole, not a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_BASELINE = Path(__file__).resolve().parent / "skip_budget_baseline.json"


def count_skips(junit_path: Path) -> int:
    """Sum the ``skipped`` attributes over every testsuite element.

    pytest writes one ``<testsuite>`` (inside ``<testsuites>``); the
    sum-over-all shape also covers tools that emit several.
    """
    try:
        root = ET.parse(junit_path).getroot()
    except (OSError, ET.ParseError) as exc:
        msg = f"cannot read junit XML at {junit_path}: {exc}"
        raise ValueError(msg) from exc
    suites = (
        [root] if root.tag == "testsuite"
        else list(root.iter("testsuite"))
    )
    if not suites:
        msg = f"no <testsuite> element in {junit_path}"
        raise ValueError(msg)
    total = 0
    for suite in suites:
        raw = suite.get("skipped", "0")
        try:
            total += int(raw)
        except ValueError as exc:
            msg = f"non-integer skipped= attribute in {junit_path}: {raw!r}"
            raise ValueError(msg) from exc
    return total


def load_baseline(path: Path) -> dict:
    """An ABSENT baseline is empty (pre-adoption); a present but
    unreadable or misshapen one raises — falling open to {} would
    demote every recorded lane to the non-enforcing NOTICE path
    behind one corrupt commit, exactly the silent-off failure this
    gate exists to close.
    """
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"cannot read baseline at {path}: {exc}"
        raise ValueError(msg) from exc
    if not isinstance(loaded, dict) or any(
        not isinstance(v, dict) for v in loaded.values()
    ):
        msg = (
            f"baseline at {path} is not a JSON object of row objects "
            f"— fix or remove it"
        )
        raise ValueError(msg)
    return loaded


def write_baseline(path: Path, lane: str, skips: int) -> None:
    """Record *lane*'s observed count, ROUND-TRIPPING every other
    lane's row and this row's non-count fields (a reviewer's ``note``,
    any future schema field) — the same note-preserving refresh
    contract as ``check_vocab_lists.write_baseline``.

    A present-but-unreadable baseline REFUSES the rewrite: treating it
    as empty would erase every other lane's row in one keystroke.
    """
    entries: dict[str, dict] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(
                f"[skip-budget] refusing --write-baseline: cannot parse "
                f"the existing baseline at {path} ({exc}); fix or remove "
                f"it first — overwriting would erase every other lane's "
                f"row",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc
        if isinstance(loaded, dict):
            entries = {
                k: dict(v) for k, v in loaded.items() if isinstance(v, dict)
            }
    row = {k: v for k, v in entries.get(lane, {}).items() if k != "skips"}
    entries[lane] = {**row, "skips": skips}
    path.write_text(
        json.dumps(entries, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lane", required=True,
                    help="baseline key for this pytest lane")
    ap.add_argument("--junit-xml", action="append", type=Path,
                    required=True, dest="junit_xml",
                    help="pytest --junitxml output (repeatable; summed)")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--full", action="store_true",
                    help="this run collected the lane's full test set — "
                         "also warn when the count fell below the "
                         "recorded one")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record the observed count for this lane")
    args = ap.parse_args()

    try:
        observed = sum(count_skips(p) for p in args.junit_xml)
    except ValueError as exc:
        print(f"[skip-budget] {exc}", file=sys.stderr)
        return 2

    if args.write_baseline:
        write_baseline(args.baseline, args.lane, observed)
        print(f"[skip-budget] recorded {args.lane}: {observed} skip(s) "
              f"in {args.baseline}")
        return 0

    try:
        baseline = load_baseline(args.baseline)
    except ValueError as exc:
        print(f"[skip-budget] {exc}", file=sys.stderr)
        return 2
    entry = baseline.get(args.lane)

    if entry is not None and not isinstance(entry.get("skips"), int):
        # A recorded row without an integer count is a malformed
        # baseline, not an unrecorded lane — demoting it to the
        # NOTICE path would stop enforcement behind a typo.
        print(
            f"[skip-budget] malformed baseline row for {args.lane}: "
            f"'skips' must be an integer (got "
            f"{entry.get('skips')!r}) — fix {args.baseline.name}",
            file=sys.stderr,
        )
        return 2

    if entry is None:
        print(
            f"[skip-budget] NOTICE {args.lane}: no recorded skip count "
            f"(observed {observed}). Record it with\n"
            f"  python3 .github/scripts/check_skip_budget.py "
            f"--lane {args.lane} --junit-xml <this run's junit xml> "
            f"--write-baseline\n"
            f"and commit {args.baseline.name}.",
        )
        return 0

    recorded = entry["skips"]
    if observed > recorded:
        print(
            f"[skip-budget] {args.lane}: skip count changed vs baseline "
            f"(observed {observed} > recorded {recorded}). Review the "
            f"run's skip reasons (pytest -rs); if the change is "
            f"intended, refresh with --write-baseline and commit "
            f"{args.baseline.name}.",
        )
        return 1
    if observed < recorded and args.full:
        print(
            f"[skip-budget] WARN {args.lane}: skip count changed vs "
            f"baseline (observed {observed} < recorded {recorded}) — "
            f"the recorded count is stale headroom; refresh with "
            f"--write-baseline and commit {args.baseline.name}.",
        )
        return 0

    print(f"[skip-budget] {args.lane}: {observed} skip(s), within the "
          f"recorded count ({recorded}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
