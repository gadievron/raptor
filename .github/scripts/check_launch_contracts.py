#!/usr/bin/env python3
"""Launch-contract closure gate (per-PR).

Repository test code that launches processes — or loads CLI scripts
in-process — is inventoried by ``core/testing/cli_launch_inventory.py``
and reviewed against the catalogue
``core/testing/tests/data/cli_launch_contracts.json``: every launch
site carries a reviewed contract, the command/environment producer
files are sha-pinned witnesses, and shell routers that delegate into
Python are pinned too. The pytest variant of this closure runs in the
slow tier only, so a PR adding an unreviewed launch site or changing a
witnessed producer could merge green and sit undetected until the
nightly run. This gate runs the same closure per PR.

Failure modes reported:

* unclassified launch site — an inventory row with no catalogue
  record (new/changed process, helper, or loader launch);
* retired contract — a catalogue record with no matching inventory
  row (the site was removed or changed signature);
* witness-set drift — the derived source-witness file set differs
  from the catalogue's ``sources`` keys;
* witness content drift — a pinned producer file is missing or its
  sha256 changed;
* shell-router drift — the derived router set or a router's sha256
  differs from ``shell_routers``.

Every failure needs catalogue reconciliation with a reviewed contract
and purpose — the catalogue is the review record, not a baseline to
rubber-stamp.

Usage:
    python3 .github/scripts/check_launch_contracts.py
    python3 .github/scripts/check_launch_contracts.py --root <tree>

Exit codes: 0 clean, 1 drift, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

_DEFAULT_ROOT = Path(__file__).resolve().parents[2]
_INVENTORY_MODULE = "core/testing/cli_launch_inventory.py"
_CATALOGUE = "core/testing/tests/data/cli_launch_contracts.json"
_CONTRACTS = frozenset({
    "standalone", "owned-custom-launch", "owned-session-or-refusal",
    "owned-in-process", "non-cli-probe",
})
_ROUTER_PREFIXES = ("bin/", "libexec/", "plugins/", ".claude/hooks/")
_REPORT_LIMIT = 20


def _load_inventory_module(root: Path) -> ModuleType:
    """Load the root-under-check's own inventory module by path (a
    package import would cache one root's module across roots)."""
    path = root / _INVENTORY_MODULE
    spec = importlib.util.spec_from_file_location(
        "_cli_launch_inventory_under_check", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tracked_paths(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, text=True, check=True, timeout=60,
    )
    return sorted(set(listed.stdout.splitlines()))


def _bounded(items: list, label: str) -> str:
    shown = ", ".join(str(item) for item in items[:_REPORT_LIMIT])
    extra = len(items) - _REPORT_LIMIT
    suffix = f" (+{extra} more)" if extra > 0 else ""
    return f"{label}: {shown}{suffix}"


def closure_failures(root: Path, paths: list[str]) -> list[str]:
    """Every launch-contract closure violation for *root*, as
    human-readable report lines (empty list == closed)."""
    mod = _load_inventory_module(root)
    catalogue = json.loads((root / _CATALOGUE).read_text(encoding="utf-8"))
    failures: list[str] = []

    rows = mod.inventory(root, paths)
    actual = Counter(
        (row["path"], row["scope"], row["signature"]) for row in rows)
    expected: Counter = Counter()
    for record in catalogue["sites"]:
        if record["contract"] not in _CONTRACTS:
            failures.append(
                f"catalogue record {record['path']}::{record['scope']} "
                f"carries unknown contract {record['contract']!r}")
        if not record["purpose"].strip():
            failures.append(
                f"catalogue record {record['path']}::{record['scope']} "
                f"has an empty purpose — the catalogue is the review "
                f"record")
        expected[(record["path"], record["scope"],
                  record["signature"])] += record["count"]

    unclassified = actual - expected
    if unclassified:
        failures.append(_bounded(
            sorted(unclassified),
            "unreviewed process/helper/loader launches — add reviewed "
            "contract records to the catalogue"))
    retired = expected - actual
    if retired:
        failures.append(_bounded(
            sorted(retired),
            "removed or changed launch contracts need reconciliation — "
            "retire or re-sign the catalogue records"))

    witnessed = mod.source_witnesses(root, paths, rows)
    missing = sorted(set(witnessed) - set(catalogue["sources"]))
    stale = sorted(set(catalogue["sources"]) - set(witnessed))
    if missing:
        failures.append(_bounded(
            missing, "new launch environment/helper witnesses — pin "
            "their sha256 in the catalogue after review"))
    if stale:
        failures.append(_bounded(
            stale, "catalogue witnesses no longer derived — remove "
            "after review"))
    changed = [
        path for path, digest in catalogue["sources"].items()
        if not (root / path).is_file()
        or hashlib.sha256(
            (root / path).read_bytes()).hexdigest() != digest]
    if changed:
        failures.append(_bounded(
            sorted(changed),
            "launch command/environment producers changed — review "
            "their launch ownership and refresh the pinned sha256"))

    routers: dict[str, str] = {}
    for path in paths:
        if not path.startswith(_ROUTER_PREFIXES):
            continue
        candidate = root / path
        if not candidate.is_file():
            continue
        try:
            source = candidate.read_text()
        except UnicodeError:
            continue
        shebang = source.splitlines()[0] if source.startswith("#!") else ""
        if shebang and ("bash" in shebang or "/sh" in shebang):
            route = mod.shell_routes(path, source)
            if route["delegates"] or route["modules"]:
                routers[path] = hashlib.sha256(
                    candidate.read_bytes()).hexdigest()
    if routers != catalogue["shell_routers"]:
        drifted = sorted(
            set(routers.items())
            ^ set(catalogue["shell_routers"].items()))
        failures.append(_bounded(
            [path for path, _ in drifted],
            "shell routing changed — review transitive Python launch "
            "ownership and refresh shell_routers"))
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not (root / _CATALOGUE).is_file():
        print(f"error: {root} carries no launch-contract catalogue",
              file=sys.stderr)
        return 2
    try:
        paths = tracked_paths(root)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"error: git file listing failed: {exc}", file=sys.stderr)
        return 2

    failures = closure_failures(root, paths)
    if failures:
        print("launch-contract closure drift — reconcile "
              f"{_CATALOGUE} (review each change; the catalogue is "
              "the review record):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("launch-contract closure: inventory, witnesses and shell "
          "routers all match the reviewed catalogue")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
