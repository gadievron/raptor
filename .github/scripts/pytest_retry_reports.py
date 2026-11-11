"""Validate failed-case pytest retries without losing first-pass coverage."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def _collection_skip(case):
    # Pytest's collection reporter has no runnable node: the module address
    # is stored in name and classname is explicitly empty. Keep this metadata
    # distinct from runnable identities; it must never authorize a retry.
    name = case.get("name", "")
    skipped = case.find("skipped")
    return (case.get("classname") == "" and bool(name)
            and all(part.replace("-", "_").isidentifier() for part in name.split("."))
            and len(case) == 1 and skipped is not None
            and skipped.get("message") == "collection skipped")


def _key(case):
    key = case.get("classname"), case.get("name")
    if not all(key) and not _collection_skip(case):
        raise ValueError("testcase lacks an unambiguous classname/name")
    return key


def _failed(case):
    return case.find("failure") is not None or case.find("error") is not None


def _counts(cases):
    return {name: sum(len(case.findall(tag)) for case in cases)
            for name, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped"))}


def _read(path):
    try:
        root = ET.parse(path).getroot()
        suites = list(root.iter("testsuite"))
        if len(suites) != 1:
            raise ValueError("expected one pytest testsuite")
        suite = suites[0]
        cases = suite.findall("testcase")
        groups = {}
        for case in cases:
            groups.setdefault(_key(case), []).append(case)
        # Pytest can emit two failed phase records for one node. Passed
        # duplicate identities instead make replacement ambiguous.
        if any(len(rows) > 1 and not all(_failed(row) for row in rows)
               for rows in groups.values()):
            raise ValueError("ambiguous duplicate testcase identity")
        for name, count in _counts(cases).items():
            if int(suite.get(name, "-1")) != count:
                raise ValueError(f"inconsistent {name} counter")
        reported = int(suite.get("tests", "-1"))
        # Successful call + teardown error can increment pytest's count
        # twice without creating a second node. Double-failure phases can
        # instead create two XML rows for one counted test.
        if not len(groups) <= reported <= len(cases) + _counts(cases)["errors"]:
            raise ValueError("inconsistent tests counter")
        duration = float(suite.get("time", "0"))
        if not math.isfinite(duration) or duration < 0:
            raise ValueError("invalid duration")
        return root, suite, groups
    except (OSError, ET.ParseError, ValueError) as exc:
        raise ValueError(f"invalid pytest report {path}: {exc}") from exc


def failed_keys(groups):
    return {key for key, rows in groups.items() if any(_failed(row) for row in rows)}


def require_passing_guards(path, attempt):
    if path is None or not isinstance(attempt, str) or not attempt:
        raise ValueError("first-attempt global guard receipt and binding are required")
    try:
        receipt = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("first-attempt global guard receipt is missing or invalid") from exc
    names = {"git_config", "egress", "session_budget", "test_wall_budget"}
    if (not isinstance(receipt, dict)
            or set(receipt) != {"version", "attempt", "complete", "guards"}
            or type(receipt["version"]) is not int or receipt["version"] != 1
            or receipt["attempt"] != attempt or receipt["complete"] is not True
            or not isinstance(receipt["guards"], dict)
            or set(receipt["guards"]) != names
            or any(type(value) is not bool for value in receipt["guards"].values())):
        raise ValueError("first-attempt global guard receipt is incomplete or mismatched")
    if not all(receipt["guards"].values()):
        raise ValueError("first-attempt global guards failed; retry cannot replace that failure")


def eligible(path, guard_report=None, attempt=None):
    require_passing_guards(guard_report, attempt)
    _, _, groups = _read(path)
    return len(failed_keys(groups))


def merge(first, retry, output):
    if output.resolve() in {first.resolve(), retry.resolve()}:
        raise ValueError("effective report must not overwrite raw attempts")
    root, suite, groups = _read(first)
    _, retry_suite, retried = _read(retry)
    # A --lf run can collect the same unavailable modules again. Accept only
    # collection skips already present in the first report, with the same
    # reason. Keep their original rows rather than treating them as retried
    # tests or adding them twice to the effective report.
    for key in [key for key in retried if key[0] == ""]:
        if key not in groups:
            raise ValueError("unexpected collection skip on retry")
        first_skip = groups[key][0].find("skipped")
        retry_skip = retried[key][0].find("skipped")
        if (first_skip.attrib, first_skip.text) != (retry_skip.attrib, retry_skip.text):
            raise ValueError("collection skip changed on retry")
        del retried[key]
    expected = failed_keys(groups)
    if not expected or set(retried) != expected:
        raise ValueError("retry did not cover exactly the previously failed cases")
    if any(row.find("skipped") is not None for rows in retried.values() for row in rows):
        raise ValueError("a previously failed case was skipped on retry")
    for case in list(suite.findall("testcase")):
        suite.remove(case)
    for key, rows in groups.items():
        suite.extend(retried[key] if key in expected else rows)
    cases = suite.findall("testcase")
    suite.attrib.update({name: str(count) for name, count in _counts(cases).items()})
    suite.set("tests", str(len(cases)))
    suite.set("time", str(float(suite.get("time", "0")) + float(retry_suite.get("time", "0"))))
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)
    return not failed_keys(retried)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("eligible")
    check.add_argument("first", type=Path)
    check.add_argument("cache", type=Path)
    check.add_argument("--guard-report", type=Path)
    check.add_argument("--attempt")
    guards = commands.add_parser("guards")
    guards.add_argument("report", type=Path)
    guards.add_argument("attempt")
    combine = commands.add_parser("merge")
    for name in ("first", "retry", "output"):
        combine.add_argument(name, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "guards":
            require_passing_guards(args.report, args.attempt)
            return 0
        if args.command == "eligible":
            count = eligible(args.first, args.guard_report, args.attempt)
            if count:
                try:
                    cached = json.loads((args.cache / "v/cache/lastfailed").read_text())
                except (OSError, ValueError) as exc:
                    raise ValueError(f"failed-case cache unavailable: {exc}") from exc
                if (not isinstance(cached, dict) or len(cached) != count
                        or any(not isinstance(key, str) or not key or value is not True
                               for key, value in cached.items())):
                    raise ValueError("failed-case cache disagrees with the first report")
            print(f"[pytest-retry] {count} failed case(s) eligible for one targeted retry")
            return 0 if count else 1
        return 0 if merge(args.first, args.retry, args.output) else 1
    except ValueError as exc:
        print(f"[pytest-retry] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
