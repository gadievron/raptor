"""Offline receipt-decision regression replay; never an audit recall score.

Run ``python -m core.audit.corpus.receipt_replay`` for the saved cases.
Snapshots contain reviewed hypotheses and receipts, not cached verdicts.
Replay executes today's production receipt policy without tool dispatch,
provider calls, or access to the original checkout or audit directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal
from core.audit.receipt_resolution import receipt_override


DEFAULT_CASES = Path(__file__).with_name("replay_cases") / "receipt_floors.json"


def load_cases(path: Path) -> list[dict]:
    data = load_json(path, max_bytes=2 * 1024 * 1024)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported receipt replay schema")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("receipt replay requires a nonempty case list")
    identifiers = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each replay case must be an object")
        identifier = case.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("replay case IDs must be nonempty and unique")
        identifiers.add(identifier)
        outcome = case.get("outcome")
        expected = case.get("expected")
        if not isinstance(outcome, dict) or not all(
            isinstance(outcome.get(key), str) and outcome[key]
            for key in ("file", "function")
        ):
            raise ValueError(f"{identifier}: missing outcome identity")
        if not isinstance(outcome.get("hypotheses"), list):
            raise ValueError(f"{identifier}: hypotheses must be a list")
        if not isinstance(case.get("receipts"), list) or not isinstance(
            case.get("detector_findings"), list,
        ):
            raise ValueError(f"{identifier}: receipts and detector_findings must be lists")
        if not isinstance(expected, dict) or expected.get("status") not in (
            "clean", "suspicious",
        ):
            raise ValueError(f"{identifier}: invalid expected receipt status")
        gate = expected.get("gate")
        if (expected["status"] == "clean" and gate is not None) or (
            expected["status"] == "suspicious" and not isinstance(gate, str)
        ):
            raise ValueError(f"{identifier}: expected gate disagrees with status")
    return cases


def replay(cases: list[dict]) -> dict:
    """Replay the production decision with isolated, untrusted config.

    The source snapshot is optional: absent source means source-based
    refuters are unavailable. A fixture's expected clean result means
    'no receipt override', never proof that the labelled code is safe.
    """
    rows = []
    for case in cases:
        captured = case["outcome"]
        outcome = SimpleNamespace(
            file=captured["file"], function=captured["function"],
            status="clean", body=captured.get("body", ""),
            hypothesis=captured.get("hypothesis", ""),
            hypotheses=captured["hypotheses"],
            evidence_tool=captured.get("evidence_tool", ""),
            review_result=captured.get("review_result", {}),
            line=captured.get("line", 0),
        )
        with tempfile.TemporaryDirectory(prefix="receipt-replay-") as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            config = SimpleNamespace(
                target_path=target, out_dir=root / "out", repo_trusted=False,
            )
            config.out_dir.mkdir()
            verdict = receipt_override(
                outcome, config=config, receipts=case["receipts"],
                detector_findings=case["detector_findings"],
                pre_evidence=case.get("pre_evidence"),
                source=case.get("source"),
            )
        actual = {
            "status": verdict.demote_to if verdict else "clean",
            "gate": verdict.gate if verdict else None,
        }
        rows.append({
            "id": case["id"], "expected": case["expected"],
            "actual": actual, "match": actual == case["expected"],
            "label_gap": case.get("label_expected") in ("finding", "suspicious")
            and actual["status"] == "clean",
        })
    audit_dir = Path(__file__).resolve().parents[1]
    implementation = hashlib.sha256()
    for name in ("receipt_resolution.py", "refutation.py"):
        implementation.update(name.encode())
        implementation.update((audit_dir / name).read_bytes())  # raw-open: trusted implementation files; hash requires complete bytes
    return {
        "schema_version": 1, "scope": "receipt_decision_only",
        "implementation_sha256": implementation.hexdigest(),
        "inputs_sha256": hashlib.sha256(json.dumps(
            cases, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "total": len(rows), "passed": sum(row["match"] for row in rows),
        "label_gaps": sum(row["label_gap"] for row in rows), "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--case", action="append", default=[], help="Replay only these case IDs")
    parser.add_argument("--output", type=Path, help="Write deterministic JSON report")
    args = parser.parse_args(argv)
    try:
        cases = load_cases(args.fixtures)
        if args.case:
            unknown = set(args.case) - {case["id"] for case in cases}
            if unknown:
                raise ValueError(f"unknown replay cases: {sorted(unknown)}")
            cases = [case for case in cases if case["id"] in args.case]
        report = replay(cases)
        if args.output:
            save_json(args.output, report)
    except (ValueError, OSError) as exc:
        parser.error(sanitise_for_terminal(str(exc), max_len=1000))
    print(f"Receipt replay: {report['passed']}/{report['total']} passed; "
          f"{report['label_gaps']} labelled-positive case(s) without an override")
    for row in report["cases"]:
        if not row["match"]:
            print(sanitise_for_terminal(
                f"  FAIL {row['id']}: expected={row['expected']} actual={row['actual']}",
                max_len=2000,
            ))
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
