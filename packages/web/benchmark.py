"""Offline regression harness for web scanner reports.

The harness does not run targets itself. It evaluates committed or freshly
generated `web_scan_report.json` files against a small manifest, which makes
scanner changes measurable without turning CI into a live exploit lab.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExpectedFinding:
    """One expected signal in a benchmark case."""

    vuln_type: str | None = None
    check_id: str | None = None
    min_count: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExpectedFinding":
        return cls(
            vuln_type=data.get("vuln_type"),
            check_id=data.get("check_id"),
            min_count=int(data.get("min_count", 1)),
        )


def evaluate_report(
    report: dict[str, Any],
    *,
    expected: list[ExpectedFinding],
    forbidden_check_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate one scan report against expected and forbidden signals."""

    findings = report.get("findings") or []
    if not isinstance(findings, list):
        findings = []

    expectations = []
    passed = True
    for item in expected:
        matches = [
            finding for finding in findings
            if (item.vuln_type is None or finding.get("vuln_type") == item.vuln_type)
            and (item.check_id is None or finding.get("check_id") == item.check_id)
        ]
        ok = len(matches) >= item.min_count
        passed = passed and ok
        expectations.append({
            "vuln_type": item.vuln_type,
            "check_id": item.check_id,
            "min_count": item.min_count,
            "observed_count": len(matches),
            "passed": ok,
        })

    forbidden = []
    for check_id in forbidden_check_ids or []:
        matches = [finding for finding in findings if finding.get("check_id") == check_id]
        ok = len(matches) == 0
        passed = passed and ok
        forbidden.append({
            "check_id": check_id,
            "observed_count": len(matches),
            "passed": ok,
        })

    return {
        "passed": passed,
        "total_findings": len(findings),
        "expectations": expectations,
        "forbidden": forbidden,
    }


def evaluate_manifest(manifest: dict[str, Any], report_dir: Path) -> dict[str, Any]:
    """Evaluate all cases whose reports exist under ``report_dir``."""

    cases = []
    overall = True
    for case in manifest.get("cases", []):
        report_path = report_dir / case["report"]
        if not report_path.exists():
            cases.append({
                "id": case["id"],
                "status": "missing_report",
                "report": str(report_path),
                "passed": False,
            })
            overall = False
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        result = evaluate_report(
            report,
            expected=[
                ExpectedFinding.from_dict(item)
                for item in case.get("expected_findings", [])
            ],
            forbidden_check_ids=list(case.get("forbidden_check_ids", [])),
        )
        cases.append({
            "id": case["id"],
            "status": "evaluated",
            "report": str(report_path),
            **result,
        })
        overall = overall and result["passed"]

    return {
        "suite": manifest.get("suite", "web-regression"),
        "passed": overall,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate RAPTOR web scan regression reports")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = evaluate_manifest(manifest, args.report_dir)
    rendered = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

