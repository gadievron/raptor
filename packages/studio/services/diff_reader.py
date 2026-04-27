"""Compare two runs of the same project by finding identity.

Identity tuple ``(file, line, normalized_vuln_type)`` matches raptor's own
SARIF-deduplication rule (docs/exploitability-validation-integration.md).
Two findings with the same identity are considered "the same bug" across runs
even if their final_status / verdict / poc changed.

Output classifies every finding into exactly one bucket:
  * ``resolved`` — on A, not on B (bug appears to be fixed)
  * ``carried`` — on both A and B (bug still present)
  * ``new``      — on B, not on A (bug newly introduced)

For carried findings, we compute status progression (did it get more
confidently confirmed? did it get ruled out on B?) so the UI can highlight
the delta.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


def _norm_type(t: str) -> str:
    if not t:
        return ""
    return t.lower().replace(" ", "_").replace("-", "_")


def _identity(finding: dict) -> tuple:
    return (
        finding.get("file", "") or "",
        finding.get("line"),
        _norm_type(finding.get("vuln_type") or finding.get("type") or ""),
    )


def _status(finding: dict) -> str:
    return finding.get("final_status") or finding.get("status") or "pending"


def _verdict(finding: dict) -> str:
    feas = finding.get("feasibility") or {}
    return feas.get("verdict") or finding.get("verdict") or "unknown"


@dataclass
class CarriedFinding:
    a: dict
    b: dict
    status_a: str = ""
    status_b: str = ""
    verdict_a: str = ""
    verdict_b: str = ""

    @property
    def status_changed(self) -> bool:
        return self.status_a != self.status_b

    @property
    def verdict_changed(self) -> bool:
        return self.verdict_a != self.verdict_b


@dataclass
class DiffResult:
    run_a: str
    run_b: str
    resolved: list[dict] = field(default_factory=list)
    carried: list[CarriedFinding] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)

    @property
    def counts(self) -> dict:
        return {
            "resolved": len(self.resolved),
            "carried":  len(self.carried),
            "new":      len(self.new),
        }


def compute_diff(
    run_a_name: str,
    findings_a: list[dict],
    run_b_name: str,
    findings_b: list[dict],
) -> DiffResult:
    """Compare findings from two runs.

    Duplicate identities within one run collapse to the last occurrence,
    matching raptor's own SARIF dedup behavior.
    """
    index_a = {_identity(f): f for f in findings_a}
    index_b = {_identity(f): f for f in findings_b}

    ids_a = set(index_a.keys())
    ids_b = set(index_b.keys())

    out = DiffResult(run_a=run_a_name, run_b=run_b_name)

    for ident in sorted(ids_a - ids_b, key=lambda x: (x[0] or "", x[1] or 0)):
        out.resolved.append(index_a[ident])

    for ident in sorted(ids_a & ids_b, key=lambda x: (x[0] or "", x[1] or 0)):
        a = index_a[ident]
        b = index_b[ident]
        out.carried.append(CarriedFinding(
            a=a, b=b,
            status_a=_status(a), status_b=_status(b),
            verdict_a=_verdict(a), verdict_b=_verdict(b),
        ))

    for ident in sorted(ids_b - ids_a, key=lambda x: (x[0] or "", x[1] or 0)):
        out.new.append(index_b[ident])

    return out
