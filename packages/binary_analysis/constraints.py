"""Narrow SMT checks for binary hypotheses.

RAPTOR does not symbolically execute whole binaries here. The operator or a
prior mechanically extracted trace supplies explicit conditions; this module
asks Z3 whether those conditions are jointly satisfiable and records the
answer as evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from core.json import load_json
from packages.exploit_feasibility.smt_path import validate_path

from .evidence import EvidenceRecord, EvidenceTier, make_evidence


def validate_constraint_file(
    path: Path,
    *,
    binary_sha256: str,
) -> tuple[Optional[dict[str, Any]], list[EvidenceRecord]]:
    payload = load_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError(f"constraint file is not a JSON object: {path}")
    conditions = payload.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise ValueError(f"constraint file has no conditions list: {path}")
    profile = str(payload.get("profile") or "uint64")
    result = validate_path(
        conditions,
        profile=profile,
        timeout_ms=payload.get("timeout_ms"),
        prefer_witness=payload.get("prefer_witness"),
    )
    record = make_evidence(
        binary_sha256,
        kind="smt_constraint_check",
        source="operator_constraint_file",
        summary=f"SMT checked {len(conditions)} explicit path conditions using {profile}",
        tier=EvidenceTier.SMT_PROVED,
        confidence="confirmed" if result.get("feasible") is not None else "candidate",
        reproducible=True,
        tool="z3",
        location=str(Path(path).resolve()),
        data={
            "conditions": conditions,
            "profile": profile,
            "result": result,
        },
    )
    return {
        "input": payload,
        "result": result,
        "evidence_id": record.id,
    }, [record]


__all__ = ["validate_constraint_file"]
