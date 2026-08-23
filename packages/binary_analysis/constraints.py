"""Narrow SMT checks for binary hypotheses.

RAPTOR does not symbolically execute whole binaries here. The operator or a
prior mechanically extracted trace supplies explicit conditions; this module
asks Z3 whether those conditions are jointly satisfiable and records the
answer as evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import logging

from core.json import load_json

from core.evidence import BinaryEvidenceRecord, EvidenceTier, make_evidence

logger = logging.getLogger(__name__)


def validate_constraint_file(
    path: Path,
    *,
    binary_sha256: str,
) -> tuple[dict[str, Any] | None, list[BinaryEvidenceRecord]]:
    payload = load_json(Path(path))
    if not isinstance(payload, dict):
        msg = f"constraint file is not a JSON object: {path}"
        raise ValueError(msg)
    conditions = payload.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        msg = f"constraint file has no conditions list: {path}"
        raise ValueError(msg)
    try:
        from packages.exploit_feasibility.smt_path import validate_path
    except ImportError:
        logger.debug("z3/smt_path not available; skipping constraint validation")
        return payload, []
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
