"""Conditional integer-layout assumptions compared with bounded platform facts."""
from pathlib import Path
from typing import Any

from .binary_review_scope import capture_binary_module
from .integer_abi import IntegerABIInput, binary_integer_abi, resolve_integer_abi


def compare_integer_abi(value: IntegerABIInput, *, target_path: Path) -> dict[str, Any] | None:
    """Retain operator selection and disclose known binary contradictions.

    Header platform conventions do not establish compiler options, packing,
    calling conventions or source types. Version checks are best effort;
    this descriptive context is never a verification receipt.
    """
    target = Path(target_path)
    if target.is_dir():
        return None
    selected = resolve_integer_abi(value)
    record: dict[str, Any] = {
        "schema_version": 1,
        "role": "conditional_assumption_not_verification_evidence",
        "status": "disabled" if selected is None else "platform_unavailable",
        "selected": selected.record() if selected is not None else None,
        "binary_platform": None,
        "module_sha256": None,
        "contradicted_fields": [],
        "limits": "Header platform conventions do not establish compiler options, packing or source types.",
    }
    if selected is None:
        return record
    module = capture_binary_module(target)
    if module is None:
        return record
    platform = binary_integer_abi(target)
    if not module.current():
        record["reason"] = "binary_changed_during_platform_comparison"
        return record
    record["module_sha256"] = module.sha256
    if platform is None:
        return record
    fields = ("char_bits", "short_bits", "int_bits", "long_bits", "long_long_bits", "representation")
    contradicted = [name for name in fields if getattr(selected, name) != getattr(platform, name)]
    record.update(binary_platform=platform.record(), contradicted_fields=contradicted,
                  status="contradictory" if contradicted else "consistent")
    return record
