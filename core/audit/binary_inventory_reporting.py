"""Bounded descriptive inventory counts, separate from review or decode coverage."""
from pathlib import Path

from core.inventory import iter_checklist_items, read_checklist_meta
from core.reporting.document import Block

_MAX_SELECTED = 200_000
_UNKNOWN_DIMENSIONS = (
    "Decoded-byte coverage", "Function-boundary confidence", "Debug/source mapping coverage",
    "Unresolved transfers and modules", "Executable-region discovery completeness",
)


def load_binary_inventory(out_dir: Path) -> dict | None:
    """Read recorded rows through inventory integrity gates, not binary probes.

    Streaming holds at most one shard and requires successful integrity-checked
    completion. Expected totals reject count mismatches; this is a recorded projection, never a coherent live build snapshot.
    """
    try:
        metadata = read_checklist_meta(out_dir)
    except (OSError, ValueError, TypeError):
        return {"mode": "unavailable", "authoritative": False, "reason": "unreadable_inventory_metadata"}
    if metadata.get("target_kind") != "binary":
        return None
    unavailable = {"mode": "unavailable", "authoritative": False}
    stats = metadata.get("binary_stats")
    selected = metadata.get("total_items")
    parsed = stats.get("total_functions") if isinstance(stats, dict) else None
    if (type(selected) is not int or type(parsed) is not int
            or not 0 <= selected <= min(parsed, _MAX_SELECTED)):
        return {**unavailable, "reason": "missing_or_invalid_inventory_totals"}
    seen = pseudocode = 0
    try:
        for path, _file, item in iter_checklist_items(out_dir, require_complete=True):
            seen += 1
            if (seen > selected or not isinstance(path, str) or not path.startswith("binary:")
                    or item.get("kind") != "function"
                    or type(item.get("has_decompilation", False)) is not bool):
                return {**unavailable, "reason": "invalid_selected_binary_records"}
            pseudocode += item.get("has_decompilation") is True
        if seen != selected or read_checklist_meta(out_dir) != metadata:
            return {**unavailable, "reason": "incomplete_or_changed_inventory"}
    except (OSError, ValueError, TypeError):
        return {**unavailable, "reason": "unreadable_inventory"}
    return {
        "mode": "recorded", "authoritative": False,
        "parsed_functions": parsed, "selected_functions": selected,
        "functions_outside_selection": parsed - selected,
        "pseudocode_recorded": pseudocode, "pseudocode_not_recorded": selected - pseudocode,
        "unmeasured_dimensions": dict.fromkeys(_UNKNOWN_DIMENSIONS),
    }


def binary_inventory_blocks(report: dict) -> list[Block]:
    record = report.get("binary_inventory")
    if not isinstance(record, dict):
        return []
    if record.get("mode") != "recorded":
        return [Block("paragraph", title="Recorded binary inventory unavailable", text=(
            "The saved binary inventory could not supply consistent bounded counts; "
            "this does not mean zero functions or complete coverage."))]
    labels = (
        ("Parsed functions recorded", "parsed_functions"),
        ("Selected function records", "selected_functions"),
        ("Parsed functions outside selection", "functions_outside_selection"),
        ("Selected records with pseudocode", "pseudocode_recorded"),
        ("Selected records without recorded pseudocode", "pseudocode_not_recorded"),
    )
    return [Block("section", title="Recorded binary inventory", children=[
        Block("paragraph", text=(
            "These are saved inventory counts, not current binary authentication or extraction completeness. "
            "Pseudocode presence is not completed review, authoritative source, or decoded-byte coverage. "
            "Functions outside selection were not thereby reviewed. Binary and source coverage have separate denominators.")),
        Block("table", columns=["Recorded dimension", "Count"],
              rows=[[label, str(record[key])] for label, key in labels]),
        Block("table", columns=["Unmeasured dimension", "Coverage"],
              rows=[[label, "unavailable"] for label in _UNKNOWN_DIMENSIONS]),
    ])]
