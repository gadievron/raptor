"""Coverage tracking with checked_by labels."""

from typing import Any, Dict, List


def _get_items(file_info):
    """Read code items from a file entry. Handles both old and new format."""
    return file_info.get("items", file_info.get("functions", []))


def update_coverage(
    inventory: Dict[str, Any],
    checked_functions: List[Dict[str, str]],
    source_label: str,
) -> Dict[str, Any]:
    """Mark functions as checked by a specific tool/stage.

    Args:
        inventory: The inventory dict to update (mutated in place).
        checked_functions: List of {"file": ..., "function": ...} that were checked.
        source_label: Tool identifier, e.g. "validate:stage-a", "understand:map".

    Returns:
        Updated inventory.
    """
    # `.get()` rather than `[...]` for caller-supplied dicts —
    # `checked_functions` flows from external callers (validate
    # stage outputs, understand-map post-processing, agentic
    # post-pass enrichment) and any of them passing a partial
    # entry (`{"file": "x"}` without `function`) would crash the
    # whole coverage update with KeyError. Skip incomplete entries
    # silently — the upstream finder is the right place to enforce
    # completeness, not the consumer.
    checked_set = {
        (f.get('file'), f.get('function'))
        for f in checked_functions
        if isinstance(f, dict) and f.get('file') and f.get('function')
    }

    for file_info in inventory.get('files', []):
        if not isinstance(file_info, dict):
            continue
        path = file_info.get('path')
        if not path:
            continue
        for func in _get_items(file_info):
            if not isinstance(func, dict):
                continue
            name = func.get('name')
            if not name:
                continue
            key = (path, name)
            if key in checked_set:
                checked_by = func.get('checked_by', [])
                if source_label not in checked_by:
                    checked_by.append(source_label)
                func['checked_by'] = checked_by

    return inventory


def get_coverage_stats(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """Compute coverage statistics from an inventory.

    Returns:
        Dict with total/checked counts (overall and by kind),
        SLOC stats, coverage_percent, and by_source breakdown.
    """
    total = 0
    checked = 0
    by_source: Dict[str, int] = {}
    by_kind: Dict[str, Dict[str, int]] = {}  # kind -> {total, checked}

    for file_info in inventory.get('files', []):
        for item in _get_items(file_info):
            total += 1
            kind = item.get('kind', 'function')

            if kind not in by_kind:
                by_kind[kind] = {"total": 0, "checked": 0}
            by_kind[kind]["total"] += 1

            checked_by = item.get('checked_by', [])
            if checked_by:
                checked += 1
                by_kind[kind]["checked"] += 1
                for source in checked_by:
                    by_source[source] = by_source.get(source, 0) + 1

    total_sloc = inventory.get('total_sloc', 0)

    func_stats = by_kind.get('function', {"total": 0, "checked": 0})

    return {
        'total_items': total,
        'checked_items': checked,
        'total_functions': func_stats["total"],      # backwards compat
        'checked_functions': func_stats["checked"],   # backwards compat
        'coverage_percent': (checked / total * 100) if total > 0 else 0,
        'total_sloc': total_sloc,
        'by_kind': by_kind,
        'by_source': by_source,
    }


def format_coverage_summary(inventory: Dict[str, Any]) -> str:
    """Format a human-readable coverage summary.

    Returns a multi-line string for printing to stdout.
    """
    stats = get_coverage_stats(inventory)
    total_files = inventory.get('total_files', 0)
    excluded = len(inventory.get('excluded_files', []))
    sloc = stats.get('total_sloc', 0)

    # Inventory line: files, SLOC, items by kind
    _PLURALS = {"function": "functions", "global": "globals", "macro": "macros", "class": "classes"}
    kind_parts = []
    for kind, counts in sorted(stats.get('by_kind', {}).items()):
        label = _PLURALS.get(kind, kind + "s")
        kind_parts.append(f"{counts['total']} {label}")
    items_str = ", ".join(kind_parts) if kind_parts else f"{stats['total_items']} items"

    inv_line = f"Inventory: {total_files} files, {sloc:,} SLOC, {items_str}"
    if excluded:
        inv_line += f" ({excluded} excluded)"
    lines = [inv_line]

    if stats['checked_items'] > 0:
        lines.append(
            f"Coverage: {stats['checked_items']}/{stats['total_items']} "
            f"items checked ({stats['coverage_percent']:.1f}%)"
        )
        for source, count in sorted(stats['by_source'].items()):
            lines.append(f"  - {source}: {count}")

    limitations = inventory.get('limitations', [])
    if limitations:
        lines.append("Limitations: " + "; ".join(limitations))

    return '\n'.join(lines)
