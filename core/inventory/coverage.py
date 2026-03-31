"""Coverage tracking with checked_by labels."""

from typing import Any, Dict, List


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
    checked_set = {(f['file'], f['function']) for f in checked_functions}

    for file_info in inventory.get('files', []):
        for func in file_info.get('functions', []):
            key = (file_info['path'], func['name'])
            if key in checked_set:
                checked_by = func.get('checked_by', [])
                if source_label not in checked_by:
                    checked_by.append(source_label)
                func['checked_by'] = checked_by

    return inventory


def get_coverage_stats(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """Compute coverage statistics from an inventory.

    Returns:
        Dict with total_functions, checked_functions, coverage_percent,
        and by_source breakdown.
    """
    total = 0
    checked = 0
    by_source: Dict[str, int] = {}

    for file_info in inventory.get('files', []):
        for func in file_info.get('functions', []):
            total += 1
            checked_by = func.get('checked_by', [])
            if checked_by:
                checked += 1
                for source in checked_by:
                    by_source[source] = by_source.get(source, 0) + 1

    return {
        'total_functions': total,
        'checked_functions': checked,
        'coverage_percent': (checked / total * 100) if total > 0 else 0,
        'by_source': by_source,
    }


def format_coverage_summary(inventory: Dict[str, Any]) -> str:
    """Format a human-readable coverage summary.

    Returns a multi-line string for printing to stdout.
    """
    stats = get_coverage_stats(inventory)
    total_files = inventory.get('total_files', 0)
    excluded = len(inventory.get('excluded_files', []))

    lines = [
        f"Inventory: {total_files} files, {stats['total_functions']} functions"
        + (f" ({excluded} excluded)" if excluded else ""),
    ]

    if stats['checked_functions'] > 0:
        lines.append(
            f"Coverage: {stats['checked_functions']}/{stats['total_functions']} "
            f"functions checked ({stats['coverage_percent']:.1f}%)"
        )
        for source, count in sorted(stats['by_source'].items()):
            lines.append(f"  - {source}: {count}")

    return '\n'.join(lines)
