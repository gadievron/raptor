"""Coverage tracking with checked_by labels."""

from typing import Any

from .checklist_mac import TOKEN_MAP_KEY, mint_checked_claim


def _get_items(file_info):
    """Read code items from a file entry. Handles both old and new format."""
    return file_info.get("items", file_info.get("functions", [])) or []


def update_coverage(
    inventory: dict[str, Any],
    checked_functions: list[dict[str, str]],
    source_label: str,
) -> dict[str, Any]:
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
    #
    # Coverage key includes `class` so two methods named `do_thing`
    # in different classes within the same file resolve as
    # distinct functions when the CALLER carries class info.
    # Real-world hit: any python file with `__init__`, `__repr__`,
    # `from_dict`, `to_dict` etc. defined on multiple classes (very
    # common). The item side derives its class from
    # `metadata.class_name` — the shape the extractors actually
    # serialise; inventory items never carry a bare `class` key, so
    # reading only that key made the disambiguation dead (every item
    # keyed `(path, "", name)`) and a caller passing the documented
    # `{"class": ...}` shape matched NOTHING and silently lost all
    # its marks. Callers without class info fall back to bare-name
    # match (legacy callers keep working; bare names inherently
    # smear across same-named twins — carry `class` to avoid that).
    checked_set = set()
    for f in checked_functions:
        if not (isinstance(f, dict) and f.get('file') and f.get('function')):
            continue
        cls = f.get('class') or ""
        checked_set.add((f['file'], cls, f['function']))

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
            meta = func.get('metadata')
            cls = (
                (meta.get('class_name') if isinstance(meta, dict) else None)
                or func.get('class')
                or ""
            )
            # Prefer (path, class, name); fall back to (path, "", name)
            # for legacy callers that didn't carry class info.
            key = (path, cls, name)
            legacy_key = (path, "", name)
            if key in checked_set or legacy_key in checked_set:
                checked_by = func.get('checked_by') or []
                if source_label not in checked_by:
                    checked_by.append(source_label)
                func['checked_by'] = checked_by
                # Mint chokepoint: this is the only code that ADDS a
                # checked_by label, so the review claim is stamped
                # here, at creation — read-modify-write writers
                # (rebuild carry-forward, project promotion) copy
                # tokens verbatim and the coverage backfill demotes
                # unverified claims to the machine hint tier
                # (core/inventory/checklist_mac.py). Minted even when
                # the label was already present: a re-mark is a fresh
                # genuine review, and re-minting heals a token that
                # went stale with the source. None (no usable key)
                # persists unstamped — never a write failure.
                token = mint_checked_claim(file_info, func, source_label)
                if token:
                    mac_map = func.get(TOKEN_MAP_KEY)
                    if not isinstance(mac_map, dict):
                        mac_map = {}
                    mac_map[source_label] = token
                    func[TOKEN_MAP_KEY] = mac_map

    return inventory


def get_coverage_stats(inventory: dict[str, Any]) -> dict[str, Any]:
    """Compute coverage statistics from an inventory.

    Returns:
        Dict with total/checked counts (overall and by kind),
        SLOC stats, coverage_percent, and by_source breakdown.
    """
    total = 0
    checked = 0
    by_source: dict[str, int] = {}
    by_kind: dict[str, dict[str, int]] = {}  # kind -> {total, checked}

    for file_info in inventory.get('files', []):
        for item in _get_items(file_info):
            total += 1
            kind = item.get('kind', 'function')

            if kind not in by_kind:
                by_kind[kind] = {"total": 0, "checked": 0}
            by_kind[kind]["total"] += 1

            checked_by = item.get('checked_by') or []
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


def format_coverage_summary(inventory: dict[str, Any]) -> str:
    """Format a human-readable coverage summary.

    Returns a multi-line string for printing to stdout.
    """
    stats = get_coverage_stats(inventory)
    total_files = inventory.get('total_files', 0)
    excluded = len(inventory.get('excluded_files') or [])
    sloc = stats.get('total_sloc', 0)

    # Inventory line: files, SLOC, items by kind
    _PLURALS = {"function": "functions", "global": "globals", "macro": "macros", "class": "classes"}
    kind_parts = []
    for kind, counts in sorted((stats.get('by_kind') or {}).items()):
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
