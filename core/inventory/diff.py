"""Inventory comparison by SHA-256 checksums."""

from typing import Any


def compare_inventories(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any] | None:
    """Compare two inventories by SHA-256 to detect source material changes.

    Returns None if nothing changed, otherwise a dict describing the changes.
    """
    old_shas = {f['path']: f.get('sha256') for f in old.get('files', []) if 'path' in f}
    new_shas = {f['path']: f.get('sha256') for f in new.get('files', []) if 'path' in f}

    # If old inventory has no sha256 fields, can't compare
    if not any(old_shas.values()):
        import logging
        logging.getLogger(__name__).warning(
            "Old inventory has no SHA-256 checksums — cannot compare"
        )
        return None

    old_keys = old_shas.keys()
    new_keys = new_shas.keys()
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(
        p for p in old_keys & new_keys
        if old_shas[p] and new_shas[p] and old_shas[p] != new_shas[p]
    )

    # Compare binary (for backwards compat with validation checklists).
    #
    # Pre-fix the boolean reduction was:
    #   binary_changed = bool(
    #       old_bin_sha and new_bin_sha and old_bin_sha != new_bin_sha
    #   )
    # — short-circuits to False whenever EITHER sha is None or
    # missing. Three operationally-significant cases were
    # silently treated as "no change":
    #
    #   1. Old has a binary, new doesn't (binary deleted between
    #      runs).
    #   2. New has a binary, old didn't (binary added — new build
    #      target landed).
    #   3. Both inventories present but only one populated the
    #      `binary.sha256` field (a mid-flight schema migration,
    #      or one inventory was built before the binary-sha
    #      pipeline ran).
    #
    # In every case the diff caller (typically the validation-
    # checklist freshness check) decided "no rebuild needed",
    # carrying stale validation results forward across a binary
    # change. Operators saw "checklist still fresh" verdicts
    # against binaries that no longer existed, or against new
    # binaries that had never been validated.
    #
    # Treat presence asymmetry as a CHANGE: if either side has a
    # sha and they differ (including one-being-None), flag it.
    old_bin_sha = (old.get('binary') or {}).get('sha256')
    new_bin_sha = (new.get('binary') or {}).get('sha256')
    if old_bin_sha is None and new_bin_sha is None:
        binary_changed = False
    else:
        binary_changed = old_bin_sha != new_bin_sha

    if not added and not removed and not modified and not binary_changed:
        return None

    diff = {
        'source_changed': bool(added or removed or modified),
        'binary_changed': binary_changed,
        'added': added,
        'removed': removed,
        'modified': modified,
    }
    if binary_changed:
        diff['binary_old_sha256'] = old_bin_sha
        diff['binary_new_sha256'] = new_bin_sha

    return diff


def _items_by_key(file_info: dict[str, Any]) -> dict[tuple, str | None]:
    """``(name, kind) → span_hash`` for a file record's items.

    First occurrence wins for duplicate names (overloads); interstitial
    residue is skipped — it is synthetic, not a reviewable unit — EXCEPT
    spans stamped ``script_handler: true``: those are the reviewable
    units of script-per-file files (classic PHP request handlers), so
    the new-code / carry-forward diff must track them like functions.
    A missing stamp keeps the old skip on that SIDE only. OLD side
    unstamped (the normal pre-stamp-inventory case): the stamped new
    side's span has no old key and reports as added — the over-boost
    direction. NEW side unstamped is the one direction that hides a
    changed span from this diff entirely (neither added nor changed);
    it is reachable only by downgrading the builder or hand-editing
    the run-dir JSON — every forward build stamps — and this diff
    feeds a priority signal, not a verdict gate, so the residual is
    accepted and named rather than guarded.
    """
    from .script_handler import script_handler_stamp

    out: dict[tuple, str | None] = {}
    for item in file_info.get('items', file_info.get('functions', [])) or []:
        name = item.get('name')
        kind = item.get('kind', 'function')
        if not name or (kind == 'interstitial'
                        and script_handler_stamp(item) is not True):
            continue
        out.setdefault((name, kind), item.get('span_hash') or None)
    return out


def function_level_diff(
    old: dict[str, Any], new: dict[str, Any],
) -> dict[str, list[str]]:
    """Function-level added/changed keys between two inventories.

    Hash-based: items carry a ``span_hash`` (SHA-256[:12] of the raw
    span lines, stamped by the builder) and an item counts as changed
    only when its hash differs. Items missing a hash on either side
    (pre-hash inventories) degrade conservatively to *changed* — this
    feeds a priority signal, so over-boosting beats silently missing
    new code. The same FN-safe direction absorbs extractor-path span
    drift: for a split return type (``static char *\\nfoo(...)``) the
    C regex path stamps ``line_start`` at the name line while
    tree-sitter stamps the type line, so a file flipping between
    grammar-present and grammar-absent environments reports such
    functions as changed — over-boost, never suppression.

    Only files reported added/modified by :func:`compare_inventories`
    are examined. Returns ``{"functions_added": [...],
    "functions_changed": [...]}`` with ``file:name`` keys.
    """
    file_diff = compare_inventories(old, new)
    if file_diff is None:
        return {'functions_added': [], 'functions_changed': []}

    added_files = set(file_diff.get('added') or [])
    modified_files = set(file_diff.get('modified') or [])
    old_by_path = {f['path']: f for f in old.get('files', []) if 'path' in f}

    fn_added: list[str] = []
    fn_changed: list[str] = []
    for file_info in new.get('files', []):
        path = file_info.get('path')
        if not path:
            continue
        if path in added_files:
            fn_added.extend(
                f"{path}:{name}" for name, _kind in _items_by_key(file_info))
            continue
        if path not in modified_files:
            continue
        old_items = _items_by_key(old_by_path.get(path, {}))
        for (name, kind), new_hash in _items_by_key(file_info).items():
            key = f"{path}:{name}"
            if (name, kind) not in old_items:
                fn_added.append(key)
                continue
            old_hash = old_items[(name, kind)]
            if not old_hash or not new_hash or old_hash != new_hash:
                fn_changed.append(key)

    return {
        'functions_added': sorted(set(fn_added)),
        'functions_changed': sorted(set(fn_changed)),
    }
