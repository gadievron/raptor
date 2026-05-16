"""Inventory comparison by SHA-256 checksums."""

from typing import Any, Dict, Optional


def compare_inventories(old: Dict[str, Any], new: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Compare two inventories by SHA-256 to detect source material changes.

    Returns None if nothing changed, otherwise a dict describing the changes.
    """
    old_shas = {f['path']: f.get('sha256') for f in old.get('files', [])}
    new_shas = {f['path']: f.get('sha256') for f in new.get('files', [])}

    # If old inventory has no sha256 fields, can't compare
    if not any(old_shas.values()):
        import logging
        logging.getLogger(__name__).warning(
            "Old inventory has no SHA-256 checksums — cannot compare"
        )
        return None

    added = sorted(set(new_shas) - set(old_shas))
    removed = sorted(set(old_shas) - set(new_shas))
    modified = sorted(
        p for p in set(old_shas) & set(new_shas)
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
    old_bin_sha = old.get('binary', {}).get('sha256')
    new_bin_sha = new.get('binary', {}).get('sha256')
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
