"""Ordered peer-group selection with a small sibling-membership index."""

from __future__ import annotations


def _plain_identity(key):
    return (type(key[0]) is str or key[0] is None) and (type(key[1]) is str or key[1] is None)


def _scan(gaps, siblings):
    return [gap for gap in gaps if any(
        sibling.function == gap.get("name") and sibling.file == gap.get("file")
        for sibling in siblings
    )]


def select_peer_gaps(gaps, siblings):
    """Preserve gap order, duplicate rows and object identities.

    Index the small sibling population, not the entire gap queue: this
    removes the inner scan without retaining another codebase-sized map.
    Missing names/paths (None) differ from empty strings. Unusual producer
    values and non-sequence siblings retain the original comparison path.
    """
    keys = set()
    if type(siblings) in (list, tuple):
        for sibling in siblings:
            key = (getattr(sibling, "function", object()),
                   getattr(sibling, "file", object()))
            if not _plain_identity(key):
                break
            keys.add(key)
        else:
            if not keys:
                return _scan(gaps, siblings)
            selected = []
            for gap in gaps:
                key = (gap.get("name"), gap.get("file"))
                if _plain_identity(key):
                    matches = key in keys
                else:
                    matches = any(s.function == gap.get("name")
                                  and s.file == gap.get("file") for s in siblings)
                if matches:
                    selected.append(gap)
            return selected
    return _scan(gaps, siblings)
