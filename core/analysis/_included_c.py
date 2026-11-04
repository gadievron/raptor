"""Inventory-only links for C implementation files included by a wrapper."""

from __future__ import annotations

import posixpath


_IMPLEMENTATIONS = (".c", ".cc", ".cpp", ".cxx")


def implementation_includes(inventory: dict) -> dict[str, tuple[str, ...]]:
    """Resolve direct, relative implementation includes to inventoried files.

    This is narrower than linking same-named functions across C files:
    static helpers are visible in a wrapper only through its explicit
    include. Headers and non-C imports do not establish these links.
    No filesystem reads or compiler search-path guesses are involved.
    """
    files = {
        record["path"]: record
        for record in inventory.get("files", [])
        if isinstance(record, dict) and isinstance(record.get("path"), str)
        and record.get("language") in ("c", "cpp")
    }
    included = {}
    for path, record in files.items():
        imports = (record.get("call_graph") or {}).get("imports") or {}
        targets = set()
        for spec in imports.values():
            if not isinstance(spec, str) or not spec.endswith(_IMPLEMENTATIONS):
                continue
            if posixpath.isabs(spec):
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
            if target != path and target in files:
                targets.add(target)
        if targets:
            included[path] = tuple(sorted(targets))
    return included
