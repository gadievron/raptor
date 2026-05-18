"""Structured AST-view enrichment for /understand --map.

After ``/understand --map`` produces ``context-map.json`` (entry
points + sinks + trust boundaries) and the normaliser runs, this
module attaches a per-function ``ast_view`` block to each entry
point and sink. Operators reading the map see the LLM's narrative
plus the machine-derived structural view (signature, calls made,
returns, inline-asm flag) for the enclosing host function.

This is the second consumer of ``core.ast.view`` after the
libexec CLI shim — the substrate-then-wire-in pattern from
``project_core_ast.md``. Downstream of this enrichment, ``/audit``
Phase A consumes ``context-map.json`` through the standard
understand-bridge channel and gets the AST view for free.

## Output shape

Each entry point and sink dict gains an ``ast_view`` field
containing :func:`core.ast.view`'s ``FunctionView.to_dict()``
output:

    {
        "id": "EP-001",
        "file": "src/routes/query.py",
        "line": 34,
        ...,
        "ast_view": {
            "function": "handle_query",
            "file": "src/routes/query.py",
            "language": "python",
            "lines": [34, 56],
            "signature": "handle_query(request: Request) -> Response",
            "calls_made": [
                {"line": 38, "chain": ["execute_query"], ...},
                ...
            ],
            "returns": [{"line": 55, "value_text": "response"}, ...],
            "has_inline_asm": false,
            "schema_version": 1
        }
    }

The ``ast_view`` field is absent (rather than null) when:

  * The entry's ``file``/``line`` doesn't resolve to a function
    in the inventory (module-level entry, path missing from
    inventory).
  * ``core.ast.view`` returns None — file unreadable / language
    unsupported / parser unavailable.

Idempotent — re-running overwrites prior enrichment with fresh
data. Best-effort: any individual entry's failure leaves that
entry unchanged but doesn't abort the run.

## Why both entry points and sinks?

Audit prompts want shape for the function under review regardless
of whether it's an attack surface or a destination. The
callgraph enricher only walks entry points because forward-
reachable closures originate at entries; ``ast_view`` is about
the function itself, so it applies equally to sinks.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def enrich_with_ast_view(
    context_map: Dict[str, Any],
    target_path: Path,
    *,
    inventory: Optional[Dict[str, Any]] = None,
) -> int:
    """Walk ``context_map``'s ``entry_points`` and ``sinks`` lists
    and attach an ``ast_view`` field to each entry whose
    ``(file, line)`` resolves to an enclosing function.

    ``inventory`` may be provided by the caller (avoids a redundant
    inventory build when a sibling consumer already constructed
    one). When omitted, builds one over ``target_path``.

    Returns the count of entries enriched (sum across entry points
    and sinks). Idempotent — re-running overwrites prior enrichment.
    """
    if not isinstance(context_map, dict):
        return 0

    sections: List[List[Any]] = []
    for key in ("entry_points", "sinks"):
        sec = context_map.get(key)
        if isinstance(sec, list) and sec:
            sections.append(sec)
    if not sections:
        return 0

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                              # noqa: BLE001
            logger.debug(
                "context_map_ast_view: inventory build failed (%s); "
                "skipping enrichment", e,
            )
            return 0

    try:
        from core.ast import view
        from core.inventory.reachability import enclosing_function
    except ImportError:
        return 0

    enriched_count = 0
    target_root = Path(target_path).resolve()

    for section in sections:
        for entry in section:
            if not isinstance(entry, dict):
                continue
            file_path = entry.get("file") or entry.get("file_path")
            line = entry.get("line") or entry.get("line_start")
            if not isinstance(file_path, str) or not file_path:
                continue
            if not isinstance(line, int) or line <= 0:
                continue

            host = enclosing_function(inventory, file_path, line)
            if host is None:
                # Module-level entry, or path/line not in inventory.
                # Skip rather than emitting a placeholder.
                continue

            # context-map paths are repo-relative; resolve under
            # target_root for view() which needs an absolute or
            # CWD-resolvable path.
            #
            # Defence: context-map.json is LLM output and may carry
            # injected entries (e.g. via prompt injection in the
            # scanned repo). Reject paths that escape target_root —
            # absolute paths (``/etc/passwd``) and traversal
            # (``../../etc/passwd``) both. ``Path.resolve()`` follows
            # symlinks, so symlinked-out files are also caught.
            abs_path = (target_root / file_path).resolve()
            try:
                abs_path.relative_to(target_root)
            except ValueError:
                logger.debug(
                    "context_map_ast_view: skipping entry whose file "
                    "%r escapes target_root %s",
                    file_path, target_root,
                )
                continue
            if not abs_path.is_file():
                # File missing on disk (stale map, moved/deleted).
                # Skip — don't fabricate an ast_view.
                continue

            try:
                fv = view(abs_path, host.name, at_line=line)
            except Exception:                              # noqa: BLE001
                # core.ast.view is documented as returning None on
                # error, but defensively swallow exceptions too —
                # one bad entry must not block the rest.
                continue
            if fv is None:
                continue

            entry["ast_view"] = fv.to_dict()
            enriched_count += 1

    if enriched_count:
        logger.info(
            "context_map_ast_view: enriched %d map entry(ies) with "
            "ast_view", enriched_count,
        )
    return enriched_count


__all__ = ["enrich_with_ast_view"]
