"""Structured AST-view enrichment for /understand --trace.

After ``/understand --trace`` produces ``flow-trace-<id>.json``
files (step-by-step source→sink walks), this module attaches a
per-step ``ast_view`` block to each step whose ``definition``
field resolves to a function in the inventory. The LLM following
the trace — or consuming the trace via the understand-bridge
into /validate Stage B — gets the host function's compact shape
(signature, calls inside body, returns, inline-asm flag) at
every hop.

This is a sibling of ``context_map_ast_view`` (PR2 for
``/understand --map`` entry points and sinks). The two cover
the two output products of ``/understand`` that anchor
downstream reasoning: the static attack-surface map and the
dynamic data-flow traces.

## Output shape

Each step in ``trace["steps"]`` gains an ``ast_view`` field
containing :func:`core.ast.view`'s ``FunctionView.to_dict()``
output for the enclosing function at the step's ``definition``
file:line:

    {
      "step": 2,
      "type": "call",
      "call_site": "src/routes/query.py:48",
      "definition": "src/services/query_service.py:12",
      "description": "...",
      ...,
      "ast_view": {
        "function": "run",
        "language": "python",
        "lines": [12, 35],
        "signature": "run(query_str: str) -> ResultSet",
        "calls_made": [
          {"line": 31, "chain": ["psycopg2", "cursor", "execute"], ...}
        ],
        "returns": [{"line": 34, "value_text": "result"}],
        "has_inline_asm": false,
        "schema_version": 1
      }
    }

The ``ast_view`` field is absent (rather than null) when:

  * The step has no ``definition`` field or it doesn't parse as
    ``file:line``.
  * The definition's file path escapes ``target_root`` (defence
    in depth — trace files are LLM output and may carry injected
    entries; same path-containment check as the map enricher).
  * The file isn't in the inventory (e.g. external dep — typical
    for sink steps where ``definition`` points at a library
    function like ``psycopg2.cursor.execute()``).
  * ``core.ast.view`` returns None (parse failure / unsupported
    language).

The ``call_site`` field is NOT enriched in this revision. The
caller's function shape is interesting in principle but doubles
the per-step token cost; ``definition`` enrichment alone gives
the LLM the function being stepped *into*, which is the new
context at each hop. Follow-up if measurement shows the LLM
needs caller-side shape too.

Idempotent — re-running overwrites prior enrichment with fresh
data, except a pre-existing ``ast_view`` is preserved
(consistent with the map enricher and the agent enrichment).
Best-effort: any individual step's failure leaves that step
unchanged but doesn't abort the run.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ``file:line`` with file optionally containing slashes/dots and line
# being a non-zero positive integer. Anchored — partial matches don't
# count (a malformed string like ``foo:bar:42`` should fail to parse
# rather than capturing some sub-fragment).
_DEFINITION_RE = re.compile(r"^(.+):(\d+)$")


def enrich_with_ast_view(
    trace: Dict[str, Any],
    target_path: Path,
    *,
    inventory: Optional[Dict[str, Any]] = None,
) -> int:
    """Walk ``trace["steps"]`` and attach an ``ast_view`` field to
    each step whose ``definition`` resolves to an in-inventory
    function.

    ``inventory`` may be provided by the caller (avoids a redundant
    inventory build when a sibling consumer already constructed
    one). When omitted, builds one over ``target_path``.

    Returns the count of steps enriched. Idempotent — re-running
    overwrites prior enrichment with fresh data.
    """
    if not isinstance(trace, dict):
        return 0
    steps = trace.get("steps")
    if not isinstance(steps, list) or not steps:
        return 0

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                              # noqa: BLE001
            logger.debug(
                "flow_trace_ast_view: inventory build failed (%s); "
                "skipping enrichment", e,
            )
            return 0

    try:
        from core.ast import view
        from core.inventory.reachability import enclosing_function
    except ImportError:
        return 0

    target_root = Path(target_path).resolve()
    enriched = 0

    for step in steps:
        if not isinstance(step, dict):
            continue
        if step.get("ast_view"):
            continue  # already set (e.g. carried forward)

        definition = step.get("definition")
        if not isinstance(definition, str) or not definition:
            continue

        parsed = _parse_definition(definition)
        if parsed is None:
            continue
        file_path, line = parsed

        host = enclosing_function(inventory, file_path, line)
        if host is None:
            # External function (typical for sink steps) or path
            # not in inventory. Skip — don't fabricate.
            continue

        abs_path = (target_root / file_path).resolve()
        # Defence: trace files are LLM output; reject paths that
        # escape target_root (absolute or traversal).
        try:
            abs_path.relative_to(target_root)
        except ValueError:
            logger.debug(
                "flow_trace_ast_view: skipping step whose definition "
                "%r escapes target_root %s", file_path, target_root,
            )
            continue
        if not abs_path.is_file():
            continue

        try:
            fv = view(abs_path, host.name, at_line=line)
        except Exception:                                   # noqa: BLE001
            continue
        if fv is None:
            continue

        step["ast_view"] = fv.to_dict()
        enriched += 1

    if enriched:
        logger.info(
            "flow_trace_ast_view: enriched %d step(s) with ast_view",
            enriched,
        )
    return enriched


def _parse_definition(definition: str) -> Optional[Tuple[str, int]]:
    """Parse a step's ``definition`` field into ``(file_path, line)``.

    Returns None for unparseable input — module-level entries (no
    line), external references (no file:line), or malformed strings.
    The line must be a positive integer; zero is rejected because
    ``core.inventory.reachability.enclosing_function`` requires
    ``line >= 1``.
    """
    m = _DEFINITION_RE.match(definition.strip())
    if m is None:
        return None
    try:
        line = int(m.group(2))
    except ValueError:
        return None
    if line < 1:
        return None
    return m.group(1), line


__all__ = ["enrich_with_ast_view"]
