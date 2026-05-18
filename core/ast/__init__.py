"""Structured per-function views built over the inventory substrate.

The inventory (``core.inventory.extractors``, ``core.inventory.call_graph``)
answers two file-/codebase-level questions:

  * "What functions exist?" — ``extract_functions(filepath, language, content)``
  * "What does this file call?" — ``extract_call_graph_<lang>(content)``

``core.ast`` answers a third, per-function-level question:

  * "What is the shape of *this one* function?" — its signature, the
    calls it makes, where it returns, whether it embeds inline asm.

The intended consumers are ``/understand --map`` (entry-point + sink
records gain an ``ast_view`` block), ``/validate`` Stage B (path
enumeration uses ``calls_made``), and ``/audit`` Phase A (per-function
review).

This package is a **composition layer**, not new parsing
infrastructure. It reuses the per-language tree-sitter walkers already
shipped in ``core.inventory``. The dependency direction reads oddly
("AST view depends on inventory") because inventory's name is
misleading — its per-language walkers are reusable substrate, not a
higher-level domain concept. A future refactor may lift the walkers
into ``core.treesitter.walkers`` and have both ``core.inventory`` and
``core.ast`` consume them; that's deferred until a third consumer
makes the duplication painful.

Public surface:

  * ``view(path, function, *, at_line=None, language=None) -> Optional[FunctionView]``
  * ``FunctionView`` dataclass (re-exported from ``.model``)
  * ``Return`` dataclass (re-exported from ``.model``)
  * ``CallSite`` is re-used as-is from ``core.inventory.call_graph``;
    no conversion layer.

Language coverage (PR1): python, javascript, java, go, c, cpp.
"""

from __future__ import annotations

from core.ast.model import FunctionView, Return
from core.ast.view import view

__all__ = ["view", "FunctionView", "Return"]
