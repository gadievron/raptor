"""Dataclasses for the per-function AST view.

Schema is frozen + JSON-serialisable so consumers (``/understand --map``,
``/audit`` annotations) can persist the view alongside their own output
without losing precision on round-trip.

``CallSite`` (from ``core.inventory.call_graph``) is reused verbatim
for the calls list — no conversion at the boundary. The field set
(``line`` / ``chain`` / ``caller``) is already what an AST view of
calls needs, and the future ``core.treesitter`` lift would move
``CallSite`` to that substrate anyway.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

# Re-exported so ``core.ast`` consumers don't have to know it lives in
# inventory. When the future ``core.treesitter`` lift happens, this
# import moves and ``core.ast`` callers are unaffected.
from core.inventory.call_graph import CallSite  # noqa: F401  (re-export)


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Return:
    """One return statement in the function body.

    ``value_text`` is the raw text between ``return`` and the
    statement terminator, preserved verbatim — no AST parsing of the
    return expression. Empty string for bare ``return`` statements.
    The text is for human / LLM inspection; downstream consumers that
    want structure parse it themselves.

    Implicit returns (end of function in Python, void function falling
    off the end in C) are NOT emitted — only explicit ``return``
    statements. Callers that need "all exit points" should union
    explicit returns with the function's end line themselves.
    """

    line: int
    value_text: str  # empty for bare `return`


@dataclass(frozen=True)
class FunctionView:
    """Structured view of one function.

    The function is identified by ``(file, function, lines)``. When
    multiple functions in one file share a name (e.g. methods of
    different classes), the line range is the unambiguous identifier.

    ``calls_made`` is a tuple of ``CallSite`` (re-used from
    ``core.inventory.call_graph``). Each call records the callee's
    attribute chain and the line; argument text is NOT preserved at
    this revision (callers that need it should re-extract from
    source). See module docstring for the reuse rationale.

    ``has_inline_asm`` is true if the function body contains any
    inline assembly construct in C/C++ (``asm``, ``__asm__``,
    ``__asm``, with or without ``volatile``). The flag is for
    consumers that want to deprioritise / specially-handle functions
    that include opaque assembly; the actual asm text is not parsed.
    For non-C/C++ languages the flag is always false.

    ``language`` is the canonical language string used elsewhere in
    RAPTOR (matches ``core.inventory.languages.LANGUAGE_MAP``
    values).
    """

    function: str
    file: str
    language: str
    lines: Tuple[int, int]  # (start, end), 1-indexed inclusive
    signature: str
    calls_made: Tuple[CallSite, ...]
    returns: Tuple[Return, ...]
    has_inline_asm: bool
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for JSON output (``/understand --map``, CLI)."""
        return {
            "function": self.function,
            "file": self.file,
            "language": self.language,
            "lines": [self.lines[0], self.lines[1]],
            "signature": self.signature,
            "calls_made": [
                {
                    "line": c.line,
                    "chain": list(c.chain),
                    "caller": c.caller,
                    "receiver_class": c.receiver_class,
                }
                for c in self.calls_made
            ],
            "returns": [{"line": r.line, "value_text": r.value_text} for r in self.returns],
            "has_inline_asm": self.has_inline_asm,
            "schema_version": self.schema_version,
        }
