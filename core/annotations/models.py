"""Annotation dataclass — the in-memory shape of one per-function
record. See :mod:`core.annotations` for the on-disk format and
storage rationale."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class Annotation:
    """One function's annotation.

    ``file``: source file path. Stored exactly as supplied; callers
    use repo-relative paths consistently so the resulting markdown
    layout mirrors the source tree.

    ``function``: function identifier. Top-level functions: bare
    name (``foo``). Class methods: dotted (``Klass.method``).
    Operators / mangled names: caller's responsibility to choose
    a stable string.

    ``body``: free-form markdown prose. May be empty (a clean-status
    annotation can carry just metadata). The body is preserved
    verbatim across read-write round-trips.

    ``metadata``: structured key=value pairs from the HTML-comment
    frontmatter (``<!-- meta: status=clean cwe=CWE-78 -->``).
    Conventional keys:
      * ``status``: ``clean`` / ``suspicious`` / ``finding`` /
        ``error`` (matches the audit coverage status enum)
      * ``cwe``: e.g. ``CWE-78``
      * ``hash``: source-line hash captured at annotation time, so
        callers can detect stale annotations after the source has
        edited.

    Other keys are accepted; readers tolerate unknown keys to allow
    consumer-specific extensions without schema migrations.
    """

    file: str
    function: str
    body: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)
