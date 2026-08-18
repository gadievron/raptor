"""Annotation dataclass — the in-memory shape of one per-function
record. See :mod:`core.annotations` for the on-disk format and
storage rationale."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


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
      * ``source``: ``human`` / ``agent`` / ``llm`` — who claims to
        have written the annotation (caller-asserted; readers grade
        it against the provenance stamp). The CLI defaults to
        ``human`` for interactive invocations and ``agent`` for
        non-interactive ones; ``llm`` marks legacy pre-migration
        LLM annotations.
        ``write_annotation(..., overwrite="respect-manual")`` skips
        writes whose existing record has ``source=human`` so
        scripted passes never clobber operator notes.
      * ``tty`` / ``provenance``: the invocation-context stamp the
        CLI records on every add/edit — which std fds were TTYs,
        and the derived ``interactive-tty`` / ``non-tty`` tag (see
        :mod:`core.annotations.provenance`). Annotations without
        the stamp are legacy (pre-stamp); readers give
        ``source=human`` ones benefit-of-doubt.
      * ``hash``: short sha256 prefix of the function's source lines,
        captured at annotation time so callers can detect a stale
        annotation when the source edits later. Use
        ``core.annotations.compute_function_hash`` to populate.

    Other keys are accepted; readers tolerate unknown keys to allow
    consumer-specific extensions without schema migrations.
    """

    file: str
    function: str
    body: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)
