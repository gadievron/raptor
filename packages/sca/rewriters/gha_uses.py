"""GitHub Actions ``uses: <owner>/<repo>@<ref>`` in-place rewriter.

The bumper-orchestrator emits :class:`RewriteEdit` records with
``locator`` set to ``"<owner>/<repo>"`` (e.g.
``"actions/checkout"``) and the ref (tag) as
``old_value`` / ``new_value``. This rewriter walks the GHA YAML
file, matches each ``uses:`` line against the locator, and
rewrites the ref portion.

Phase 3.b MVP scope:

* **Tag-pinned**: ``uses: actions/checkout@v4`` — supported.
  Rewritten to ``uses: actions/checkout@<new_tag>``.
* **SHA-pinned with comment**: ``uses: actions/checkout@<40hex>  # was v4``
  — NOT supported by this rewriter. Phase 3.b.2 will add it,
  requiring tag→SHA resolution at edit construction time.
  Currently silently skipped (the walker doesn't emit
  candidates for SHA-pinned refs).
* **Branch-pinned**: ``uses: foo/bar@main`` — silently skipped
  (auto-bumping a branch ref to a tag is a security upgrade we
  could surface in a future commit; not in scope here).

Same atomic-write + idempotent + value-mismatch semantics as
the Dockerfile rewriters."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _is_gha_workflow(path: Path) -> bool:
    """Predicate: path is a GHA workflow file
    (``.github/workflows/*.yml`` or ``*.yaml``)."""
    if path.suffix not in (".yml", ".yaml"):
        return False
    parts = path.parts
    for i in range(len(parts) - 2):
        if parts[i] == ".github" and parts[i + 1] == "workflows":
            return True
    return False


@register(predicate=_is_gha_workflow)
def rewrite_gha_uses(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply ``uses:`` ref-bump edits to a GHA workflow file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=e2, applied=False,
                              reason=f"error: read failed: {e}")
                for e2 in edits]

    new_text = text
    results: List[RewriteResult] = []
    for edit in edits:
        new_text, result = _apply_one_uses(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    for r in results]
    return results


def _apply_one_uses(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
    """Apply one ``uses:`` edit — either tag-pinned or
    SHA-pinned-with-comment.

    SHA+comment shape (Phase 3.b.2): when ``edit.extra`` carries
    ``{"old_sha": ..., "new_sha": ...}``, the rewriter targets
    ``uses: <repo>@<old_sha>  # was <old_value>`` and rewrites
    BOTH the SHA and the ``# was vX`` comment in one pass.

    Tag-pinned shape (Phase 3.b): ``edit.extra`` is None;
    rewriter targets ``uses: <repo>@<old_value>`` and rewrites
    the tag.

    The locator is ``<owner>/<repo>`` (e.g.
    ``actions/checkout``). Sub-action paths
    (``github/codeql-action/init``) are matched as
    ``<locator>/<subpath>@``; the subpath stays untouched."""
    if edit.extra and edit.extra.get("old_sha"):
        return _apply_sha_pinned(text, edit)
    # The locator may be the bare repo (``actions/checkout``)
    # OR the repo with a sub-action path (``github/codeql-action``
    # used as ``github/codeql-action/init``). Match the locator
    # as a prefix; allow optional ``/<subpath>`` between locator
    # and ``@``.
    locator = re.escape(edit.locator)
    # Allow YAML list marker (``- uses:``) and arbitrary
    # indentation. Three groups: prefix (everything up to + ``@``),
    # the ref value, and the trailing boundary char.
    pattern = re.compile(
        rf"^(\s*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)"
        rf"([^\s#]+)"                    # ref (up to whitespace or comment)
        rf"(\s|$|#)",                    # boundary
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current_ref = match.group(2)
    # SHA-pinned refs (40-char hex) are Phase 3.b.2 territory.
    # The walker doesn't emit candidates for them today, so
    # encountering one here is a signal that something's off —
    # refuse politely.
    if _looks_like_sha(current_ref):
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                "value_mismatch: file uses SHA-pinned ref "
                f"{current_ref[:12]}..., bumper only handles "
                "tag-pinned refs in Phase 3.b"
            ),
        )
    if current_ref == edit.new_value:
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if current_ref != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {current_ref!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    new_text = pattern.sub(
        rf"\g<1>{edit.new_value}\g<3>",
        text, count=1,
    )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


_SHA_RE = re.compile(r"^[a-f0-9]{40}$")


def _looks_like_sha(ref: str) -> bool:
    return _SHA_RE.match(ref) is not None


def _apply_sha_pinned(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
    """Apply a SHA-pinned-with-``# was vX``-comment edit.

    Targets the canonical raptor shape:

        uses: actions/checkout@<40hex>  # was v6

    Rewrites both the SHA and the ``# was vX`` comment in one
    pass. Both edit.extra["old_sha"] and edit.extra["new_sha"]
    are required.

    The ``old_value`` / ``new_value`` are the human-readable
    tags (``v6`` / ``v7``); SHAs are in extra.
    """
    locator = re.escape(edit.locator)
    old_sha = edit.extra["old_sha"]
    new_sha = edit.extra["new_sha"]
    # The expected line shape: optional YAML list marker,
    # ``uses:``, the locator (possibly with subpath), ``@<40hex>``,
    # whitespace, comment containing ``was <tag>``. We MATCH on
    # locator + 40-hex SHA, REWRITE both the SHA and the
    # ``was <tag>`` value.
    pattern = re.compile(
        rf"^(\s*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)"
        rf"([a-f0-9]{{40}})"             # current SHA
        rf"(\s+#\s*was\s+)"               # the "# was " prefix
        rf"([^\s#]+)"                     # current tag in the comment
        rf"([\s#]|$)",                    # boundary
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    file_sha = match.group(2)
    file_tag = match.group(4)
    if file_sha == new_sha and file_tag == edit.new_value:
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if file_sha != old_sha:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file SHA {file_sha[:12]}... "
                f"differs from plan's old SHA {old_sha[:12]}..."
            ),
        )
    if file_tag != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file '# was {file_tag}' "
                f"differs from plan's old tag {edit.old_value!r}"
            ),
        )
    # Rewrite both the SHA and the # was vX comment.
    new_text = pattern.sub(
        rf"\g<1>{new_sha}\g<3>{edit.new_value}\g<5>",
        text, count=1,
    )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


def _atomic_write(path: Path, content: str) -> None:
    """Atomic tempfile + rename (same pattern as the other
    Dockerfile rewriters)."""
    try:
        from .._atomic import atomic_write_text
        atomic_write_text(path, content)
        return
    except ImportError:
        pass
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, str(path))
    except Exception:                # noqa: BLE001
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
