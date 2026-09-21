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

from . import RewriteEdit, RewriteResult, register, rewrite_file_with
from typing import TYPE_CHECKING
from ..file_shapes import is_gha_workflow as _is_gha_workflow

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


@register(predicate=_is_gha_workflow)
def rewrite_gha_uses(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    """Apply ``uses:`` ref-bump edits to a GHA workflow file."""
    return rewrite_file_with(path, edits, _apply_one_uses)


def _apply_one_uses(
    text: str, edit: RewriteEdit,
) -> tuple[str, RewriteResult]:
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
    # Leading indent is HORIZONTAL-only ([^\S\n]) — the MULTILINE
    # ^\s* idiom is quadratic on blank-line runs (see the helm
    # rewriter's fixed anchor; same sibling idiom).
    pattern = re.compile(
        rf"^([^\S\n]*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)"
        rf"([^\s#]+)"                    # ref (up to whitespace or comment)
        rf"(\s|$|#)",                    # boundary
        re.MULTILINE,
    )
    # A workflow can reference the same action several times with
    # DIFFERENT refs (``@main`` in one job, ``@v4`` in another).
    # Verdicts must be computed across ALL matching lines — deciding
    # from the first match alone would let an unrelated ``@main``
    # occurrence shadow a legitimate ``@v4`` bump into value_mismatch.
    refs = [m.group(2) for m in pattern.finditer(text)]
    if not refs:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    # Occurrences that actually need the bump: at the old ref and not
    # already at the new one (a degenerate plan with old == new is
    # idempotent, not applied).
    old_refs = [r for r in refs
                if r == edit.old_value and r != edit.new_value]
    if old_refs:
        # SHA-pinned refs (40-char hex) are Phase 3.b.2 territory.
        # The walker doesn't emit candidates for them today, so a plan
        # whose old value matches only SHA-pinned occurrences is a
        # signal that something's off — refuse politely.
        if all(_looks_like_sha(r) for r in old_refs):
            return text, RewriteResult(
                edit=edit, applied=False,
                reason=(
                    "value_mismatch: file uses SHA-pinned ref "
                    f"{old_refs[0][:12]}..., bumper only handles "
                    "tag-pinned refs in Phase 3.b"
                ),
            )

        def _repl(m: re.Match) -> str:
            if m.group(2) == edit.old_value:
                return f"{m.group(1)}{edit.new_value}{m.group(3)}"
            return m.group(0)
        new_text = pattern.sub(_repl, text)
        return new_text, RewriteResult(
            edit=edit, applied=True, reason="applied",
        )
    # No occurrence carries the plan's old value.
    if all(r == edit.new_value for r in refs):
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if all(_looks_like_sha(r) for r in refs):
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                "value_mismatch: file uses SHA-pinned ref "
                f"{refs[0][:12]}..., bumper only handles "
                "tag-pinned refs in Phase 3.b"
            ),
        )
    stray = next(r for r in refs if r != edit.new_value)
    return text, RewriteResult(
        edit=edit, applied=False,
        reason=(
            f"value_mismatch: file has {stray!r}, "
            f"plan expected {edit.old_value!r}"
        ),
    )


_SHA_RE = re.compile(r"^[a-f0-9]{40}$")


def _looks_like_sha(ref: str) -> bool:
    return _SHA_RE.match(ref) is not None


def _apply_sha_pinned(
    text: str, edit: RewriteEdit,
) -> tuple[str, RewriteResult]:
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
    old_sha = edit.extra.get("old_sha") or ""
    new_sha = edit.extra.get("new_sha") or ""
    # The ``rewrite()`` chokepoint validates ``new_value`` (the tag),
    # but the bytes actually spliced into the workflow line on this
    # path are the SHAs from ``edit.extra`` — a poisoned upstream
    # tag→SHA resolution must not write arbitrary bytes into a file
    # that executes in CI. Enforce the 40-hex grammar here, the one
    # place the extra values reach the file.
    if not (_SHA_RE.match(old_sha) and _SHA_RE.match(new_sha)):
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                "invalid_new_value: extra sha is not a 40-hex "
                "commit SHA"
            ),
        )
    # The expected line shape: optional YAML list marker,
    # ``uses:``, the locator (possibly with subpath), ``@<40hex>``,
    # whitespace, comment containing ``was <tag>``. We MATCH on
    # locator + 40-hex SHA, REWRITE both the SHA and the
    # ``was <tag>`` value.
    # Horizontal-only indent — same rationale as the match pattern.
    pattern = re.compile(
        rf"^([^\S\n]*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)"
        rf"([a-f0-9]{{40}})"             # current SHA
        rf"(\s+#\s*was\s+)"               # the "# was " prefix
        rf"([^\s#]+)"                     # current tag in the comment
        rf"([\s#]|$)",                    # boundary
        re.MULTILINE,
    )
    # A workflow can pin the same action in several jobs/steps.
    # Verdicts are computed across ALL matching lines — deciding
    # from the first match alone let an occurrence at a different
    # SHA (or one already bumped) shadow a legitimate bump into
    # value_mismatch / no_change while its twin stayed on the old
    # SHA. Same all-occurrence semantics as the tag-pinned arm.
    matches = list(pattern.finditer(text))
    if not matches:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    needs_bump = [
        m for m in matches
        if m.group(2) == old_sha and m.group(4) == edit.old_value
        and (m.group(2) != new_sha or m.group(4) != edit.new_value)
    ]
    if not needs_bump:
        if all(m.group(2) == new_sha and m.group(4) == edit.new_value
               for m in matches):
            return text, RewriteResult(
                edit=edit, applied=False, reason="no_change",
            )
        stray = next(
            m for m in matches
            if m.group(2) != new_sha or m.group(4) != edit.new_value
        )
        if stray.group(2) != old_sha:
            return text, RewriteResult(
                edit=edit, applied=False,
                reason=(
                    f"value_mismatch: file SHA {stray.group(2)[:12]}... "
                    f"differs from plan's old SHA {old_sha[:12]}..."
                ),
            )
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file '# was {stray.group(4)}' "
                f"differs from plan's old tag {edit.old_value!r}"
            ),
        )
    # Rewrite both the SHA and the ``# was vX`` tag comment on every
    # occurrence still at the plan's old (SHA, tag) pair.
    def _repl(m):
        if m.group(2) == old_sha and m.group(4) == edit.old_value:
            return f"{m.group(1)}{new_sha}{m.group(3)}{edit.new_value}{m.group(5)}"
        return m.group(0)
    new_text = pattern.sub(_repl, text)
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


