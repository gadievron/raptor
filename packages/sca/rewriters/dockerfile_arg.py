r"""Dockerfile ``ARG <NAME>_VERSION=<value>`` in-place rewriter.

The bumper-orchestrator emits :class:`RewriteEdit` records with
the ARG name as the locator, then calls
``rewriters.rewrite(dockerfile_path, edits)`` to apply them. This
module handles the regex match + idempotent in-place rewrite.

Behaviour:

* Edit doesn't match an ARG line in the file → ``not_found``
  result (no change to file for that edit)
* Edit's ``old_value`` matches what's in the file → rewrite to
  ``new_value``, return ``applied=True``
* Edit's ``old_value`` doesn't match what's actually in the file
  → ``value_mismatch`` result. Preserves the file's state so a
  stale bump plan doesn't silently overwrite operator work.
* No edits applied → file untouched.

Atomic write via :func:`core.file.atomic_write` (or the
package-local ``_atomic`` if core.file isn't available).

Adapted from https://github.com/gadievron/raptor/pull/467 by
Natalie Somersall — her ``update_dockerfile()`` shipped the
``rf"^(ARG {arg}=)(\S+)"`` regex + the idempotent
skip-if-unchanged + change-tuple-return pattern. This module
generalises that into the ``RewriteEdit``/``RewriteResult``
shape used across all SCA rewriters.
"""

from __future__ import annotations

import logging
import re

from core.atomic_fs import write_text_atomically as _atomic_write

from . import RewriteEdit, RewriteResult
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _is_dockerfile(path: Path) -> bool:
    """Predicate matching the inline-installs parser's predicate
    so a rewriter is wired to every file the parser sees."""
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    return path.suffix == ".dockerfile"


# NOT @register'd: the Dockerfile predicate is owned by
# ``dockerfile_from`` which dispatches ARG-shaped edits here
# internally (locators containing ``/`` route to FROM, the rest
# to ARG). One predicate registration prevents the
# first-match-wins dispatcher from picking the wrong rewriter
# for a mixed-edit batch.
def rewrite_dockerfile_arg(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    """Apply ARG version-pin edits to a Dockerfile in place.

    Each edit's ``locator`` is the ARG name (``SEMGREP_VERSION``,
    ``CLAUDE_CODE_VERSION``, etc.). The regex matches
    ``ARG <NAME>=<value>`` with optional whitespace; the value
    component is rewritten if it matches ``edit.old_value``.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=e2, applied=False,
                              reason=f"error: read failed: {e}")
                for e2 in edits]

    results: list[RewriteResult] = []
    new_text = text
    for edit in edits:
        new_text, result = _apply_one(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            # I/O failure on write — convert every applied edit
            # to a failure (we couldn't actually persist).
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    if r.applied else r
                    for r in results]
    return results


def _apply_one(
    text: str, edit: RewriteEdit,
) -> tuple[str, RewriteResult]:
    """Apply a single ARG edit to the text. Returns the (possibly
    unchanged) text plus the per-edit result."""
    # Pattern matches ``ARG <NAME>=<value>`` with optional
    # whitespace around the ``=``. The prefix capture includes
    # the trailing whitespace after ``=`` (if any) so quoted-vs-
    # bare value handling stays clean. Value captures until
    # whitespace / comment / EOL. Multi-line mode so each line
    # is tested independently — Dockerfile ARGs are always
    # one-per-line.
    name = re.escape(edit.locator)
    pattern = re.compile(
        rf"^(\s*ARG\s+{name}\s*=\s*)(\S+)",
        re.MULTILINE,
    )
    # Multi-stage Dockerfiles redeclare the same ARG per stage, so the
    # value can appear on several lines. Verdicts are computed across
    # ALL matching lines and every occurrence still at the old value is
    # rewritten — a first-match ``count=1`` substitution would bump one
    # stage's declaration and leave the redeclaration on the vulnerable
    # version while the run reports applied.
    #
    # Tolerate quoted values: ``ARG FOO="1.2.3"`` should match against
    # ``edit.old_value="1.2.3"`` (the parser strips quotes when
    # extracting, so edits won't carry them). Strip outer quotes from
    # each captured value for comparison.
    def _bare(value: str) -> str:
        return value.strip('"').strip("'")

    values = [m.group(2) for m in pattern.finditer(text)]
    if not values:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    # Occurrences that actually need the bump: at the old value and not
    # already at the new one (a degenerate plan with old == new is
    # idempotent, not applied).
    needs_bump = [v for v in values
                  if _bare(v) == edit.old_value
                  and _bare(v) != edit.new_value]
    if not needs_bump:
        if all(_bare(v) == edit.new_value for v in values):
            # Already at target everywhere — idempotent skip. (Per
            # Natalie's original update_dockerfile() pattern.)
            return text, RewriteResult(
                edit=edit, applied=False, reason="no_change",
            )
        # The file's current value differs from what the bumper
        # plan thinks it is — refuse to overwrite. Operator may
        # have already bumped manually, or the plan is stale.
        stray = next(_bare(v) for v in values
                     if _bare(v) != edit.new_value)
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {stray!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )

    # Apply the rewrite to every old-value occurrence. Preserve the
    # prefix verbatim (whitespace and casing); preserve whether each
    # original was quoted by quoting the new value the same way.
    # Callable replacement writes the value as an exact literal —
    # interpolating it into a re.sub template would let backslash /
    # group-reference sequences in the value rewrite the ARG line
    # into something other than the validated literal.
    def _repl(m: re.Match) -> str:
        current_value = m.group(2)
        if _bare(current_value) != edit.old_value:
            return m.group(0)
        if current_value.startswith('"') and current_value.endswith('"'):
            new_value_quoted = f'"{edit.new_value}"'
        elif current_value.startswith("'") and current_value.endswith("'"):
            new_value_quoted = f"'{edit.new_value}'"
        else:
            new_value_quoted = edit.new_value
        return m.group(1) + new_value_quoted

    new_text = pattern.sub(_repl, text)
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


