"""Dockerfile ``ARG <NAME>_VERSION=<value>`` in-place rewriter.

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
``rf"^(ARG {arg}=)(\\S+)"`` regex + the idempotent
skip-if-unchanged + change-tuple-return pattern. This module
generalises that into the ``RewriteEdit``/``RewriteResult``
shape used across all SCA rewriters.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from . import RewriteEdit, RewriteResult

logger = logging.getLogger(__name__)


def _is_dockerfile(path: Path) -> bool:
    """Predicate matching the inline-installs parser's predicate
    so a rewriter is wired to every file the parser sees."""
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


# NOT @register'd: the Dockerfile predicate is owned by
# ``dockerfile_from`` which dispatches ARG-shaped edits here
# internally (locators containing ``/`` route to FROM, the rest
# to ARG). One predicate registration prevents the
# first-match-wins dispatcher from picking the wrong rewriter
# for a mixed-edit batch.
def rewrite_dockerfile_arg(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
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

    results: List[RewriteResult] = []
    new_text = text
    for edit in edits:
        new_text, result = _apply_one(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            # I/O failure on write — convert every successful edit
            # to a failure (we couldn't actually persist).
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    for r in results]
    return results


def _apply_one(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
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
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current_value = match.group(2)
    # Tolerate quoted values: ``ARG FOO="1.2.3"`` should match
    # against ``edit.old_value="1.2.3"`` (the parser strips quotes
    # when extracting, so edits won't carry them). Strip outer
    # quotes from the captured value for comparison.
    bare_current = current_value.strip('"').strip("'")
    if bare_current == edit.new_value:
        # Already at target — idempotent skip. (Per Natalie's
        # original update_dockerfile() pattern.)
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if bare_current != edit.old_value:
        # The file's current value differs from what the bumper
        # plan thinks it is — refuse to overwrite. Operator may
        # have already bumped manually, or the plan is stale.
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {bare_current!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    # Apply the rewrite. Preserve the prefix verbatim (whitespace
    # and casing); preserve whether the original was quoted by
    # quoting the new value the same way.
    if current_value.startswith('"') and current_value.endswith('"'):
        new_value_quoted = f'"{edit.new_value}"'
    elif current_value.startswith("'") and current_value.endswith("'"):
        new_value_quoted = f"'{edit.new_value}'"
    else:
        new_value_quoted = edit.new_value
    new_text = pattern.sub(rf"\g<1>{new_value_quoted}", text, count=1)
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


def _atomic_write(path: Path, content: str) -> None:
    """Atomic write via a sibling tempfile + rename. Uses
    ``packages.sca._atomic`` if available, else inline."""
    try:
        from .._atomic import atomic_write_text
        atomic_write_text(path, content)
        return
    except ImportError:
        pass
    # Fallback for environments without the helper. Same
    # tempfile-then-rename pattern.
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
