"""Dockerfile ``RUN pip install <name>==<version>`` rewriter.

The inline-install bumper walker emits :class:`RewriteEdit`
records whose ``locator`` is the PyPI package name and
``extra["kind"] == "inline_install_pip"``. This module finds the
matching ``<name>==<version>`` token inside any ``RUN`` line in
the Dockerfile and rewrites the version.

Coverage today is PyPI exact-pinned installs only —
``pip install <name>==<version>``. Other ecosystems
(``apt-get install foo=1.0``, ``npm install -g foo@1.0``,
``gem install foo -v 1.0``) have parsers in
``packages.sca.parsers.inline_installs`` but no bumper walker
yet; each needs a different upstream-latest source. Add when
triggers fire.

Like ``dockerfile_arg``, this module is NOT ``@register``'d
directly — the Dockerfile predicate is owned by
``dockerfile_from`` which routes inline-install edits here based
on ``extra["kind"]``.
"""

from __future__ import annotations

import logging
import re

from . import RewriteEdit, RewriteResult, rewrite_file_with
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def rewrite_dockerfile_inline_install(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    r"""Apply inline-pip install version-pin edits to a Dockerfile.

    Each edit's ``locator`` is the PyPI package name; the regex
    matches ``<name>==<version>`` with optional surrounding
    quoting / whitespace inside any line that looks like part of
    a ``RUN`` instruction. We don't try to parse RUN bodies —
    they can span multiple physical lines via ``\`` continuation
    — instead we rewrite the first matching ``<name>==<value>``
    token anywhere in the file, refusing to touch any other line
    that happens to contain ``<name>==``.
    """
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(
    text: str, edit: RewriteEdit,
) -> tuple[str, RewriteResult]:
    """Apply a single inline-install edit. Refuses on value
    mismatch (the file's value differs from what the plan
    expected) so a stale plan never silently corrupts an
    already-bumped pin.
    """
    name = re.escape(edit.locator)
    # Match ``<name>==<version>`` as a whole-word token.
    # Word-boundary before; version captured up to next
    # whitespace / quote / EOL / shell metachar. Tolerates
    # extras / markers like ``<name>[extra]==1.0`` only
    # implicitly (the ``[extra]`` portion isn't between name and
    # ``==`` so the regex sees ``<name>`` + ``[extra]==1.0``
    # which doesn't match — those are skipped).
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.\-])({name}==)([A-Za-z0-9.+\-]+)",
    )
    # Multi-stage Dockerfiles repeat the same install line per stage
    # (``pip install foo==1.0`` in builder AND runtime). Verdicts are
    # computed across ALL occurrences and every one still at the old
    # value is bumped — a first-match ``count=1`` substitution bumped
    # one stage and left its twin on the vulnerable version while the
    # run reported applied.
    matches = list(pattern.finditer(text))
    if not matches:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    values = [m.group(2) for m in matches]
    needs_bump = [
        m for m in matches
        if m.group(2) == edit.old_value and m.group(2) != edit.new_value
    ]
    if not needs_bump:
        if all(v == edit.new_value for v in values):
            return text, RewriteResult(
                edit=edit, applied=False, reason="no_change",
            )
        stray = next(v for v in values if v != edit.new_value)
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {stray!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    # Splice the value span directly, back-to-front so earlier
    # offsets stay valid (also removes the re.sub template
    # interpolation of new_value entirely).
    new_text = text
    for m in sorted(needs_bump, key=lambda m: m.start(2), reverse=True):
        new_text = new_text[:m.start(2)] + edit.new_value + new_text[m.end(2):]
    stray_values = sorted(set(values) - {edit.old_value, edit.new_value})
    reason = "applied"
    if stray_values:
        reason = (
            f"partial: {len(needs_bump)} occurrence(s) bumped; other "
            f"value(s) left in place: {stray_values!r}"
        )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason=reason,
    )


