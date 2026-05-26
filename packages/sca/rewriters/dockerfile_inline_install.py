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
from pathlib import Path
from typing import List

from . import RewriteEdit, RewriteResult

logger = logging.getLogger(__name__)


def rewrite_dockerfile_inline_install(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply inline-pip install version-pin edits to a Dockerfile.

    Each edit's ``locator`` is the PyPI package name; the regex
    matches ``<name>==<version>`` with optional surrounding
    quoting / whitespace inside any line that looks like part of
    a ``RUN`` instruction. We don't try to parse RUN bodies —
    they can span multiple physical lines via ``\\`` continuation
    — instead we rewrite the first matching ``<name>==<value>``
    token anywhere in the file, refusing to touch any other line
    that happens to contain ``<name>==``.
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
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    for r in results]
    return results


def _apply_one(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
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
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current_value = match.group(2)
    if current_value == edit.new_value:
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if current_value != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {current_value!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    new_text = pattern.sub(
        rf"\g<1>{edit.new_value}", text, count=1,
    )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


def _atomic_write(path: Path, content: str) -> None:
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
