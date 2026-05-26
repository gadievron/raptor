"""Dockerfile ``FROM <image>:<tag>`` in-place rewriter.

The bumper-orchestrator emits :class:`RewriteEdit` records with
``locator`` set to ``"{registry}/{repository}"`` and the tag as
``old_value``/``new_value``. This rewriter walks the Dockerfile,
matches each ``FROM`` line against the locator, and rewrites the
tag portion.

Edge cases handled:

* ``FROM <registry>/<repo>:<tag> AS <stage>`` — preserve the
  ``AS <stage>`` suffix.
* Variant tags (``3.12-bookworm``) — the bumper never emits
  candidates for these; the rewriter doesn't expect to see them.
  If the ``old_value`` doesn't match the file's tag exactly,
  return ``value_mismatch``.
* Digest-pinned FROM — the bumper skips these; rewriter not
  invoked.
* Short-form refs (``FROM python:3.12``) — must match by the
  expanded locator (``docker.io/library/python``). The walker
  parses to the canonical form; we accept both short and
  expanded forms in the file.

Same atomic-write + idempotent + value-mismatch semantics as
``dockerfile_arg``."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _is_dockerfile(path: Path) -> bool:
    """Match the same predicate as ``dockerfile_arg`` — both
    rewriters register against Dockerfiles. The dispatcher routes
    by content (we look at every ``RewriteEdit`` and pick the
    line shape that matches)."""
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


@register(predicate=_is_dockerfile, filenames=None)
def rewrite_dockerfile_from(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply FROM-image tag-bump edits to a Dockerfile in place.

    The Dockerfile-ARG rewriter ALSO registers against Dockerfile
    predicates. The dispatcher resolves a single rewriter per
    path, so both rewriter functions actually need to be the
    same physical function — OR this module needs to coordinate
    with dockerfile_arg.

    Implementation: this function delegates by examining each
    edit. Primary discriminator is ``extra["kind"]`` set by the
    bumper orchestrator from the candidate's ``kind`` field.
    Fallback (no kind in extra): image-shaped locators (containing
    ``/``) route to the FROM path, everything else to ARG. Mixed
    batches get split + reassembled.
    """
    arg_edits: List[RewriteEdit] = []
    from_edits: List[RewriteEdit] = []
    inline_install_edits: List[RewriteEdit] = []
    for edit in edits:
        kind = (edit.extra or {}).get("kind")
        if kind == "from_image":
            from_edits.append(edit)
        elif kind == "arg":
            arg_edits.append(edit)
        elif kind == "inline_install_pip":
            inline_install_edits.append(edit)
        else:
            # Back-compat shape heuristic for edits without an
            # ``extra["kind"]``: image refs always contain ``/``,
            # ARG names never do.
            if "/" in edit.locator:
                from_edits.append(edit)
            else:
                arg_edits.append(edit)

    results: List[RewriteResult] = []
    if from_edits:
        results.extend(_apply_from_edits(path, from_edits))
    if arg_edits:
        # Delegate ARG edits to the ARG rewriter so registration
        # collisions don't cause one rewriter to clobber the other.
        from .dockerfile_arg import rewrite_dockerfile_arg
        results.extend(rewrite_dockerfile_arg(path, arg_edits))
    if inline_install_edits:
        from .dockerfile_inline_install import (
            rewrite_dockerfile_inline_install,
        )
        results.extend(rewrite_dockerfile_inline_install(
            path, inline_install_edits,
        ))
    return results


def _apply_from_edits(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply image-tag edits, atomic-writing the result.

    Each edit's locator is ``"{registry}/{repository}"`` (e.g.
    ``"docker.io/library/python"``). We match both the canonical
    and short forms in the file (Docker accepts ``python:3.12``
    as shorthand for ``docker.io/library/python:3.12``).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=e2, applied=False,
                              reason=f"error: read failed: {e}")
                for e2 in edits]

    new_text = text
    results: List[RewriteResult] = []
    for edit in edits:
        new_text, result = _apply_one_from(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    for r in results]
    return results


def _apply_one_from(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
    """Apply one image-tag edit. Matches both canonical and
    short forms of the image ref."""
    locator = edit.locator
    # Build the candidate image-ref forms we'll match against.
    # Canonical: registry/repo. Short forms: if registry is
    # docker.io and repo starts with "library/", the bare repo
    # name (e.g. "python") is also accepted; otherwise the
    # short form is registry/repo verbatim. Parse the registry
    # component explicitly via partition rather than startswith
    # (this isn't a URL, but the lexical shape triggers
    # incomplete-URL-sanitisation scanners).
    forms = [locator]
    registry, _, rest = locator.partition("/")
    if registry == "docker.io" and rest:
        namespace, _, image = rest.partition("/")
        if namespace == "library" and image:
            forms.append(image)
            forms.append(f"library/{image}")
            forms.append(f"docker.io/{image}")
        else:
            forms.append(rest)
    image_alternates = "|".join(re.escape(f) for f in forms)
    # Match: optional ``FROM`` + whitespace + image + ``:`` +
    # captured tag + (optional ``@digest`` + optional ``AS
    # <stage>`` + optional comment / EOL).
    pattern = re.compile(
        rf"^(\s*FROM\s+(?:--platform=\S+\s+)?(?:{image_alternates}):)"
        rf"(\S+?)"                  # tag (non-greedy)
        rf"(\s|$|@|#)",              # boundary
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current_tag = match.group(2)
    if current_tag == edit.new_value:
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if current_tag != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {current_tag!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    # Group 1 = prefix-up-to-colon, group 3 = boundary char.
    new_text = pattern.sub(
        rf"\g<1>{edit.new_value}\g<3>",
        text, count=1,
    )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


def _atomic_write(path: Path, content: str) -> None:
    """Atomic tempfile + rename. Shared pattern with
    ``dockerfile_arg``; could be factored to a shared
    ``rewriters/_atomic.py`` when a third rewriter lands."""
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
