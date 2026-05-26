"""Rewriter registry — symmetric to ``packages/sca/parsers/``.

Each rewriter takes a manifest path + a list of ``RewriteEdit``
records and applies them in place (writing the file atomically),
returning a per-edit ``RewriteResult`` for the orchestrator. The
bumper subcommand dispatches edits via the registry; the legacy
``update.py`` flow keeps its own per-rewriter functions for now
(migrating those is a separate cleanup).

Adding a new rewriter:

1. Drop a module in this directory.
2. Decorate the entry-point with ``@register(filenames=..., predicate=...)``
3. The function takes ``(path: Path, edits: List[RewriteEdit])`` and
   returns ``List[RewriteResult]``. The function is responsible for
   reading, rewriting, and atomic-writing the file; it must be
   idempotent (re-running with the same edits should produce no
   change after the first run).
4. The ``@register`` decorator is mirrored from parsers/__init__.py
   so the operator/contributor model is uniform.

Failure modes:
* Edit doesn't match anything in the file → ``RewriteResult(applied=False,
  reason="not_found")``. The function still writes nothing for that
  edit but processes the rest.
* Edit's ``old_value`` doesn't match what's actually in the file →
  ``RewriteResult(applied=False, reason="value_mismatch: ...")``.
  Operators see the discrepancy so a stale bump plan doesn't
  silently corrupt the file.
* I/O errors → ``RewriteResult(applied=False, reason="error: ...")``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RewriteEdit:
    """A single proposed edit to a manifest file.

    ``locator`` identifies WHAT to edit within the file — the
    semantics are rewriter-specific. For Dockerfile ARG pins it's
    the ARG name (``SEMGREP_VERSION``); for npm package.json it's
    the dep name (``lodash``); for Maven it's the group:artifact
    (``org.springframework:spring-core``).

    ``extra`` is a kind-specific metadata escape-hatch. GHA's
    SHA-pinned ``uses:`` lines carry ``"old_sha"`` /
    ``"new_sha"`` here so the rewriter can update both the SHA
    and the ``# was vX`` comment in one pass. Most edits ignore
    ``extra`` and treat it as None.
    """

    locator: str
    old_value: str
    new_value: str
    extra: Optional[dict] = None


@dataclass(frozen=True)
class RewriteResult:
    """Per-edit outcome from a rewriter."""

    edit: RewriteEdit
    applied: bool
    reason: str = ""


# Rewriter signature: ``(path, edits) -> List[RewriteResult]``.
RewriterFn = Callable[[Path, List[RewriteEdit]], List[RewriteResult]]


_REGISTRY: Dict[str, RewriterFn] = {}
_PREDICATE_REGISTRY: List[
    "tuple[Callable[[Path], bool], RewriterFn]"
] = []


def register(
    *,
    filenames: Optional[List[str]] = None,
    predicate: Optional[Callable[[Path], bool]] = None,
):
    """Decorator: register a rewriter for the given filename / predicate.

    Mirrors the parsers/__init__.py shape so a contributor reading
    one figures out the other for free."""

    def _wrap(fn: RewriterFn) -> RewriterFn:
        for name in filenames or ():
            if name in _REGISTRY and _REGISTRY[name] is not fn:
                raise RuntimeError(
                    f"sca.rewriters: duplicate filename "
                    f"registration {name!r}"
                )
            _REGISTRY[name] = fn
        if predicate is not None:
            _PREDICATE_REGISTRY.append((predicate, fn))
        return fn

    return _wrap


def rewrite(path: Path, edits: List[RewriteEdit]) -> List[RewriteResult]:
    """Dispatch to the right rewriter for ``path`` and apply
    ``edits``. Returns one ``RewriteResult`` per edit; an edit
    that doesn't match anything still returns a result with
    ``applied=False`` and a ``reason``.

    Returns an empty list (with a debug log) when no rewriter is
    registered for the path — caller treats that as "this surface
    isn't supported yet".
    """
    fn = _resolve(path)
    if fn is None:
        logger.debug("sca.rewriters: no rewriter for %s", path)
        return []
    try:
        return fn(path, edits)
    except Exception:  # noqa: BLE001 — rewriters must not break pipeline
        logger.warning(
            "sca.rewriters: rewriter raised on %s; reporting "
            "all edits as failed",
            path, exc_info=True,
        )
        return [
            RewriteResult(edit=e, applied=False, reason="rewriter raised")
            for e in edits
        ]


def _resolve(path: Path) -> Optional[RewriterFn]:
    name = path.name
    if name in _REGISTRY:
        return _REGISTRY[name]
    for pred, fn in _PREDICATE_REGISTRY:
        try:
            if pred(path):
                return fn
        except Exception:    # noqa: BLE001
            continue
    return None


# Side-effect imports: each module calls register() at import time.
# ``dockerfile_from`` is the registered dispatch entry point for
# all Dockerfile edits; it delegates ARG-shaped edits to
# ``dockerfile_arg`` internally. Order matters here only insofar
# as ``dockerfile_arg`` must be importable when ``dockerfile_from``
# tries to delegate, which is naturally satisfied because
# ``dockerfile_from`` does a deferred import on first delegation.
from . import dockerfile_arg          # noqa: E402,F401
from . import dockerfile_from         # noqa: E402,F401
from . import gha_uses                # noqa: E402,F401
from . import helm_chart              # noqa: E402,F401
from . import yaml_image              # noqa: E402,F401
# CPM + Gradle catalog rewriters — close the modern .NET / Gradle
# write-side gap. Without these, harden / bumper writes against
# CPM-using csproj would either fail (no inline Version to match)
# or update the wrong file (csproj override that doesn't
# propagate). See ``parsers/directory_packages_props`` +
# ``parsers/gradle_version_catalog`` for the read-side.
from . import csproj                              # noqa: E402,F401
from . import directory_packages_props            # noqa: E402,F401
from . import gradle_version_catalog              # noqa: E402,F401


__all__ = [
    "RewriteEdit",
    "RewriteResult",
    "register",
    "rewrite",
]
