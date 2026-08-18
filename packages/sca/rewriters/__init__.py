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
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# Conservative version-literal grammar for ``RewriteEdit.new_value``.
# Fix versions originate in OSV advisory ``fixed`` strings — registry
# content, not operator input — and rewriters splice them verbatim
# into manifests that are themselves interpreted downstream (csproj
# XML attributes, TOML strings, Dockerfile ARG lines, YAML image
# tags, Helm charts). Real fix versions look like ``1.2.3``,
# ``2.0.0-rc1``, ``32.2.0-jre``, ``1.24+dfsg-1``, ``v5`` — plain
# alphanumerics with dot / underscore / plus / hyphen separators.
# Everything a hostile advisory would need to break out of the
# surrounding syntax (quotes, angle brackets, backslashes, newlines,
# whitespace, ``$``, braces) is outside the grammar, so a value that
# fails the check is skipped, never written.
_VERSION_LITERAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


def is_safe_version_literal(value: str) -> bool:
    """True when ``value`` is safe to splice into a manifest verbatim."""
    return bool(isinstance(value, str) and _VERSION_LITERAL_RE.match(value))


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
    extra: dict | None = None


@dataclass(frozen=True)
class RewriteResult:
    """Per-edit outcome from a rewriter."""

    edit: RewriteEdit
    applied: bool
    reason: str = ""


# Rewriter signature: ``(path, edits) -> List[RewriteResult]``.
RewriterFn = Callable[[Path, list[RewriteEdit]], list[RewriteResult]]


_REGISTRY: dict[str, RewriterFn] = {}
_PREDICATE_REGISTRY: list[
    tuple[Callable[[Path], bool], RewriterFn]
] = []


def register(
    *,
    filenames: list[str] | None = None,
    predicate: Callable[[Path], bool] | None = None,
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


def rewrite(path: Path, edits: list[RewriteEdit]) -> list[RewriteResult]:
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

    # Version-literal gate — single chokepoint for every registered
    # rewriter. An edit whose ``new_value`` falls outside the
    # conservative grammar is skipped (with a result the caller can
    # surface) rather than spliced into the manifest.
    safe_edits: list[RewriteEdit] = []
    rejected: dict[int, RewriteResult] = {}
    for i, edit in enumerate(edits):
        if is_safe_version_literal(edit.new_value):
            safe_edits.append(edit)
            continue
        logger.warning(
            "sca.rewriters: refusing to write suspicious version "
            "literal for %s in %s: %s",
            edit.locator, path, repr(edit.new_value)[:80],
        )
        rejected[i] = RewriteResult(
            edit=edit, applied=False,
            reason="invalid_new_value: not a safe version literal",
        )

    if safe_edits:
        try:
            inner = fn(path, safe_edits)
        except Exception:
            logger.warning(
                "sca.rewriters: rewriter raised on %s; reporting "
                "all edits as failed",
                path, exc_info=True,
            )
            inner = [
                RewriteResult(edit=e, applied=False,
                              reason="rewriter raised")
                for e in safe_edits
            ]
    else:
        inner = []

    if not rejected:
        return inner

    # Merge back into input order: rejected edits keep their
    # synthesised result, the rest consume the rewriter's results
    # in sequence (contract: one result per edit, in order).
    inner_iter = iter(inner)
    merged: list[RewriteResult] = []
    for i, edit in enumerate(edits):
        if i in rejected:
            merged.append(rejected[i])
        else:
            merged.append(next(
                inner_iter,
                RewriteResult(edit=edit, applied=False,
                              reason="rewriter returned no result"),
            ))
    return merged


def _resolve(path: Path) -> RewriterFn | None:
    name = path.name
    if name in _REGISTRY:
        return _REGISTRY[name]
    for pred, fn in _PREDICATE_REGISTRY:
        try:
            if pred(path):
                return fn
        except Exception:
            logger.debug(
                "sca.rewriters: predicate raised for %s", path,
                exc_info=True,
            )
            continue
    return None


# Side-effect imports: each module calls register() at import time.
# ``dockerfile_from`` is the registered dispatch entry point for
# all Dockerfile edits; it delegates ARG-shaped edits to
# ``dockerfile_arg`` internally. Order matters here only insofar
# as ``dockerfile_arg`` must be importable when ``dockerfile_from``
# tries to delegate, which is naturally satisfied because
# ``dockerfile_from`` does a deferred import on first delegation.
# CPM + Gradle catalog rewriters — close the modern .NET / Gradle
# write-side gap. Without these, harden / bumper writes against
# CPM-using csproj would either fail (no inline Version to match)
# or update the wrong file (csproj override that doesn't
# propagate). See ``parsers/directory_packages_props`` +
# ``parsers/gradle_version_catalog`` for the read-side.
from . import (
    csproj,  # noqa: F401
    directory_build_targets,  # noqa: F401
    directory_packages_props,  # noqa: F401
    dockerfile_arg,  # noqa: F401
    dockerfile_from,  # noqa: F401
    gha_uses,  # noqa: F401
    gradle_version_catalog,  # noqa: F401
    helm_chart,  # noqa: F401
    yaml_image,  # noqa: F401
)

__all__ = [
    "RewriteEdit",
    "RewriteResult",
    "is_safe_version_literal",
    "register",
    "rewrite",
]
