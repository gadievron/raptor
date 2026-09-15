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
from functools import lru_cache
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core.atomic_fs import write_text_atomically as _atomic_write

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
_VERSION_LITERAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")


def is_safe_version_literal(value: str) -> bool:
    """True when ``value`` is safe to splice into a manifest verbatim.

    ``fullmatch``, not ``match(...$)`` — ``$`` admits one trailing
    newline, so ``"4.17.21\\n"`` passed the gate and spliced a raw
    newline into the manifest (invalid JSON in a proposed
    package.json; corruption-only, since the charset excludes any
    further content, but the chokepoint's own contract is "no raw
    newline ever").
    """
    return bool(
        isinstance(value, str)
        and _VERSION_LITERAL_RE.fullmatch(value),
    )


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
                msg = (
                    f"sca.rewriters: duplicate filename "
                    f"registration {name!r}"
                )
                raise RuntimeError(msg)
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


def rewrite_file_with(
    path: Path,
    edits: list[RewriteEdit],
    apply_one: Callable[[str, RewriteEdit], tuple[str, RewriteResult]],
) -> list[RewriteResult]:
    """Read ``path``, thread every edit through ``apply_one``, and
    write the result back atomically when anything applied.

    Shared driver for rewriters whose entry point is "read the file,
    apply each edit in sequence against the evolving text, write
    once at the end". A read failure fails every edit; a write
    failure fails the edits that had applied while keeping the
    results of those that hadn't.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=ed, applied=False,
                              reason=f"error: read failed: {e}")
                for ed in edits]

    new_text = text
    results: list[RewriteResult] = []
    for edit in edits:
        new_text, result = apply_one(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            return [RewriteResult(
                edit=r.edit, applied=False,
                reason=f"error: write failed: {e}",
            ) if r.applied else r
            for r in results]
    return results


@lru_cache(maxsize=2)
def _blank_xml_comments(text: str) -> str:
    """XML comment spans replaced with same-length spaces (newlines
    kept), so match offsets computed on the view splice 1:1 into the
    original text.

    The MSBuild rewriters are regex-over-raw-text by design (comments
    are preserved on write), which made a commented-out declaration
    match identically to a live one: a stale plan then reported
    ``applied`` while only mutating a comment, and commented entries
    polluted the ``partial``/``value_mismatch`` verdicts with prose.
    The parser side is immune (defusedxml drops comments), so plans
    are always generated from live entries — matching must see the
    same view. An unterminated ``<!--`` is malformed XML: the
    remainder is left unblanked (the parser side would have refused
    the file anyway).

    Linear ``str.find`` scan, never a regex: a non-greedy
    ``<!--.*?-->`` pattern re-scans to EOF for EVERY unterminated
    ``<!--``, so a hostile props file made of ``<!--`` repeats cost
    quadratic time per edit — the same hostile-manifest hang class
    the helm rewriter closes. Cached (the per-edit driver re-blanks
    the same file text once per plan entry otherwise; maxsize 2
    covers the one-file-at-a-time rewrite loop).
    """
    out: list[str] = []
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start == -1:
            out.append(text[pos:])
            break
        end = text.find("-->", start + 4)
        if end == -1:
            out.append(text[pos:])
            break
        out.append(text[pos:start])
        out.append(
            "".join(c if c == "\n" else " "
                    for c in text[start:end + 3])
        )
        pos = end + 3
    return "".join(out)


def apply_version_edit(
    text: str,
    edit: RewriteEdit,
    pattern_builders: tuple[Callable[[str], re.Pattern], ...],
) -> tuple[str, RewriteResult]:
    """Apply one version edit using the first pattern that matches.

    Shared driver for rewriters whose per-edit logic is "try each
    locator-derived pattern in preference order; the first pattern
    with any match decides the outcome". Each pattern must expose a
    ``version`` named group.

    Verdicts are computed across ALL of the deciding pattern's
    matches and every occurrence still at ``edit.old_value`` is
    rewritten — a first-match substitution would bump one occurrence
    (a csproj with per-TFM conditional duplicate ``<PackageReference>``
    rows, a redeclared catalog entry) and leave its twin on the
    vulnerable version while the run reports applied. Same semantics
    as the dockerfile_arg / yaml_image / gha_uses rewriters:

    * no occurrence at the old value, all at the new → ``no_change``
      (idempotent re-run);
    * no occurrence at the old value, some other value present →
      ``value_mismatch`` (stale plan / manual edit — refuse);
    * otherwise every old-value occurrence is rewritten; when
      OTHER-valued occurrences remain the result is applied with an
      explicit ``partial:`` reason so the run never reports a clean
      apply over a mixed file.
    """
    # Match against the comment-blanked view; splice into the
    # original (offsets map 1:1 — see _blank_xml_comments). Every
    # consumer of this driver is an MSBuild XML rewriter.
    view = _blank_xml_comments(text)
    for pattern_builder in pattern_builders:
        pat = pattern_builder(edit.locator)
        matches = list(pat.finditer(view))
        if not matches:
            continue
        needs_bump = [
            m for m in matches
            if m.group("version") == edit.old_value
            and m.group("version") != edit.new_value
        ]
        if not needs_bump:
            if all(m.group("version") == edit.new_value for m in matches):
                return text, RewriteResult(
                    edit=edit, applied=False, reason="no_change",
                )
            stray = next(
                m.group("version") for m in matches
                if m.group("version") != edit.new_value
            )
            return text, RewriteResult(
                edit=edit, applied=False,
                reason=(
                    f"value_mismatch: file has version={stray!r}, "
                    f"edit expected {edit.old_value!r}"
                ),
            )
        # Back-to-front so earlier match offsets stay valid.
        new_text = text
        for m in sorted(needs_bump, key=lambda m: m.start("version"),
                        reverse=True):
            new_text = (
                new_text[:m.start("version")]
                + edit.new_value
                + new_text[m.end("version"):]
            )
        stray_values = sorted(
            {m.group("version") for m in matches}
            - {edit.old_value, edit.new_value},
        )
        reason = ""
        if stray_values:
            reason = (
                f"partial: {len(needs_bump)} occurrence(s) bumped; "
                f"other value(s) left in place: {stray_values!r}"
            )
        return new_text, RewriteResult(
            edit=edit, applied=True, reason=reason,
        )
    return text, RewriteResult(
        edit=edit, applied=False, reason="not_found",
    )


def build_element_attr_version_pattern(
    element_names: tuple[str, ...],
    name_attr: str,
    name_value: str,
    version_attr: str,
) -> re.Pattern:
    """Order-agnostic XML open-tag pattern for the MSBuild rewriters.

    Matches an ``<Element …>`` open tag that carries
    ``name_attr="name_value"`` ANYWHERE among its attributes and
    captures ``version_attr``'s value as the ``version`` group
    wherever it sits in the tag. XML parsers (and MSBuild) are
    attribute-order-agnostic, so ``<PackageVersion Version="…"
    Include="X"/>`` is exactly as authoritative as the conventional
    Include-first spelling; an Include-then-Version regex left the
    reversed twin invisible — unmatched occurrences never entered the
    all-occurrence verdict, so a mixed file reported a clean apply
    while the reversed twin stayed on the vulnerable version.

    The name-attribute assertion is a lookahead (non-consuming), so
    it binds regardless of where the version attribute sits relative
    to it. ``\\b`` fences both attribute names so ``VersionOverride``
    or a hypothetical ``DataVersion`` never satisfies a ``Version``
    match. Quote style is per-attribute consistent via backreference.
    """
    elem = "|".join(re.escape(e) for e in element_names)
    val = re.escape(name_value)
    attr = re.escape(name_attr)
    ver = re.escape(version_attr)
    return re.compile(
        rf"""<(?:{elem})\b"""
        rf"""(?=[^>]*\b{attr}\s*=\s*(?P<nq>['"]){val}(?P=nq))"""
        rf"""[^>]*?\b{ver}\s*=\s*(?P<vq>['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P=vq)""",
        re.IGNORECASE,
    )


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
