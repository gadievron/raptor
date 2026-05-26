"""``Directory.Packages.props`` rewriter — write-side counterpart
to ``parsers/directory_packages_props.py``.

Rewrites ``<PackageVersion Include="X" Version="OLD" />`` (and
``<GlobalPackageReference>``) entries to use a new version, in
place. Used by:

  * ``packages/sca/update.py`` (harden ``fix --harden`` flow):
    dispatched via ``_rewrite_one`` for manifests named
    ``Directory.Packages.props``.
  * ``packages/sca/bump/orchestrator.py`` (bumper apply flow):
    dispatched via the ``rewriters/__init__.py`` registry when a
    bump candidate's ``manifest_path`` points at a CPM file.

Locator semantics for ``RewriteEdit``:
  * ``edit.locator`` is the package name (case-folded match —
    NuGet is case-insensitive on names).
  * ``edit.old_value`` is the current version (must match what
    the file contains; mismatch → ``value_mismatch`` failure).
  * ``edit.new_value`` is the target version.

Regex-based rewrite (not XML round-trip) so whitespace,
attribute ordering, and comments are preserved. The pattern
matches both attribute and child-element version shapes, same
as ``parsers/directory_packages_props`` reads.

Failure modes:
  * Edit's locator missing from the file → ``not_found``.
  * Edit's old_value doesn't match file content → ``value_mismatch``.
  * I/O error → ``error: ...``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Tuple

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


# ``<PackageVersion Include="X" Version="OLD" />`` shape. We also
# accept ``<GlobalPackageReference>`` since it has identical
# attribute structure and the bumper / harden may target either.
# Capture groups: ``open_tag`` (PackageVersion / GlobalPackageReference),
# ``prefix`` (everything from the tag through the Include attribute),
# ``ver_open`` (``Version="`` literal), ``version`` (the value),
# ``ver_close`` (``"``), ``suffix`` (rest of the tag).
#
# The include attribute is matched with quotes that can be either
# style (``"`` or ``'``); MSBuild allows both.
def _build_attr_pattern(include_name: str) -> "re.Pattern":
    """Compile a per-package pattern that matches BOTH the
    ``<PackageVersion>`` and ``<GlobalPackageReference>`` shapes
    with the supplied Include value (case-insensitive — NuGet
    convention)."""
    # Escape the include name; it's a NuGet package name which
    # can contain dots / dashes / pluses but no quote chars in
    # the wild. Belt-and-braces re.escape anyway.
    inc = re.escape(include_name)
    return re.compile(
        # tag open
        r"""(?P<open><(?:PackageVersion|GlobalPackageReference)\b)"""
        # everything up to the Include attribute, then Include
        r"""(?P<prefix>[^>]*?Include\s*=\s*['"])"""
        # the include value (case-insensitive match below via re.I)
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        # whatever sits between Include="..." and Version="..."
        r"""(?P<mid>[^>]*?Version\s*=\s*['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P<ver_close>['"])"""
        r"""(?P<suffix>[^>]*/?>)""",
        re.IGNORECASE,
    )


def _build_child_pattern(include_name: str) -> "re.Pattern":
    """Compile a per-package pattern matching the child-element
    Version shape: ``<PackageVersion Include="X"><Version>OLD</Version></PackageVersion>``."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><(?:PackageVersion|GlobalPackageReference)\b)"""
        r"""(?P<prefix>[^>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<gap>[^>]*>\s*<Version>\s*)"""
        r"""(?P<version>[^<]*?)"""
        r"""(?P<post>\s*</Version>\s*</(?:PackageVersion|GlobalPackageReference)>)""",
        re.IGNORECASE,
    )


@register(filenames=["Directory.Packages.props"])
def rewrite_directory_packages_props(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply ``<PackageVersion>`` / ``<GlobalPackageReference>``
    version edits to a Directory.Packages.props file.

    Idempotent — re-running with the same edits after a
    successful first run is a no-op (the file already has the
    new version; the second pass triggers
    ``value_mismatch`` if ``edit.old_value`` wasn't updated to
    the new value).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=ed, applied=False,
                              reason=f"error: read failed: {e}")
                for ed in edits]

    new_text = text
    results: List[RewriteResult] = []
    for edit in edits:
        new_text, result = _apply_one(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            return [RewriteResult(
                edit=r.edit, applied=False,
                reason=f"error: write failed: {e}",
            ) for r in results]
    return results


def _apply_one(text: str, edit: RewriteEdit) -> Tuple[str, RewriteResult]:
    """Try the attribute-shape rewrite first; fall back to the
    child-element shape. Operators don't mix shapes in practice
    (one file usually picks a convention) but we tolerate
    both."""
    pat = _build_attr_pattern(edit.locator)
    match = pat.search(text)
    if match is None:
        pat = _build_child_pattern(edit.locator)
        match = pat.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current = match.group("version")
    if current != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has Version={current!r}, "
                f"edit expected {edit.old_value!r}"
            ),
        )
    # Substitute the captured Version section with the new value.
    new_substring = (
        text[:match.start("version")]
        + edit.new_value
        + text[match.end("version"):]
    )
    return new_substring, RewriteResult(
        edit=edit, applied=True, reason="",
    )


def _atomic_write(path: Path, content: str) -> None:
    """Atomic write via tempfile + rename, matching the
    repo-wide convention from ``packages/sca/_atomic``."""
    from packages.sca._atomic import atomic_write_text
    atomic_write_text(path, content)


__all__ = ["rewrite_directory_packages_props"]
