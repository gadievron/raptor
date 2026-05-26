"""``.csproj`` / ``.fsproj`` / ``.vbproj`` PackageReference rewriter.

Handles both the inline-version shape used by traditional
.NET projects and the per-csproj VersionOverride attribute
used by modern CPM projects to override a centrally-declared
version. The locator semantics:

  * ``edit.locator`` is the NuGet package name. Case-insensitive
    match (NuGet convention).
  * The rewriter prefers ``Version="..."`` (inline) when present;
    falls back to ``VersionOverride="..."`` (CPM per-csproj
    override) when no inline Version exists. This matches the
    parser's resolution chain.

The source-origin annotation on a Dependency (set by the parser
at ``parsers/nuget.py``) tells the dispatcher whether to write to
the csproj or to ``Directory.Packages.props``:

  * ``inline_version`` / ``inline_version_child`` → this rewriter.
  * ``version_override`` → this rewriter (writes VersionOverride).
  * ``cpm_central`` / ``cpm_global`` → ``directory_packages_props``
    rewriter (in the sibling module).

Dispatch is by file suffix — registered for ``.csproj``,
``.fsproj``, and ``.vbproj``. The dispatcher in
``packages/sca/rewriters/__init__.py`` ROUTES TO HERE BASED ON
THE MANIFEST PATH, not on the source-origin field. Routing by
origin happens at the call site (bumper / harden) that decides
which manifest path to put on the edit.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Tuple

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _csproj_predicate(path: Path) -> bool:
    return path.suffix.lower() in (".csproj", ".fsproj", ".vbproj")


def _build_inline_version_pattern(include_name: str) -> "re.Pattern":
    """``<PackageReference Include="X" Version="OLD" />`` — the
    pre-CPM and CPM-with-inline shape."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<mid>[^>]*?Version\s*=\s*['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P<ver_close>['"])""",
        re.IGNORECASE,
    )


def _build_version_override_pattern(include_name: str) -> "re.Pattern":
    """``<PackageReference Include="X" VersionOverride="OLD" />`` —
    CPM per-csproj override shape. Separate from the inline
    pattern so the rewriter can pick which attribute to update."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<mid>[^>]*?VersionOverride\s*=\s*['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P<ver_close>['"])""",
        re.IGNORECASE,
    )


def _build_child_version_pattern(include_name: str) -> "re.Pattern":
    """``<PackageReference Include="X"><Version>OLD</Version></PackageReference>``
    — older child-element shape some projects use."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<gap>[^>]*>\s*<Version>\s*)"""
        r"""(?P<version>[^<]*?)"""
        r"""(?P<post>\s*</Version>\s*</PackageReference>)""",
        re.IGNORECASE,
    )


@register(predicate=_csproj_predicate)
def rewrite_csproj(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply ``<PackageReference>`` Version / VersionOverride
    edits to an MSBuild project file.

    Preference order per edit:
      1. Inline ``Version="..."`` attribute (most common).
      2. ``VersionOverride="..."`` attribute (CPM override).
      3. Child ``<Version>...</Version>`` element (older shape).

    A reference matching MULTIPLE shapes (an inline Version
    AND a child element — illegal in MSBuild but operators
    sometimes have malformed files) updates the FIRST shape
    matched only; the others are left alone to preserve
    operator intent. Logged at debug for diagnosis.
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
    for pattern_builder in (
        _build_inline_version_pattern,
        _build_version_override_pattern,
        _build_child_version_pattern,
    ):
        pat = pattern_builder(edit.locator)
        match = pat.search(text)
        if match is None:
            continue
        current = match.group("version")
        if current != edit.old_value:
            return text, RewriteResult(
                edit=edit, applied=False,
                reason=(
                    f"value_mismatch: file has version={current!r}, "
                    f"edit expected {edit.old_value!r}"
                ),
            )
        new_text = (
            text[:match.start("version")]
            + edit.new_value
            + text[match.end("version"):]
        )
        return new_text, RewriteResult(
            edit=edit, applied=True, reason="",
        )
    return text, RewriteResult(
        edit=edit, applied=False, reason="not_found",
    )


def _atomic_write(path: Path, content: str) -> None:
    from packages.sca._atomic import atomic_write_text
    atomic_write_text(path, content)


__all__ = ["rewrite_csproj"]
