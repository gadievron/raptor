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

from . import (
    RewriteEdit,
    RewriteResult,
    apply_version_edit,
    build_element_attr_version_pattern,
    register,
    rewrite_file_with,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _csproj_predicate(path: Path) -> bool:
    return path.suffix.lower() in (".csproj", ".fsproj", ".vbproj")


def _build_inline_version_pattern(include_name: str) -> re.Pattern:
    """``<PackageReference Include="X" Version="OLD" />`` — the
    pre-CPM and CPM-with-inline shape, either attribute order
    (MSBuild is order-agnostic)."""
    return build_element_attr_version_pattern(
        ("PackageReference",), "Include", include_name, "Version",
    )


def _build_version_override_pattern(include_name: str) -> re.Pattern:
    """``<PackageReference Include="X" VersionOverride="OLD" />`` —
    CPM per-csproj override shape, either attribute order. Separate
    from the inline pattern so the rewriter can pick which attribute
    to update."""
    return build_element_attr_version_pattern(
        ("PackageReference",), "Include", include_name, "VersionOverride",
    )


def _build_child_version_pattern(include_name: str) -> re.Pattern:
    """``<PackageReference Include="X"><Version>OLD</Version></PackageReference>``
    — older child-element shape some projects use.

    Attribute spans are ``[^<>]`` (not ``[^>]``): a raw ``<`` is
    illegal inside an XML open tag, so real tags match identically,
    while with ``[^>]`` every planted ``<PackageReference`` inside
    an unclosed tag re-scanned the rest of it — quadratic on
    hostile project files."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^<>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<gap>[^<>]*>\s*<Version>\s*)"""
        r"""(?P<version>[^<]*?)"""
        r"""(?P<post>\s*</Version>\s*</PackageReference>)""",
        re.IGNORECASE,
    )


@register(predicate=_csproj_predicate)
def rewrite_csproj(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
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
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(text: str, edit: RewriteEdit) -> tuple[str, RewriteResult]:
    return apply_version_edit(text, edit, (
        _build_inline_version_pattern,
        _build_version_override_pattern,
        _build_child_version_pattern,
    ))


__all__ = ["rewrite_csproj"]
