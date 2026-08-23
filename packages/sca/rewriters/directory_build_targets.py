"""``Directory.Build.targets`` ``<PackageReference Update=...>`` rewriter.

Pre-CPM central-version pattern: Directory.Build.targets is an MSBuild
auto-import loaded AFTER each project, where many projects keep their
version table as ``<PackageReference Update="Name" Version="X"/>`` — the
``Update`` attribute *overrides* a transitively-inherited reference's
version (vs ``Include`` which adds a new one). Parser support landed in
``parsers/nuget.py``; this is the matching rewriter.

Mirrors :mod:`packages.sca.rewriters.csproj` exactly, with one swap:
``Update=`` in place of ``Include=`` on every pattern. Same three shapes
(inline ``Version=`` / ``VersionOverride=`` / child ``<Version>`` element),
same locator semantics (case-insensitive NuGet package name), same
preference order.

Dispatched from ``packages/sca/rewriters/__init__.py`` by filename
(registered for ``Directory.Build.targets``); from harden / update via
``update._rewrite_one``.
"""

from __future__ import annotations

import logging
import re

from . import RewriteEdit, RewriteResult, apply_version_edit, register, rewrite_file_with
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _build_targets_predicate(path: Path) -> bool:
    return path.name == "Directory.Build.targets"


def _build_inline_version_pattern(update_name: str) -> re.Pattern:
    """``<PackageReference Update="X" Version="OLD" />`` — central-version
    override shape."""
    upd = re.escape(update_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Update\s*=\s*['"])"""
        rf"""(?P<upd>{upd})"""
        r"""(?P<upd_close>['"])"""
        r"""(?P<mid>[^>]*?Version\s*=\s*['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P<ver_close>['"])""",
        re.IGNORECASE,
    )


def _build_version_override_pattern(update_name: str) -> re.Pattern:
    """``<PackageReference Update="X" VersionOverride="OLD" />``."""
    upd = re.escape(update_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Update\s*=\s*['"])"""
        rf"""(?P<upd>{upd})"""
        r"""(?P<upd_close>['"])"""
        r"""(?P<mid>[^>]*?VersionOverride\s*=\s*['"])"""
        r"""(?P<version>[^'"]*)"""
        r"""(?P<ver_close>['"])""",
        re.IGNORECASE,
    )


def _build_child_version_pattern(update_name: str) -> re.Pattern:
    """``<PackageReference Update="X"><Version>OLD</Version></PackageReference>``
    — older child-element shape."""
    upd = re.escape(update_name)
    return re.compile(
        r"""(?P<open><PackageReference\b)"""
        r"""(?P<prefix>[^>]*?Update\s*=\s*['"])"""
        rf"""(?P<upd>{upd})"""
        r"""(?P<upd_close>['"])"""
        r"""(?P<gap>[^>]*>\s*<Version>\s*)"""
        r"""(?P<version>[^<]*?)"""
        r"""(?P<post>\s*</Version>\s*</PackageReference>)""",
        re.IGNORECASE,
    )


@register(predicate=_build_targets_predicate)
def rewrite_directory_build_targets(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    """Apply ``<PackageReference Update=...>`` Version / VersionOverride
    edits to a Directory.Build.targets file. Preference order per edit:
    inline ``Version=`` → ``VersionOverride=`` → child ``<Version>`` element."""
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(text: str, edit: RewriteEdit) -> tuple[str, RewriteResult]:
    return apply_version_edit(text, edit, (
        _build_inline_version_pattern,
        _build_version_override_pattern,
        _build_child_version_pattern,
    ))


__all__ = ["rewrite_directory_build_targets"]
