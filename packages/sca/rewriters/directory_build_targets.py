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
from pathlib import Path
from typing import List, Tuple

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _build_targets_predicate(path: Path) -> bool:
    return path.name == "Directory.Build.targets"


def _build_inline_version_pattern(update_name: str) -> "re.Pattern":
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


def _build_version_override_pattern(update_name: str) -> "re.Pattern":
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


def _build_child_version_pattern(update_name: str) -> "re.Pattern":
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
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply ``<PackageReference Update=...>`` Version / VersionOverride
    edits to a Directory.Build.targets file. Preference order per edit:
    inline ``Version=`` → ``VersionOverride=`` → child ``<Version>`` element."""
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


__all__ = ["rewrite_directory_build_targets"]
