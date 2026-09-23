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


# ``<PackageVersion Include="X" Version="OLD" />`` shape. We also
# accept ``<GlobalPackageReference>`` since it has identical
# attribute structure and the bumper / harden may target either.
#
# The include attribute is matched with quotes that can be either
# style (``"`` or ``'``); MSBuild allows both. Attribute ORDER is
# NOT assumed: MSBuild is order-agnostic, so ``<PackageVersion
# Version="OLD" Include="X"/>`` must enter the all-occurrence
# verdict exactly like the conventional Include-first spelling.
def _build_attr_pattern(include_name: str) -> re.Pattern:
    """Compile a per-package pattern that matches BOTH the
    ``<PackageVersion>`` and ``<GlobalPackageReference>`` shapes
    with the supplied Include value (case-insensitive — NuGet
    convention), in either attribute order."""
    return build_element_attr_version_pattern(
        ("PackageVersion", "GlobalPackageReference"),
        "Include", include_name, "Version",
    )


def _build_child_pattern(include_name: str) -> re.Pattern:
    """Compile a per-package pattern matching the child-element
    Version shape: ``<PackageVersion Include="X"><Version>OLD</Version></PackageVersion>``.

    Attribute spans are ``[^<>]`` (not ``[^>]``): a raw ``<`` is
    illegal inside an XML open tag, so real tags match identically,
    while with ``[^>]`` every planted element opener inside an
    unclosed tag re-scanned the rest of it — quadratic on hostile
    project files."""
    inc = re.escape(include_name)
    return re.compile(
        r"""(?P<open><(?:PackageVersion|GlobalPackageReference)\b)"""
        r"""(?P<prefix>[^<>]*?Include\s*=\s*['"])"""
        rf"""(?P<inc>{inc})"""
        r"""(?P<inc_close>['"])"""
        r"""(?P<gap>[^<>]*>\s*<Version>\s*)"""
        r"""(?P<version>[^<]*?)"""
        r"""(?P<post>\s*</Version>\s*</(?:PackageVersion|GlobalPackageReference)>)""",
        re.IGNORECASE,
    )


@register(filenames=["Directory.Packages.props"])
def rewrite_directory_packages_props(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    """Apply ``<PackageVersion>`` / ``<GlobalPackageReference>``
    version edits to a Directory.Packages.props file.

    Idempotent — re-running with the same edits after a
    successful first run is a ``no_change`` no-op (every
    occurrence is already at the new version); a file whose
    versions match neither the old nor the new value triggers
    ``value_mismatch``.
    """
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(text: str, edit: RewriteEdit) -> tuple[str, RewriteResult]:
    """Try the attribute-shape rewrite first; fall back to the
    child-element shape. Operators don't mix shapes in practice
    (one file usually picks a convention) but we tolerate both.

    Routed through the shared ``apply_version_edit`` driver:
    ``Directory.Packages.props`` legitimately declares the same
    package in multiple conditional ``<ItemGroup Condition=…>``
    blocks (per-TFM central pins; the parser tolerates duplicates
    with last-wins), so verdicts are computed across ALL matches
    and every occurrence still at the old value is rewritten — a
    last-match substitution bumped one conditional branch and left
    its twin on the vulnerable version while the run reported
    applied."""
    return apply_version_edit(
        text, edit, (_build_attr_pattern, _build_child_pattern),
    )



__all__ = ["rewrite_directory_packages_props"]
