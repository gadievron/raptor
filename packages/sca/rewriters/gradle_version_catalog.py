"""Gradle ``libs.versions.toml`` rewriter — write-side
counterpart to ``parsers/gradle_version_catalog.py``.

Routing semantics:
  * When a Dependency's ``source_extra.origin`` is
    ``gradle_catalog_ref`` (version came via a ``version.ref``
    lookup), the bumper updates the ``[versions]`` table entry
    referenced by ``version_ref_name`` — touching ONE row
    propagates to every library that points at that ref.
  * When the origin is ``gradle_catalog_inline`` (inline
    ``version`` in the library table), the bumper updates the
    ``[libraries]`` table entry directly.
  * Same split for ``gradle_catalog_plugin_*``.

The rewriter receives the FILE PATH and a list of edits. It
doesn't know about origin semantics — that routing happened at
the call site. ``edit.locator`` carries the TOML KEY to update:

  * For a ``[versions]`` edit, ``locator = "version:" + key_name``.
  * For a ``[libraries]`` edit, ``locator = "library:" + alias``.
  * For a ``[plugins]`` edit, ``locator = "plugin:" + alias``.

Edit precedence within the file is "first matching pattern
wins" — and the patterns are disjoint per section (each section
has its own TOML header anchor) so order doesn't matter.

Format preservation: regex-based rewrite in place; TOML
comments / whitespace / table ordering / unrelated entries are
left untouched. Round-tripping through tomllib + tomli_w would
lose comments (TOML libraries don't preserve them).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Tuple

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _is_libs_versions_toml(path: Path) -> bool:
    """Predicate matching the parser's discovery target.
    Conventional location is ``gradle/libs.versions.toml`` but
    we trigger on the basename so non-conventional layouts work
    too."""
    return path.name == "libs.versions.toml"


def _version_key_pattern(key: str) -> "re.Pattern":
    """Match a ``[versions]`` table entry: ``key = "value"`` or
    ``key = 'value'``. The ``key`` is the TOML literal name from
    the catalog (e.g. ``spring-boot`` or ``junit``).

    The pattern only matches within the ``[versions]`` section
    — we anchor on the ``[versions]`` header and stop before the
    next ``[section]`` header. Without the section anchor a
    ``junit = "5.9.0"`` line under ``[libraries]`` (where it
    means something different) would be wrongly matched.
    """
    k = re.escape(key)
    return re.compile(
        # ``[versions]`` header (anchor)
        r"(?P<hdr>^\s*\[versions\]\s*$)"
        # everything up to the key line (non-greedy, no other
        # section headers in between)
        r"(?P<inter>(?:(?!^\s*\[)[\s\S])*?)"
        # the key line itself
        rf"(?P<lead>^\s*{k}\s*=\s*['\"])"
        r"(?P<version>[^'\"]*)"
        r"(?P<tail>['\"])",
        re.MULTILINE,
    )


def _inline_library_version_pattern(alias: str) -> "re.Pattern":
    """Match ``alias = { ... version = "OLD" ... }`` in
    ``[libraries]``. Handles both single-line and (somewhat)
    multi-line inline-table forms.

    Multi-line inline tables are uncommon in libs.versions.toml
    (most operators write one library per line) — we handle the
    common single-line case correctly and fall through on the
    multi-line case (returning not_found, operator edits by hand).
    """
    a = re.escape(alias)
    # ``rf""`` parts double-brace ``}}`` to escape the f-string
    # — the resulting regex sees a single ``}``. Plain ``r""``
    # parts use single ``}`` (no f-string escape). Pre-fix the
    # tail capture used ``r"...\}}"`` which the regex engine read
    # as TWO ``}}`` chars — never matched a single-``}`` inline
    # table close.
    return re.compile(
        r"(?P<hdr>^\s*\[libraries\]\s*$)"
        r"(?P<inter>(?:(?!^\s*\[)[\s\S])*?)"
        rf"(?P<lead>^\s*{a}\s*=\s*\{{[^}}\n]*?version\s*=\s*['\"])"
        r"(?P<version>[^'\"]*)"
        r"(?P<tail>['\"][^}\n]*\})",
        re.MULTILINE,
    )


def _inline_library_string_pattern(alias: str) -> "re.Pattern":
    """Match the string-shorthand library form:
    ``alias = "group:artifact:VERSION"``. Update only the
    version segment."""
    a = re.escape(alias)
    return re.compile(
        r"(?P<hdr>^\s*\[libraries\]\s*$)"
        r"(?P<inter>(?:(?!^\s*\[)[\s\S])*?)"
        rf"(?P<lead>^\s*{a}\s*=\s*['\"][^'\":]+:[^'\":]+:)"
        r"(?P<version>[^'\"]+)"
        r"(?P<tail>['\"])",
        re.MULTILINE,
    )


def _inline_plugin_version_pattern(alias: str) -> "re.Pattern":
    """Match ``alias = { id = "...", version = "OLD" }`` in
    ``[plugins]``. Same brace-escape note as
    ``_inline_library_version_pattern``."""
    a = re.escape(alias)
    return re.compile(
        r"(?P<hdr>^\s*\[plugins\]\s*$)"
        r"(?P<inter>(?:(?!^\s*\[)[\s\S])*?)"
        rf"(?P<lead>^\s*{a}\s*=\s*\{{[^}}\n]*?version\s*=\s*['\"])"
        r"(?P<version>[^'\"]*)"
        r"(?P<tail>['\"][^}\n]*\})",
        re.MULTILINE,
    )


@register(predicate=_is_libs_versions_toml)
def rewrite_libs_versions_toml(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply ``[versions]`` / ``[libraries]`` / ``[plugins]``
    version edits to a Gradle version catalog.

    Each ``RewriteEdit.locator`` is prefixed to select the
    section: ``"version:<key>"``, ``"library:<alias>"``, or
    ``"plugin:<alias>"``.
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
    section, _, key = edit.locator.partition(":")
    if not key:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"malformed locator {edit.locator!r}; expected "
                "'<section>:<key>' (section in version/library/plugin)"
            ),
        )

    if section == "version":
        candidates = [_version_key_pattern]
    elif section == "library":
        candidates = [
            _inline_library_version_pattern,
            _inline_library_string_pattern,
        ]
    elif section == "plugin":
        candidates = [_inline_plugin_version_pattern]
    else:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=f"unknown locator section {section!r}",
        )

    for build_pat in candidates:
        pat = build_pat(key)
        match = pat.search(text)
        if match is None:
            continue
        current = match.group("version")
        if current != edit.old_value:
            return text, RewriteResult(
                edit=edit, applied=False,
                reason=(
                    f"value_mismatch: catalog has version={current!r}, "
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


__all__ = ["rewrite_libs_versions_toml"]
