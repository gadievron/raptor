"""Top-level-only license detection for a scan target."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# SPDX identifiers we recognise as OSI-approved open-source. Covers
# the licenses that account for ~95%+ of real-world OSS targets.
# Used both for SPDX-Identifier header matching and as the trusted
# allowlist when the detected SPDX is supplied verbatim.
_OSS_SPDX_IDS = frozenset({
    # Permissive
    "MIT", "MIT-0",
    "Apache-2.0",
    "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
    "Zlib",
    "BlueOak-1.0.0",
    # Weak copyleft
    "MPL-2.0",
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "EPL-2.0",
    # Strong copyleft (still OSS; copyleft is a downstream concern,
    # not a CodeQL-terms concern)
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
})

# Glob patterns we check at the target's top level. Case-insensitive
# at match-time. Order matters only for tie-breaking when multiple
# files exist: the SPDX-bearing one wins regardless of name.
_LICENSE_FILENAME_PATTERNS = (
    "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE.rst",
    "LICENCE", "LICENCE.txt", "LICENCE.md",
    "COPYING", "COPYING.txt", "COPYING.md",
    "COPYRIGHT", "COPYRIGHT.txt", "COPYRIGHT.md",
    # Dual-license: many projects ship `LICENSE-MIT` + `LICENSE-APACHE`
    # at the top level (Rust ecosystem convention).
    "LICENSE-*", "LICENCE-*",
    # Per-license filename layout: vte ships ``COPYING.GPL3`` +
    # ``COPYING.LGPL3``; systemd ships ``LICENSE.GPL2`` +
    # ``LICENSE.LGPL2.1``. Common across systemd / GNOME /
    # Linux kernel-adjacent projects. The ``.*`` glob matches
    # any extension (fnmatch ``*`` includes dots), so this also
    # subsumes the explicit ``LICENSE.txt`` / ``COPYING.txt``
    # entries above — they're kept for documentation value.
    "LICENSE.*", "LICENCE.*", "COPYING.*",
)

# Cap how many lines we read from each file. SPDX headers + standard
# license preambles fit in the first ~50 lines; reading more burns
# IO on the tail of MIT's reproduction-of-copyright clause.
_LICENSE_READ_LINES = 50

# Proprietary markers — case-insensitive substring match against the
# first _LICENSE_READ_LINES lines of any detected file. Hits route
# the file to ``classification="proprietary"`` rather than
# ``"unknown"``. The markers are deliberately broad: a LICENSE file
# that says ''All Rights Reserved'' or ''Confidential'' is signalling
# something other than OSS.
_PROPRIETARY_MARKERS = (
    "all rights reserved",
    "proprietary",
    "confidential",
    "internal use only",
    "no part of this",
)

# Heuristic text fingerprints for the most common OSS licenses,
# fallback when no SPDX-Identifier header is present. Each entry is
# ``(spdx_id, marker_text)``; the first marker that hits wins.
# Conservative — fingerprints picked from the canonical license
# preamble, not generic phrases.
# Non-GPL fingerprints — simple substring → SPDX mapping. GPL
# family is handled separately because the version is essential
# (GPL-2.0 vs GPL-3.0 is a material licensing distinction; we
# can't conflate them to "GPL-3.0" the way we used to). BSD is
# also handled separately because BSD-2 vs BSD-3 cannot be told
# apart by a single substring (BSD-3 = BSD-2 + 'neither the
# name of' clause); see ``_classify_bsd``.
_TEXT_FINGERPRINTS = (
    ("MIT", "permission is hereby granted, free of charge"),
    ("Apache-2.0", "apache license"),
    ("ISC", "permission to use, copy, modify, and/or distribute"),
    ("MPL-2.0", "mozilla public license"),
    ("Unlicense", "this is free and unencumbered software"),
)

# BSD discriminator. BSD-2 and BSD-3 both start with
# "redistribution and use in source and binary forms" — the
# distinguishing clause is BSD-3's "Neither the name of the
# copyright holder nor the names of its contributors may be
# used to endorse or promote". When the discriminator is
# present → BSD-3; absent → BSD-2.
_BSD_INTRO_MARKER = "redistribution and use in source and binary forms"
_BSD3_DISCRIMINATOR = "neither the name of"

# GPL-family fingerprints — order matters within this tuple:
# more-specific names (Lesser / Library / Affero) MUST come
# before the bare "GNU General Public License" since the bare
# name appears INSIDE the LGPL/AGPL preamble text. Earliest-
# position in _classify_text uses the index here only to break
# pos ties.
#
# Each entry is (family_label, family_marker, default_version)
# — version is filled in by ``_classify_gpl_version`` reading
# the surrounding text for "Version X". Default is the most-
# common version for that family if no version marker is found.
_GPL_FAMILY_FINGERPRINTS = (
    # Affero before "lesser" before "library" before bare GPL —
    # AGPL preamble mentions GPL; LGPL preamble mentions GPL.
    ("AGPL", "gnu affero general public license", "3.0"),
    ("LGPL", "gnu lesser general public license", "2.1"),
    # Pre-rename name: LGPL was called "Library GPL" before the
    # rename in 1999 (LGPL v2 was "Library GPL"; v2.1 onwards
    # was "Lesser GPL"). "Library" + Version 2 = LGPL-2.0;
    # "Library" + Version 2.1 = unusual but possible.
    ("LGPL", "gnu library general public license", "2.0"),
    ("GPL", "gnu general public license", "2.0"),
)

_SPDX_HEADER_RE = re.compile(
    r"SPDX-License-Identifier\s*:\s*([A-Za-z0-9.\-+]+)", re.IGNORECASE,
)

# Compound headers (``SPDX-License-Identifier: MIT OR Apache-2.0``)
# need to capture the FULL expression — operators + operands — not
# just the first id. Matches the shared grammar in
# ``core/license/spdx.py``.
_SPDX_COMPOUND_HEADER_RE = re.compile(
    r"SPDX-License-Identifier\s*:\s*"
    r"([A-Za-z0-9.+\-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-]+)+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TargetLicense:
    """Detection result for a scan target's top-level license file(s).

    - ``spdx_id``: the SPDX identifier extracted from a header, or
      inferred from text fingerprints. ``None`` for ``"unknown"`` /
      ``"missing"`` / ``"proprietary"`` (proprietary licenses aren't
      typically given SPDX ids).
    - ``classification``: ``"oss"`` / ``"proprietary"`` / ``"unknown"``
      / ``"missing"``. Drives the surface-warning shape.
    - ``source_file``: relative path of the file we read, or ``None``
      when ``classification="missing"``.
    - ``confidence``: ``"high"`` (SPDX-Identifier header), ``"medium"``
      (text fingerprint), ``"low"`` (proprietary marker / nothing
      matched).
    - ``additional_files``: other license-named files found at the
      top level — usually the dual-license case (``LICENSE-MIT`` +
      ``LICENSE-APACHE``) where we pick one but flag the others.
    """

    spdx_id: Optional[str]
    classification: str
    source_file: Optional[str]
    confidence: str
    additional_files: tuple = ()

    def to_dict(self) -> dict:
        """Serialise for storage in the project record / provenance
        manifest. Stable shape — additive only."""
        return {
            "spdx_id": self.spdx_id,
            "classification": self.classification,
            "source_file": self.source_file,
            "confidence": self.confidence,
            "additional_files": list(self.additional_files),
        }


def _find_license_files(target_dir: Path) -> List[Path]:
    """Return license-named files at the top level of ``target_dir``,
    case-insensitive. Glob first to keep IO bounded; then de-dupe.

    Symlinks: accepted IF they resolve inside ``target_dir`` —
    REUSE-compliant projects commonly ship ``COPYING`` as a
    symlink into ``LICENSES/<SPDX>.txt`` (glib, NetworkManager
    et al.). Refused when the symlink resolves outside the tree
    (defence against ``LICENSE`` → ``/etc/passwd`` planted on a
    crafted target). Broken symlinks (resolve fails) are
    dropped.
    """
    found: dict = {}  # name → Path (dedup case-insensitive)
    if not target_dir.is_dir():
        return []
    try:
        entries = list(target_dir.iterdir())
        target_resolved = target_dir.resolve()
    except OSError:
        return []
    name_patterns_lower = [p.lower() for p in _LICENSE_FILENAME_PATTERNS]
    for entry in entries:
        if not entry.is_file():
            # is_file follows symlinks; True for symlinks pointing
            # at regular files (including in-tree REUSE layouts).
            # False for dangling links + non-regular targets.
            continue
        if entry.is_symlink():
            try:
                resolved = entry.resolve()
                # In-tree symlinks ok (REUSE layout). Out-of-tree
                # ones refused (crafted-target defence).
                resolved.relative_to(target_resolved)
            except (OSError, ValueError):
                continue
        name_lower = entry.name.lower()
        for pat in name_patterns_lower:
            # Match by fnmatch semantics for the wildcard cases
            # (``license-*``); literal equality otherwise.
            if "*" in pat:
                from fnmatch import fnmatchcase
                if fnmatchcase(name_lower, pat):
                    found.setdefault(name_lower, entry)
                    break
            elif name_lower == pat:
                found.setdefault(name_lower, entry)
                break
    return sorted(found.values(), key=lambda p: p.name.lower())


def _read_license_head(path: Path) -> str:
    """Read the first ``_LICENSE_READ_LINES`` lines of ``path`` as
    text (original case preserved — SPDX ids are case-sensitive).
    Best-effort: binary files and encoding errors return ``""`` so
    the caller's pattern matching falls through to
    ``classification="unknown"`` cleanly."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= _LICENSE_READ_LINES:
                    break
                lines.append(line)
            return "".join(lines)
    except OSError:
        return ""


def _classify_text(text: str) -> tuple:
    """Inspect license text content. Returns
    ``(spdx_id, classification, confidence)``. Caller composes
    these with the file metadata into a TargetLicense.

    Detection precedence:
      1. Compound SPDX-Identifier header (``MIT OR Apache-2.0``;
         OSS only if ALL operands are in the allowlist)
      2. Single SPDX-Identifier header (OSS allowlist membership)
      3. Common-license text fingerprint (medium)
      4. Proprietary marker → ``"proprietary"`` (low)
      5. Nothing matched → ``"unknown"`` (low)
    """
    if not text:
        return None, "unknown", "low"
    # SPDX detection runs on original-case text so the extracted
    # identifier preserves canonical casing (Apache-2.0 vs
    # apache-2.0).
    #
    # Compound header first — order matters because the single-id
    # regex would otherwise match just the first operand and
    # silently drop the rest.
    from .spdx import split_compound_expression
    compound_m = _SPDX_COMPOUND_HEADER_RE.search(text)
    if compound_m:
        expr = compound_m.group(1).strip()
        operands = split_compound_expression(expr)
        # Conservative: all-OSS-operands means the compound is OSS;
        # any non-OSS operand (or a license-WITH-exception form
        # whose exception isn't a recognised license) drops to
        # proprietary. Operators reading the result see the full
        # expression in ``spdx_id``.
        non_oss = [
            op for op in operands
            if not any(oss.lower() == op.lower() for oss in _OSS_SPDX_IDS)
        ]
        if not non_oss:
            return expr, "oss", "high"
        # Special-case ``X WITH Y``: the exception (Y) often isn't a
        # standalone SPDX license id. If the principal license (X)
        # is OSS and the operator separator is WITH, treat the whole
        # as OSS. ``\bWITH\b`` keyword check on the original text
        # disambiguates from AND/OR.
        if (re.search(r"\bWITH\b", expr, re.IGNORECASE)
                and operands
                and any(oss.lower() == operands[0].lower()
                        for oss in _OSS_SPDX_IDS)):
            return expr, "oss", "high"
        return expr, "proprietary", "high"
    m = _SPDX_HEADER_RE.search(text)
    if m:
        spdx = m.group(1)
        canonical = next(
            (oss for oss in _OSS_SPDX_IDS if oss.lower() == spdx.lower()),
            None,
        )
        if canonical:
            return canonical, "oss", "high"
        # SPDX header present but not in our OSS allowlist (e.g. a
        # custom commercial identifier) — treat as proprietary.
        return spdx, "proprietary", "high"
    # Fingerprint matching: pick the EARLIEST hit in the text,
    # not the first in registry order. Pre-fix Firefox's
    # license.html (which contains both "Mozilla Public License"
    # at the top and "permission is hereby granted" later in
    # the bundled-lib aggregation section) classified as MIT
    # because MIT was first in _TEXT_FINGERPRINTS. The earliest
    # position is the signal an operator actually wants — the
    # project's primary license is stated at the top of the
    # file; bundled-lib notices follow it.
    lowered = text.lower()
    earliest_pos: Optional[int] = None
    earliest_spdx: Optional[str] = None
    # Non-GPL fingerprints.
    for spdx, marker in _TEXT_FINGERPRINTS:
        pos = lowered.find(marker)
        if pos == -1:
            continue
        if earliest_pos is None or pos < earliest_pos:
            earliest_pos = pos
            earliest_spdx = spdx
    # BSD discriminator. Present at the BSD-intro position.
    # BSD-3 wins over BSD-2 whenever the "neither the name of"
    # clause is present anywhere in the text — it's strictly
    # MORE restrictive than BSD-2 (extra clause), so if it
    # applies, the license IS BSD-3 not BSD-2.
    bsd_pos = lowered.find(_BSD_INTRO_MARKER)
    if bsd_pos != -1:
        spdx = (
            "BSD-3-Clause"
            if _BSD3_DISCRIMINATOR in lowered
            else "BSD-2-Clause"
        )
        if earliest_pos is None or bsd_pos < earliest_pos:
            earliest_pos = bsd_pos
            earliest_spdx = spdx
    # GPL-family fingerprints — version-disambiguated. The
    # version is essential (GPL-2.0 vs GPL-3.0 is a material
    # licensing distinction). Resolved by scanning the text near
    # the family marker for ``Version X``.
    for family, marker, default_ver in _GPL_FAMILY_FINGERPRINTS:
        pos = lowered.find(marker)
        if pos == -1:
            continue
        if earliest_pos is None or pos < earliest_pos:
            spdx = _classify_gpl_version(text, family, pos, default_ver)
            earliest_pos = pos
            earliest_spdx = spdx
    if earliest_spdx is not None:
        return earliest_spdx, "oss", "medium"
    for marker in _PROPRIETARY_MARKERS:
        if marker in lowered:
            return None, "proprietary", "low"
    return None, "unknown", "low"


# Version regex: "Version 2", "Version 2.1", "Version 3.0" —
# common in GNU LICENSE preambles ("GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007"). Captures the version number.
_GPL_VERSION_RE = re.compile(
    r"\bversion\s+(\d+(?:\.\d+)?)\b", re.IGNORECASE,
)


def _classify_gpl_version(
    text: str, family: str, family_pos: int, default_version: str,
) -> str:
    """Resolve the GPL-family SPDX id by looking for a ``Version X``
    marker near the family preamble. Searches a window starting
    at the family-marker position so a project that mentions
    multiple GPL versions doesn't get confused (the version
    nearest the preamble is the one that classifies the file).
    Falls back to the family's default version when no version
    marker is found within the window.
    """
    # Window: ~500 chars after the family marker — enough to
    # capture "Version X" on the line immediately after the
    # title (every GNU preamble I've seen puts the version on
    # line 2 or 3).
    window = text[family_pos: family_pos + 500]
    m = _GPL_VERSION_RE.search(window)
    if m:
        version = m.group(1)
    else:
        version = default_version
    # SPDX normalises bare-integer versions to N.0 (the
    # canonical id is "GPL-3.0", "AGPL-3.0", "LGPL-2.0" —
    # never "GPL-3"). "LGPL-2.1" keeps its minor because it's
    # a distinct license version (LGPL changed substantively
    # from 2.0 → 2.1).
    if "." not in version:
        version = f"{version}.0"
    return f"{family}-{version}"


def detect_target_license(target_dir: Path) -> TargetLicense:
    """Walk the target's top-level dir for license files; return the
    classification of the strongest signal.

    When multiple license files exist (e.g. dual-licensed
    ``LICENSE-MIT`` + ``LICENSE-APACHE``), pick the file with the
    highest-confidence detection and record the others in
    ``additional_files``. ''Highest confidence'' breaks ties in
    favour of an SPDX header, then a text fingerprint, then
    anything else.

    When the strongest top-level file is itself a redirect
    (e.g. Firefox's ``LICENSE`` → "see toolkit/content/license.html"),
    follow up to ``_INDIRECTION_DEPTH_LIMIT`` levels of file
    references, re-classifying each, and adopt the strongest
    classification found anywhere in the chain. Path-traversal
    defended: referenced paths must resolve inside ``target_dir``.

    No-match cases:
      * No license files at top level → ``classification="missing"``
      * Files present + indirection-followed but still no match →
        ``classification="unknown"``
    """
    target_dir = Path(target_dir).resolve()
    files = _find_license_files(target_dir)
    if not files:
        return TargetLicense(
            spdx_id=None, classification="missing",
            source_file=None, confidence="low",
        )

    # Score each file by detection confidence; pick the
    # strongest. Dual-license projects (e.g. libgcrypt ships
    # ``COPYING`` GPL + ``COPYING.LIB`` LGPL; NetworkManager
    # ships COPYING GPL + COPYING.LGPL) are inherently
    # ambiguous — there's no general way to know which one is
    # the operator's intended "project license." We report
    # whichever has the highest-confidence detection (ties
    # broken by alphabetical filename for determinism), and
    # the ``additional_files`` field carries the rest so the
    # operator can see the layout.
    _CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}
    best = None
    best_rank = -1
    for f in files:
        text = _read_license_head(f)
        spdx, classification, confidence = _classify_text(text)
        rank = _CONFIDENCE_RANK[confidence]
        if rank > best_rank:
            best = (f, spdx, classification, confidence)
            best_rank = rank
    assert best is not None  # files non-empty → loop ran at least once
    chosen_file, spdx, classification, confidence = best
    additional = tuple(
        f.name for f in files if f != chosen_file
    )

    # Follow LICENSE-file indirections ("see X" / "license is in X"
    # / "refer to X") when the strongest top-level signal didn't
    # classify. Common for projects whose root LICENSE points at
    # a nested file (Firefox → toolkit/content/license.html;
    # multi-license projects → LICENSES/<spdx>.txt). Returns the
    # original TargetLicense unchanged when the chain doesn't
    # improve confidence.
    if classification == "unknown":
        follow_result = _follow_license_indirection(
            target_dir, chosen_file,
        )
        if follow_result is not None:
            spdx, classification, confidence, chosen_path = follow_result
            return TargetLicense(
                spdx_id=spdx,
                classification=classification,
                # Render as a relative path so the operator can
                # see the chain hop ("toolkit/content/license.html"
                # rather than just "license.html").
                source_file=str(
                    chosen_path.relative_to(target_dir),
                ),
                confidence=confidence,
                additional_files=additional,
            )

    return TargetLicense(
        spdx_id=spdx,
        classification=classification,
        source_file=chosen_file.name,
        confidence=confidence,
        additional_files=additional,
    )


# Indirection-follow tunables. Bounded recursion + path count
# prevent a malicious / pathological LICENSE chain from making
# detection allocate forever.
_INDIRECTION_DEPTH_LIMIT = 2          # root LICENSE → linked → linked-of-linked
_INDIRECTION_PATH_LIMIT = 8           # cap referenced paths per file
_INDIRECTION_FILE_BYTES = 256 * 1024  # cap per-file read at 256 KB


# Patterns we recognise as "this LICENSE file points elsewhere".
# Case-insensitive; capture group 1 is the referenced path.
# Conservative: only match patterns whose intent is unambiguous
# ("see file X", "refer to X", "license is in X", "license can be
# found at X"). Don't try to parse free-form prose like "X is the
# license file" — false positives there are worse than a missed
# follow.
# Path shape recognised in "see X" patterns: either a common
# file extension (txt/md/rst/html/htm), OR a license-naming
# convention (LICENSE.<id> / LICENCE.<id> / COPYING.<id>) where
# the suffix is the license id rather than a conventional
# extension. tracker's COPYING says "See the file COPYING.LGPL"
# — no .txt/.md/etc. but unambiguously a license-file reference.
_INDIRECTION_PATH = (
    r"(?:"
    r"[A-Za-z0-9_./\-]+\.(?:txt|md|rst|html?|htm)"
    r"|"
    r"(?:[A-Za-z0-9_./\-]+/)?(?:LICENSE|LICENCE|COPYING)\.[A-Za-z0-9_\-]+"
    r")"
)
_INDIRECTION_PATTERNS = [
    re.compile(
        r"(?:please\s+)?see\s+(?:the\s+file\s+)?(" + _INDIRECTION_PATH + r")",
        re.IGNORECASE,
    ),
    re.compile(
        r"licens(?:e|ing)\s+(?:text\s+)?is\s+in\s+("
        + _INDIRECTION_PATH + r")",
        re.IGNORECASE,
    ),
    re.compile(
        r"refer\s+to\s+(" + _INDIRECTION_PATH + r")",
        re.IGNORECASE,
    ),
    re.compile(
        r"licens(?:e|ing)\s+(?:can\s+be\s+|may\s+be\s+)?"
        r"found\s+(?:at|in)\s+(" + _INDIRECTION_PATH + r")",
        re.IGNORECASE,
    ),
    # Plain "see DIR/" pattern — referenced TARGET is a directory.
    # We resolve to every license-named file inside that dir.
    re.compile(
        r"see\s+(?:the\s+)?([A-Za-z0-9_./\-]+/)\s+(?:directory|dir|folder)",
        re.IGNORECASE,
    ),
]


def _extract_indirection_paths(text: str) -> List[str]:
    """Return referenced paths from a LICENSE body, capped at
    ``_INDIRECTION_PATH_LIMIT`` so a malicious file with hundreds
    of "see X" lines can't make the follow allocate forever."""
    found: List[str] = []
    seen: set = set()
    for pat in _INDIRECTION_PATTERNS:
        for m in pat.finditer(text):
            ref = m.group(1)
            if ref not in seen:
                seen.add(ref)
                found.append(ref)
                if len(found) >= _INDIRECTION_PATH_LIMIT:
                    return found
    return found


def _read_license_full(path: Path, byte_cap: int) -> str:
    """Like ``_read_license_head`` but reads up to ``byte_cap``
    bytes (for indirection-follow we may need the full body of
    a linked file, not just the header). Best-effort: returns
    "" on any IO / encoding error.

    Uses ``O_NOFOLLOW`` defence-in-depth — the caller already
    refuses symlinked indirection targets via is_symlink before
    resolve, but a TOCTOU swap between the check and the open
    could otherwise pivot us through a symlink. O_NOFOLLOW
    refuses to open a symlink at the final path component.
    """
    import os
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "rb") as f:
            buf = f.read(byte_cap)
        return buf.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _follow_license_indirection(
    target_dir: Path, source_file: Path,
):
    """Recursively follow ``see X`` / ``license is in X`` /
    ``refer to X`` references inside license files. Returns
    ``(spdx, classification, confidence, resolved_path)`` for
    the strongest classified file in the chain, or None when
    the chain doesn't improve over the caller's unknown.

    Path-traversal defended: every referenced path is resolved
    relative to the file containing it, then checked to live
    inside ``target_dir.resolve()``. Symlinks rejected outright
    (a malicious LICENSE-redirect chain via symlinks could
    otherwise escape the target tree).
    """
    target_dir = target_dir.resolve()
    _CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}
    best = None
    best_rank = -1

    # BFS over the chain so we visit every referenced file once,
    # not depth-first into the first link. Queue entries are
    # (file_path, depth, is_root) — is_root flags the original
    # source_file we're trying to improve, so we don't re-
    # classify it (caller already did that and got unknown).
    queue: List[tuple] = [(source_file, 0, True)]
    visited: set = set()
    visited.add(source_file.resolve())

    while queue:
        current_file, depth, is_root = queue.pop(0)
        if depth > _INDIRECTION_DEPTH_LIMIT:
            continue

        # Read the file ONCE — classify_text AND extract refs
        # both consume the same body. Pre-fix this read each
        # non-root file twice, doubling IO on the indirection
        # path (which already includes a per-target walk).
        text = _read_license_full(current_file, _INDIRECTION_FILE_BYTES)
        if not text:
            continue

        # Classify the current file — unless it's the root
        # (caller already classified it and found unknown).
        # Earliest-position fingerprint matching in _classify_text
        # handles multi-license aggregation files correctly
        # (Firefox's license.html: MPL at top, bundled-lib
        # notices later → picks MPL). No HTML-specific
        # downgrade needed here; the position-based picker is
        # the principled fix.
        if not is_root:
            spdx, classification, confidence = _classify_text(text)
            rank = _CONFIDENCE_RANK[confidence]
            if rank > best_rank:
                best = (spdx, classification, confidence, current_file)
                best_rank = rank

        # Extract this file's own references and enqueue them
        # for further follow.
        refs = _extract_indirection_paths(text)

        for ref in refs:
            # Reject absolute-path refs and `~` expansion at
            # the regex layer's blind spot — defence in depth
            # before resolve() canonicalises.
            if ref.startswith(("/", "~")):
                continue
            # Check is_symlink on the RAW (un-resolved) path
            # FIRST. After .resolve() canonicalises, the result
            # is the final target, and is_symlink() always
            # returns False for it — so a post-resolve check
            # would never fire. A LICENSE redirect via an
            # in-tree symlink to e.g. ``.env`` would otherwise
            # bypass our intent to "refuse symlink-pivoted
            # indirection chains."
            raw = current_file.parent / ref
            try:
                if raw.is_symlink():
                    continue
            except OSError:
                continue
            # Resolve relative to the file containing the ref,
            # not the target root — references are usually
            # written as paths relative to the operator's view
            # of the repo (LICENSES/MIT.txt under the root,
            # ./license.html in a nested file).
            try:
                candidate = raw.resolve()
            except (OSError, ValueError):
                continue
            if candidate in visited:
                continue
            visited.add(candidate)

            # Path-traversal defence: must live inside target_dir.
            try:
                candidate.relative_to(target_dir)
            except ValueError:
                continue

            # Directory reference: enqueue every license-named
            # file inside it. Same-depth, NOT depth+1 — the dir
            # itself isn't being classified, just enumerated;
            # each file inside is the same hop as if it had been
            # referenced directly. Otherwise a real chain like
            # "LICENSE → see LICENSES/ directory → MIT.txt" hits
            # the depth limit at the contents step.
            #
            # Capped at ``_INDIRECTION_PATH_LIMIT`` children too —
            # otherwise a hostile target with 10k files in
            # LICENSES/ would enqueue all of them, blowing the
            # per-file caps' intent.
            if candidate.is_dir():
                enqueued_from_dir = 0
                try:
                    for child in candidate.iterdir():
                        if enqueued_from_dir >= _INDIRECTION_PATH_LIMIT:
                            break
                        if not child.is_file() or child.is_symlink():
                            continue
                        if child.suffix.lower() in (".txt", ".md", ".rst", ".html", ".htm") or "license" in child.name.lower() or "copying" in child.name.lower():
                            if child.resolve() not in visited:
                                visited.add(child.resolve())
                                queue.append((child, depth + 1, False))
                                enqueued_from_dir += 1
                except OSError:
                    pass
                continue

            if not candidate.is_file():
                continue

            queue.append((candidate, depth + 1, False))

    if best is not None and best[1] != "unknown":
        return best
    return None


def format_license_summary(lic: TargetLicense, *, command: str = "") -> str:
    """Render a terse operator-facing one-liner (plus a warning
    when classification raises CodeQL-license concerns).

    The HOW of detection (source file, confidence tier, additional
    files) is left to debug-level logging — most operators just
    want the classification at a glance. ``log_license_details``
    emits the full record for debugging / forensic review.

    The optional ``command`` argument lets the caller indicate which
    RAPTOR command is about to run — when it's CodeQL-related (the
    license terms restrict non-OSS use), the warning text mentions
    /codeql specifically.
    """
    cmd_lower = command.lower()
    is_codeql_path = "codeql" in cmd_lower or cmd_lower in {"agentic", "scan"}
    lines: list = []

    if lic.classification == "oss":
        lines.append(f"Target license: {lic.spdx_id}")
    elif lic.classification == "proprietary":
        spdx_part = f" ({lic.spdx_id})" if lic.spdx_id else ""
        lines.append(f"Target license: proprietary{spdx_part}")
        if is_codeql_path:
            lines.append(
                "  ⚠️  CodeQL terms restrict use on non-OSS code. "
                "Verify your CodeQL use is licensed (free tier covers "
                "OSS / research / education only) before continuing."
            )
    elif lic.classification == "unknown":
        lines.append("Target license: undetermined")
        if is_codeql_path:
            lines.append(
                "  ⚠️  RAPTOR can't determine if CodeQL's free-tier "
                "terms apply. Check the license before running /codeql."
            )
    else:  # "missing"
        lines.append("Target license: not detected")
        if is_codeql_path:
            lines.append(
                "  ⚠️  No license file means RAPTOR can't tell if "
                "CodeQL's free-tier terms apply. Check before running "
                "/codeql; for first-party / bug-bounty / pentest use "
                "this is usually fine, but verify."
            )
    return "\n".join(lines)


def log_license_details(lic: TargetLicense) -> None:
    """Emit the detection HOW at debug level — operator-facing
    summary stays terse via ``format_license_summary``; investigators
    or anyone running RAPTOR with ``--verbose`` / debug-log enabled
    can see source file, confidence tier, additional files."""
    import logging
    logger = logging.getLogger(__name__)
    logger.debug(
        "license-detect: classification=%s spdx_id=%s source=%s "
        "confidence=%s additional=%s",
        lic.classification, lic.spdx_id, lic.source_file,
        lic.confidence,
        list(lic.additional_files) or None,
    )
