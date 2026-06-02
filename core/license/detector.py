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
_TEXT_FINGERPRINTS = (
    ("MIT", "permission is hereby granted, free of charge"),
    ("Apache-2.0", "apache license"),
    ("BSD-3-Clause", "neither the name of"),
    ("BSD-2-Clause", "redistribution and use in source and binary forms"),
    ("ISC", "permission to use, copy, modify, and/or distribute"),
    ("MPL-2.0", "mozilla public license"),
    ("GPL-3.0", "gnu general public license"),
    ("LGPL-2.1", "gnu lesser general public license"),
    ("AGPL-3.0", "gnu affero general public license"),
    ("Unlicense", "this is free and unencumbered software"),
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
    Symlinks dropped defensively — a symlink to /etc/passwd via a
    crafted LICENSE link shouldn't be read."""
    found: dict = {}  # name → Path (dedup case-insensitive)
    if not target_dir.is_dir():
        return []
    try:
        entries = list(target_dir.iterdir())
    except OSError:
        return []
    name_patterns_lower = [p.lower() for p in _LICENSE_FILENAME_PATTERNS]
    for entry in entries:
        if not entry.is_file() or entry.is_symlink():
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
    # Fingerprint and marker checks are case-insensitive — license
    # preambles vary on title-case vs upper-case across projects.
    lowered = text.lower()
    for spdx, marker in _TEXT_FINGERPRINTS:
        if marker in lowered:
            return spdx, "oss", "medium"
    for marker in _PROPRIETARY_MARKERS:
        if marker in lowered:
            return None, "proprietary", "low"
    return None, "unknown", "low"


def detect_target_license(target_dir: Path) -> TargetLicense:
    """Walk the target's top-level dir for license files; return the
    classification of the strongest signal.

    When multiple license files exist (e.g. dual-licensed
    ``LICENSE-MIT`` + ``LICENSE-APACHE``), pick the file with the
    highest-confidence detection and record the others in
    ``additional_files``. ''Highest confidence'' breaks ties in
    favour of an SPDX header, then a text fingerprint, then
    anything else.

    No-match cases:
      * No license files at top level → ``classification="missing"``
      * Files present but none classifiable → ``classification="unknown"``
    """
    target_dir = Path(target_dir)
    files = _find_license_files(target_dir)
    if not files:
        return TargetLicense(
            spdx_id=None, classification="missing",
            source_file=None, confidence="low",
        )

    # Score each file by detection confidence to pick the strongest.
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
    return TargetLicense(
        spdx_id=spdx,
        classification=classification,
        source_file=chosen_file.name,
        confidence=confidence,
        additional_files=additional,
    )


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
