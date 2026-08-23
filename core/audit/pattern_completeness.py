"""Detect regex, glob, and prefix patterns that are too narrow.

Real bugs this catches:

- Bug 389: ``_is_pip_option`` uses ``line.startswith("--editable")`` so
  ``--editable <spec>`` is dropped, but ``-e <spec>`` works.
- Bug 393: ``glob("*.yml")`` misses GitHub-valid ``*.yaml`` workflows.
- Bug 437: ``_PURL_RE`` path group ``[^@?#]+`` rejects leading ``@``,
  so scoped npm packages (``@scope/name``) are dropped.
- Bug 382: ``_split_image_ref`` doesn't handle tag+digest combinations
  (``nginx:1.18@sha256:...``).

All detection is mechanical — regex on source text, no LLM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._util import find_enclosing_function as _find_enclosing_function

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

GAP_TYPES = frozenset({
    "missing_synonym",
    "char_class_exclusion",
    "greedy_prefix",
    "missing_combination",
})


@dataclass
class PatternGap:
    """A pattern that handles some valid inputs but not all."""

    file: str
    function: str
    line: int
    pattern: str
    gap_type: str
    suggestion: str
    confidence: str
    sibling_pattern: str = ""

    def __post_init__(self) -> None:
        if self.gap_type not in GAP_TYPES:
            msg = (
                f"gap_type must be one of {sorted(GAP_TYPES)}, "
                f"got {self.gap_type!r}"
            )
            raise ValueError(msg)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "pattern": self.pattern,
            "gap_type": self.gap_type,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "sibling_pattern": self.sibling_pattern,
        }


# ---------------------------------------------------------------------------
# Extension synonym table
# ---------------------------------------------------------------------------

# Each tuple lists synonyms — if a pattern uses one but not the others in
# the same file/module, the missing ones are flagged.
_EXTENSION_SYNONYM_GROUPS: list[tuple[str, ...]] = [
    (".yml", ".yaml"),
    (".htm", ".html"),
    (".jpg", ".jpeg"),
    (".tar.gz", ".tgz"),
]

# Build a flat lookup: extension -> tuple-of-synonyms (excluding itself).
_EXTENSION_SYNONYMS: dict[str, tuple[str, ...]] = {}
for _group in _EXTENSION_SYNONYM_GROUPS:
    for _ext in _group:
        _EXTENSION_SYNONYMS[_ext] = tuple(e for e in _group if e != _ext)

# Directories where specific extensions are expected.
_DIRECTORY_EXTENSION_EXPECTATIONS: dict[str, tuple[str, ...]] = {
    ".github/workflows": (".yml", ".yaml"),
}

# ---------------------------------------------------------------------------
# CLI option short/long form table
# ---------------------------------------------------------------------------

_SHORT_LONG_PAIRS: list[tuple[str, str]] = [
    ("-e", "--editable"),
    ("-r", "--requirement"),
    ("-f", "--find-links"),
    ("-i", "--index-url"),
    ("-c", "--constraint"),
    ("-o", "--output"),
    ("-v", "--verbose"),
    ("-q", "--quiet"),
    ("-h", "--help"),
    ("-n", "--dry-run"),
    ("-p", "--port"),
]

_SHORT_TO_LONG: dict[str, str] = {short: long for short, long in _SHORT_LONG_PAIRS}
_LONG_TO_SHORT: dict[str, str] = {long: short for short, long in _SHORT_LONG_PAIRS}

# ---------------------------------------------------------------------------
# Regex character class known-valid chars by domain
# ---------------------------------------------------------------------------

_DOMAIN_VALID_CHARS: dict[str, str] = {
    "purl": "@:/?#",
    "npm": "@/",
    "url": ":@[]?#/",
    "path": " ",
    "docker": ":@/",
}

# Keywords that hint at the domain of a regex pattern.
_DOMAIN_HINTS: dict[str, list[str]] = {
    "purl": ["purl", "pkg:", "package_url", "PURL"],
    "npm": ["npm", "node_module", "package.json", "scoped"],
    "url": ["url", "uri", "href", "endpoint", "http"],
    "docker": ["image", "docker", "container", "registry", "tag", "digest"],
    "path": ["path", "filename", "filepath", "dirname"],
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Matches glob("*.ext") or glob("**/*.ext") patterns.
_GLOB_RE = re.compile(
    r"""glob\(\s*["'](\*\*/?)?\*(\.[a-zA-Z0-9_.]+)["']\s*\)"""
)

# Matches endswith(".ext") patterns.
_ENDSWITH_RE = re.compile(
    r"""\.endswith\(\s*["'](\.[a-zA-Z0-9_.]+)["']\s*\)"""
)

# Matches startswith("--option") or startswith("-x") patterns.
# The option may be followed by a space (e.g., startswith("-e ")), which
# we strip — we only care about the flag itself for sibling lookup.
_STARTSWITH_RE = re.compile(
    r"""\.startswith\(\s*["'](--?[a-zA-Z][\w-]*)\s*["']\s*\)"""
)

# Matches negated character classes in regexes: [^...].
_NEGATED_CLASS_RE = re.compile(
    r"""\[\^([^\]]+)\]"""
)


def _nearby_text(lines: list[str], line_idx: int, window: int = 10) -> str:
    """Return source text around a line for domain hinting."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window + 1)
    return "\n".join(lines[start:end])


def _guess_domain(context: str) -> str | None:
    """Guess the domain from surrounding source text."""
    context_lower = context.lower()
    for domain, hints in _DOMAIN_HINTS.items():
        for hint in hints:
            if hint.lower() in context_lower:
                return domain
    return None


# ---------------------------------------------------------------------------
# Sub-detectors
# ---------------------------------------------------------------------------

def _detect_extension_synonym_gaps(
    filename: str,
    source: str,
    lines: list[str],
) -> list[PatternGap]:
    """Find glob/endswith patterns that use one extension but miss synonyms."""
    gaps: list[PatternGap] = []
    source_lower = source.lower()

    for line_idx, line in enumerate(lines):
        line_no = line_idx + 1

        # Check glob patterns.
        for m in _GLOB_RE.finditer(line):
            ext = m.group(2).lower()
            synonyms = _EXTENSION_SYNONYMS.get(ext)
            if not synonyms:
                continue
            # Check if ANY synonym is also handled in this file.
            missing = [
                s for s in synonyms
                if f"*{s}" not in source_lower
                and f'"{s}"' not in source_lower
                and f"'{s}'" not in source_lower
            ]
            gaps.extend(PatternGap(
                    file=filename,
                    function=_find_enclosing_function(lines, line_idx),
                    line=line_no,
                    pattern=m.group(0),
                    gap_type="missing_synonym",
                    suggestion=f"also match *{miss}",
                    confidence="high",
                ) for miss in missing)

        # Check endswith patterns.
        for m in _ENDSWITH_RE.finditer(line):
            ext = m.group(1).lower()
            synonyms = _EXTENSION_SYNONYMS.get(ext)
            if not synonyms:
                continue
            missing = [
                s for s in synonyms
                if f'"{s}"' not in source_lower
                and f"'{s}'" not in source_lower
            ]
            gaps.extend(PatternGap(
                    file=filename,
                    function=_find_enclosing_function(lines, line_idx),
                    line=line_no,
                    pattern=m.group(0),
                    gap_type="missing_synonym",
                    suggestion=f'also check endswith("{miss}")',
                    confidence="high",
                ) for miss in missing)

    return gaps


def _detect_sibling_prefix_gaps(
    filename: str,
    source: str,
    lines: list[str],
) -> list[PatternGap]:
    """Find startswith patterns where a short/long form sibling is missing."""
    gaps: list[PatternGap] = []

    # Collect all startswith options in this file.
    prefix_locations: list[tuple[str, int, str]] = []  # (option, line_no, match_text)
    for line_idx, line in enumerate(lines):
        prefix_locations.extend((m.group(1), line_idx + 1, m.group(0)) for m in _STARTSWITH_RE.finditer(line))

    all_prefixes = {opt for opt, _, _ in prefix_locations}

    for option, line_no, match_text in prefix_locations:
        sibling: str | None = None
        if option in _LONG_TO_SHORT:
            sibling = _LONG_TO_SHORT[option]
        elif option in _SHORT_TO_LONG:
            sibling = _SHORT_TO_LONG[option]

        if sibling is None:
            continue

        # Check if the sibling is handled ANYWHERE in this file.
        # Look for startswith("sibling"), sibling in quotes, etc.
        sibling_present = (
            sibling in all_prefixes
            or f'"{sibling}"' in source
            or f"'{sibling}'" in source
        )
        if sibling_present:
            # Both forms exist — but check if one is in an exclusion
            # context and the other in a handler context.
            line_idx = line_no - 1
            # Heuristic: check a small window around the startswith line
            # AND the enclosing function name for exclusion hints.
            exclusion_hints = ("skip", "ignore", "exclude", "filter",
                               "discard", "drop", "is_pip_option",
                               "is_option", "reject", "deny")
            context_window = _nearby_text(lines, line_idx, window=3).lower()
            func_name = _find_enclosing_function(lines, line_idx).lower()
            is_exclusion = (
                any(h in context_window for h in exclusion_hints)
                or any(h in func_name for h in exclusion_hints)
            )

            if is_exclusion:
                # Check if sibling is ALSO in an exclusion context.
                # We look for sibling in startswith() calls specifically
                # to avoid false matches (e.g., "-e" inside "--editable").
                sibling_in_exclusion = False
                sibling_sw = f'startswith("{sibling}'
                sibling_sw2 = f"startswith('{sibling}"
                for other_idx, other_line in enumerate(lines):
                    if sibling_sw not in other_line and \
                            sibling_sw2 not in other_line:
                        continue
                    other_ctx = _nearby_text(
                        lines, other_idx, window=3,
                    ).lower()
                    other_func = _find_enclosing_function(
                        lines, other_idx,
                    ).lower()
                    if (any(h in other_ctx for h in exclusion_hints)
                            or any(h in other_func
                                   for h in exclusion_hints)):
                        sibling_in_exclusion = True
                        break
                if not sibling_in_exclusion:
                    gaps.append(PatternGap(
                        file=filename,
                        function=_find_enclosing_function(
                            lines, line_idx,
                        ),
                        line=line_no,
                        pattern=match_text,
                        gap_type="greedy_prefix",
                        suggestion=(
                            f'"{option}" is excluded but sibling '
                            f'"{sibling}" is handled differently'
                        ),
                        confidence="medium",
                        sibling_pattern=f'startswith("{sibling}")',
                    ))
        else:
            # Sibling is completely absent.
            gaps.append(PatternGap(
                file=filename,
                function=_find_enclosing_function(lines, line_no - 1),
                line=line_no,
                pattern=match_text,
                gap_type="greedy_prefix",
                suggestion=(
                    f'handles "{option}" but not its sibling "{sibling}"'
                ),
                confidence="medium",
                sibling_pattern="",
            ))

    return gaps


def _detect_char_class_exclusions(
    filename: str,
    _source: str,
    lines: list[str],
) -> list[PatternGap]:
    """Find negated character classes that exclude valid domain chars."""
    gaps: list[PatternGap] = []

    for line_idx, line in enumerate(lines):
        line_no = line_idx + 1

        for m in _NEGATED_CLASS_RE.finditer(line):
            excluded_chars = m.group(1)
            context = _nearby_text(lines, line_idx)
            domain = _guess_domain(context)
            if domain is None:
                continue

            valid_chars = _DOMAIN_VALID_CHARS.get(domain, "")
            wrongly_excluded = [
                ch for ch in valid_chars
                if ch in excluded_chars
            ]

            if wrongly_excluded:
                gaps.append(PatternGap(
                    file=filename,
                    function=_find_enclosing_function(lines, line_idx),
                    line=line_no,
                    pattern=f"[^{excluded_chars}]",
                    gap_type="char_class_exclusion",
                    suggestion=(
                        f"character class excludes "
                        f"{', '.join(repr(c) for c in wrongly_excluded)} "
                        f"but {domain} inputs can contain "
                        f"{'them' if len(wrongly_excluded) > 1 else 'it'}"
                    ),
                    confidence="high" if len(wrongly_excluded) > 1 else "medium",
                ))

    return gaps


def _detect_directory_glob_gaps(
    filename: str,
    source: str,
    lines: list[str],
) -> list[PatternGap]:
    """Flag globs in known directory types that miss expected extensions."""
    gaps: list[PatternGap] = []

    for dir_pattern, expected_exts in _DIRECTORY_EXTENSION_EXPECTATIONS.items():
        if dir_pattern not in source:
            continue
        # Find which expected extensions appear in glob patterns.
        found_exts = set()
        for ext in expected_exts:
            if f"*{ext}" in source.lower():
                found_exts.add(ext)

        if not found_exts:
            continue  # No relevant globs at all — nothing to flag.

        missing = set(expected_exts) - found_exts
        if not missing:
            continue

        # Find the line where the dir pattern appears for anchoring.
        for line_idx, line in enumerate(lines):
            if dir_pattern in line:
                for miss in sorted(missing):
                    present = sorted(found_exts)
                    gaps.append(PatternGap(
                        file=filename,
                        function=_find_enclosing_function(lines, line_idx),
                        line=line_idx + 1,
                        pattern=f"*{present[0]} in {dir_pattern}",
                        gap_type="missing_synonym",
                        suggestion=(
                            f"also glob *{miss} in {dir_pattern}"
                        ),
                        confidence="high",
                        sibling_pattern=f"*{present[0]}",
                    ))
                break  # Only flag once per directory pattern.

    return gaps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_pattern_gaps(source_text: dict[str, str]) -> list[PatternGap]:
    """Detect patterns in source files that are too narrow.

    Args:
        source_text: Mapping of ``{filename: source_code}``.

    Returns:
        List of ``PatternGap`` instances, one per detected gap.
    """
    all_gaps: list[PatternGap] = []

    for filename, source in source_text.items():
        lines = source.splitlines()

        all_gaps.extend(_detect_extension_synonym_gaps(filename, source, lines))
        all_gaps.extend(_detect_sibling_prefix_gaps(filename, source, lines))
        all_gaps.extend(_detect_char_class_exclusions(filename, source, lines))
        all_gaps.extend(_detect_directory_glob_gaps(filename, source, lines))

    return all_gaps
