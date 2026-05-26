"""Maven version comparator.

Maven version ordering is genuinely subtle — it has its own qualifier
system, where qualifiers like SNAPSHOT, alpha, beta, rc, sp, ga, final
have specific meanings. The canonical implementation is the
`maven-artifact` library's ComparableVersion class.

This is the most-corner-cased ecosystem comparator. The headline gotcha:
    1.0-SNAPSHOT < 1.0
That's because a qualifier (SNAPSHOT) attached to a release version makes
it pre-release relative to the bare release.

Reference: https://maven.apache.org/pom.html#Dependency_Version_Requirement_Specification
Reference: https://maven.apache.org/ref/3.9.6/maven-artifact/apidocs/org/apache/maven/artifact/versioning/ComparableVersion.html

Implementation strategy:
    Tokenise on . - and the digit/non-digit boundary, then compare token
    streams component-wise. A "qualifier-only" segment compares by the
    well-known qualifier order; numeric segments by integer comparison.

Limitations of this implementation (acceptable for /sca):
    - Doesn't handle every weird input (e.g., empty segments).
    - Some Maven version edge cases (deeply nested qualifiers) may rank
    differently from ComparableVersion. We mark Maven advisories with
    `version_match_confidence: medium` when the comparison is non-trivial
    so operators are aware.

For full fidelity we'd shell out to `mvn` or wrap a pyjnius binding —
both add weighty dependencies. The current behaviour covers the common
case (release vs pre-release, simple numeric ordering) correctly.
"""

from __future__ import annotations

import re
from typing import List, Tuple, Union

# Well-known qualifier ordering (lower = older; SNAPSHOT/alpha/beta/rc <
# release, sp > release).
# Adapted from ComparableVersion.QUALIFIERS order.
_QUALIFIER_ORDER = {
    "alpha": -5,
    "a": -5,
    "beta": -4,
    "b": -4,
    "milestone": -3,
    "m": -3,
    "rc": -2,
    "cr": -2,
    "snapshot": -1,
    "": 0,            # "" represents 'release' / 'ga' / 'final'
    "ga": 0,
    "final": 0,
    "release": 0,
    "sp": 1,
}

# Tokenise into runs of digits, runs of letters, and explicit separators.
_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+|[.\-_])")


# A token is either a numeric int, a qualifier string, or a separator (str).
Token = Union[int, str]


def _tokenise(version: str) -> List[Token]:
    """Tokenise a Maven version string into ints, qualifier strings, and
    separators."""
    out: List[Token] = []
    for m in _TOKEN_RE.finditer(version.strip().lower()):
        tok = m.group(1)
        if tok.isdigit():
            out.append(int(tok))
        else:
            out.append(tok)
    return out


def _items(version: str) -> List[Tuple[str, Union[int, str]]]:
    """Convert tokens to (kind, value) pairs, where kind is one of
    'int', 'str' (qualifier), or 'sep'."""
    pairs: List[Tuple[str, Union[int, str]]] = []
    for tok in _tokenise(version):
        if isinstance(tok, int):
            pairs.append(("int", tok))
        elif tok in (".", "-", "_"):
            pairs.append(("sep", tok))
        else:
            pairs.append(("str", tok))
    return pairs


def compare(a: str, b: str) -> int:
    """Return -1, 0, 1 per Maven version ordering."""
    if a == b:
        return 0
    items_a = _items(a)
    items_b = _items(b)
    # Strip trailing zero-equivalents for comparison stability:
    # 1.0.0 == 1.0, 1.0-ga == 1.0, etc.
    items_a = _strip_trivial_tail(items_a)
    items_b = _strip_trivial_tail(items_b)

    # Compare aligned non-separator tokens.
    ia = [p for p in items_a if p[0] != "sep"]
    ib = [p for p in items_b if p[0] != "sep"]
    for ta, tb in zip(ia, ib):
        c = _compare_tokens(ta, tb)
        if c != 0:
            return c
    # Lengths differ — extra tokens in one side decide ordering.
    # An extra integer 0 doesn't matter (1.0.0 == 1.0); other extras do.
    if len(ia) == len(ib):
        return 0
    if len(ia) < len(ib):
        return -_compare_extra(ib[len(ia):])
    return _compare_extra(ia[len(ib):])


def _compare_tokens(ta: Tuple[str, Union[int, str]],
                    tb: Tuple[str, Union[int, str]]) -> int:
    ka, va = ta
    kb, vb = tb
    if ka == "int" and kb == "int":
        if va == vb:
            return 0
        return -1 if va < vb else 1
    if ka == "int" and kb == "str":
        # Numeric segment > qualifier (e.g., 1.0.1 > 1.0-SNAPSHOT)
        return 1
    if ka == "str" and kb == "int":
        return -1
    # both str: qualifier order
    oa = _QUALIFIER_ORDER.get(va, None)
    ob = _QUALIFIER_ORDER.get(vb, None)
    if oa is not None and ob is not None:
        if oa == ob:
            return 0
        return -1 if oa < ob else 1
    # Unknown qualifiers compared lexicographically among themselves;
    # known qualifiers always sort before unknowns? Per ComparableVersion,
    # unknowns sort AFTER all known qualifiers; relative to each other
    # lexicographically.
    if oa is not None and ob is None:
        return -1
    if oa is None and ob is not None:
        return 1
    if va == vb:
        return 0
    return -1 if va < vb else 1


def _compare_extra(extras: List[Tuple[str, Union[int, str]]]) -> int:
    """When two versions differ in length, decide ordering from the extra
    tokens of the longer one. Extra zeros don't matter; extra qualifiers
    typically make it less.
    """
    for kind, val in extras:
        if kind == "int":
            if val != 0:
                return 1 if val > 0 else -1
            # int 0 is trivial; continue
        elif kind == "str":
            order = _QUALIFIER_ORDER.get(val, None)
            if order is None:
                # Unknown qualifier — convention: sort longer side higher
                return 1
            if order < 0:
                return -1   # alpha/beta/rc/snapshot makes it lower
            if order > 0:
                return 1    # sp makes it higher
            # order == 0 (ga/final/release equivalent) is trivial
    return 0


def _strip_trivial_tail(items: List[Tuple[str, Union[int, str]]]
                         ) -> List[Tuple[str, Union[int, str]]]:
    """Strip trailing tokens that don't affect ordering (e.g., '.0', '-ga')."""
    out = list(items)
    while out:
        kind, val = out[-1]
        if kind == "sep":
            out.pop()
            continue
        if kind == "int" and val == 0:
            out.pop()
            continue
        if kind == "str" and _QUALIFIER_ORDER.get(val, None) == 0:
            # ga / final / release: trivial
            out.pop()
            continue
        break
    return out
