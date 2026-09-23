"""Mechanical witnesses for commonly-dismissed auth hypotheses (Java).

Reviews on auth-critical Java code reliably FORM the right hypothesis
and then dismiss it without tool adjudication. Two recurring shapes
had no mechanical witness; this module supplies both, detection-grade
(@role detection — they seed/corroborate, never promote):

1. **Synchronized-section escape** (``sync_escape``): a record
   obtained from a keyed collection INSIDE a ``synchronized`` block is
   mutated AFTER the block — the keyed lookup was atomic but the
   mutation races other threads' lookups of the same key (lost
   updates in an auth-failure ledger weaken lockout protection).

2. **Nullable getter into digest material** (``null_concat``): a
   same-file-declared String-returning getter that can return null
   (abstract, or a body with a ``return null`` path) is concatenated
   directly into a string that then feeds a digest/hash computation.
   Java concatenation turns null into the LITERAL ``"null"``, so an
   unknown principal yields a valid-looking digest of
   ``user:realm:null`` instead of a failure.

Both are structural, single-file checks over Java stdlib spellings
(``synchronized``, string ``+``), not learned project vocabulary.
Safety contract: boost-only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_SYNC_RE = re.compile(r"^\s*synchronized\s*[({]")
# record binding from a keyed collection inside the block
# \b-pinned to a word start: unanchored, a bare `\w+` re-scans a
# hostile identifier run from every offset (quadratic); dropped
# matches are mid-word suffix false tokens only.
_KEYED_GET_RE = re.compile(
    r"\b(?P<var>\w+)\s*=\s*[\w.]+\.get\(",
)
# post-block mutation: a method call on the record that is not an
# obvious read accessor.
_READ_PREFIXES = ("get", "is", "has", "size", "toString", "equals",
                  "hashCode")

# nullable String getter declarations
# The modifier/type token list is count-bounded: unbounded, hostile
# text repeating "abstract " inside one token run makes every
# occurrence re-scan the run — quadratic. Real declarations carry a
# handful of tokens before String.
_ABSTRACT_GETTER_RE = re.compile(
    r"abstract\s+(?:[\w<>\[\]]+\s+){0,8}String\s+(?P<name>\w+)\s*\(",
)
# When no access keyword is present the leading whitespace run is
# pinned to its start ((?<!\s) branch): unanchored, a bare `\s*`
# prefix re-consumes a hostile whitespace run from every position —
# quadratic. The earliest match always starts at the run start, so
# the match set is unchanged. The parameter window is bounded (a
# real parameter list sits far under 1024 chars).
_GETTER_DECL_RE = re.compile(
    r"(?:(?:public|protected|private)|(?<!\s))\s*(?:static\s+)?String\s+"
    r"(?P<name>\w+)\s*\([^)]{0,1024}\)\s*\{",
)
# The name prefix is bounded: unbounded `\w*` before the keyword
# costs every split of a hostile word run per word start. Real
# function names sit far under 256 chars.
_DIGESTY_CALL_RE = re.compile(
    r"\b\w{0,256}(?:digest|Digest|hash|Hash|hmac|Hmac)\w*\s*\(",
)


@dataclass
class AuthWitness:
    """One witness hit."""

    file: str
    function: str
    detector: str
    line: int
    description: str


def _brace_span(lines: list[str], start: int) -> int:
    """Index (0-based) of the line closing the block opened at *start*."""
    depth = 0
    opened = False
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if lines[i].count("{"):
            opened = True
        if opened and depth <= 0:
            return i
    return len(lines) - 1


def scan_sync_escape(
    file_path: str, function: str, source: str,
) -> list[AuthWitness]:
    """Synchronized-section escape within one Java function body."""
    lines = source.split("\n")
    findings: list[AuthWitness] = []
    for i, line in enumerate(lines):
        if not _SYNC_RE.match(line):
            continue
        end = _brace_span(lines, i)
        bound: dict[str, int] = {}
        for j in range(i, end + 1):
            mg = _KEYED_GET_RE.search(lines[j])
            if mg:
                bound[mg.group("var")] = j + 1
        if not bound:
            continue
        for j in range(end + 1, len(lines)):
            for var, bind_line in bound.items():
                m = re.search(
                    r"\b" + re.escape(var) + r"\.(?P<meth>\w+)\(",
                    lines[j],
                )
                if m and not m.group("meth").startswith(_READ_PREFIXES):
                    findings.append(AuthWitness(
                        file=file_path, function=function,
                        detector="sync_escape", line=j + 1,
                        description=(
                            f"synchronized-section escape: '{var}' was "
                            f"looked up from a keyed collection inside "
                            f"the synchronized block (line {bind_line}) "
                            f"but '{var}.{m.group('meth')}()' mutates it "
                            f"AFTER the block — concurrent callers for "
                            f"the same key race the mutation (lost "
                            f"update)"
                        ),
                    ))
                    break
            else:
                continue
            break
    return findings


def _nullable_getters(file_source: str) -> set[str]:
    """Names of same-file String getters that can return null."""
    out: set[str] = set()
    for m in _ABSTRACT_GETTER_RE.finditer(file_source):
        out.add(m.group("name"))
    for m in _GETTER_DECL_RE.finditer(file_source):
        # crude body scan: from the decl to the next top-level-ish
        # closing brace, look for a bare `return null`
        tail = file_source[m.end():m.end() + 4000]
        if re.search(r"\breturn\s+null\s*;", tail.split("\n    }")[0]):
            out.add(m.group("name"))
    return out


def scan_null_concat(
    file_path: str, function: str, source: str,
    nullable_getters: set[str],
) -> list[AuthWitness]:
    """Nullable getter concatenated into digest material."""
    if not nullable_getters:
        return []
    lines = source.split("\n")
    findings: list[AuthWitness] = []
    concat_vars: dict[str, tuple[int, str]] = {}
    for i, line in enumerate(lines):
        for g in nullable_getters:
            # The whitespace after '=' is subsumed by the filler
            # class ([^=\n] includes horizontal whitespace, and the
            # line loop never feeds a newline), so the naive
            # ``=\s*[^=\n]*`` overlapped two unbounded spans —
            # quadratic on an assignment line ending in a long
            # whitespace run with no concatenation.
            # The variable is \b-pinned and the pre-concat window
            # bounded: unbounded, both re-scan a hostile run from
            # every position — quadratic. A real assignment RHS up
            # to the concatenation sits far under 300 chars.
            m = re.search(
                r"(?:\b(?P<var>\w+)\s*=)?[^=\n]{0,300}\+\s*" + re.escape(g)
                + r"\s*\(",
                line,
            )
            if m is None:
                continue
            if re.search(re.escape(g) + r"\s*\([^)]{0,256}\)\s*[!=]=\s*null", source) or \
               re.search(r"null\s*[!=]=\s*" + re.escape(g), source):
                continue  # result is null-checked somewhere in the body
            var = m.group("var")
            if var:
                concat_vars[var] = (i + 1, g)
            elif _DIGESTY_CALL_RE.search(line):
                findings.append(AuthWitness(
                    file=file_path, function=function,
                    detector="null_concat", line=i + 1,
                    description=(
                        f"null-becomes-literal lead: '{g}(...)' can "
                        f"return null (same-file declaration) and is "
                        f"concatenated straight into digest material — "
                        f"an unknown principal yields a valid-looking "
                        f"digest of the literal string 'null'"
                    ),
                ))
    for var, (line_no, g) in concat_vars.items():
        for j, line in enumerate(lines):
            if j + 1 <= line_no:
                continue
            if re.search(r"\b" + re.escape(var) + r"\b", line) and (
                _DIGESTY_CALL_RE.search(line)
                or ".getBytes(" in line
            ):
                findings.append(AuthWitness(
                    file=file_path, function=function,
                    detector="null_concat", line=line_no,
                    description=(
                        f"null-becomes-literal lead: '{g}(...)' can "
                        f"return null (same-file declaration), is "
                        f"concatenated into '{var}' (line {line_no}), "
                        f"and '{var}' feeds a digest computation (line "
                        f"{j + 1}) — an unknown principal yields a "
                        f"valid-looking digest of the literal 'null'"
                    ),
                ))
                break
    return findings


def scan_gaps(
    gaps: list[dict],
    source_texts: dict[str, str],
) -> list[AuthWitness]:
    """Scan Java checklist gaps (mechanical-detector phase input)."""
    findings: list[AuthWitness] = []
    nullable_cache: dict[str, set[str]] = {}
    for gap in gaps:
        fp = gap.get("file", "")
        if not fp.endswith(".java"):
            continue
        text = source_texts.get(fp)
        if text is None:
            continue
        ls = gap.get("line_start", 0)
        le = gap.get("line_end") or ls
        if not ls:
            continue
        body = "\n".join(text.split("\n")[ls - 1:le])
        fn = gap.get("name", "")
        if fp not in nullable_cache:
            nullable_cache[fp] = _nullable_getters(text)
        try:
            for f in scan_sync_escape(fp, fn, body) + scan_null_concat(
                fp, fn, body, nullable_cache[fp],
            ):
                f.line += ls - 1
                findings.append(f)
        except Exception:  # noqa: BLE001 — one gap must not sink the phase
            logger.debug(
                "auth witness scan failed for %s:%s", fp, fn, exc_info=True,
            )
    return findings
