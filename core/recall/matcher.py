"""Tolerance matcher: expected findings vs produced findings.

A produced finding (the normalized dict shape from
``core.sarif.parser.parse_sarif_findings``: ``file``, ``startLine``,
``endLine``, ``cwe_id``, ``tool``, ``rule_id``) matches an expected
finding when:

* the file paths agree after normalisation — the expected path is
  repo-relative, the produced path may be absolute or carry a
  different prefix, so agreement is posix suffix-match on the
  repo-relative form;
* the line falls inside ``[line_start - drift, line_end + drift]``,
  or the expected entry is file-level (``line_start is None``);
* the CWE matches exactly, or (when ``cwe_family_match``) is a
  sibling per :mod:`packages.checker_synthesis.cwe_families` — the
  producers legitimately disagree about e.g. CWE-77 vs CWE-78.

Findings without a CWE never satisfy an expected entry: crediting a
CWE-less hit would let a noisy producer fake recall by blanketing
files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, TYPE_CHECKING

from packages.checker_synthesis.cwe_families import cwe_siblings


if TYPE_CHECKING:
    from core.recall.manifest import ExpectedFinding, Tolerance


@dataclass
class MatchResult:
    """Outcome for one expected finding."""

    expected: ExpectedFinding
    matched: bool
    #: producers that hit it (deduped, sorted): e.g. ["codeql", "semgrep"]
    tools: list[str] = field(default_factory=list)
    #: the concrete findings that matched (normalized dicts)
    hits: list[dict[str, Any]] = field(default_factory=list)


def _norm_rel(path: str) -> str:
    """Posix-normalise and strip leading ./ for suffix comparison."""
    p = PurePosixPath(str(path).replace("\\", "/"))
    parts = [x for x in p.parts if x not in (".",)]
    return "/".join(parts)


def path_matches(expected_file: str, produced_file: str | None) -> bool:
    """True when the produced path plausibly names the expected file.

    Suffix match in either direction on normalised posix parts —
    the produced URI may be absolute (``/work/repo/src/a.java``) or
    shallower than the manifest's repo-relative path.
    """
    if not produced_file:
        return False
    exp = _norm_rel(expected_file)
    got = _norm_rel(produced_file)
    if not exp or not got:
        return False
    return got.endswith(exp) or exp.endswith(got)


def _line_matches(expected: ExpectedFinding, produced: dict[str, Any],
                  drift: int) -> bool:
    if expected.line_start is None:
        return True  # file-level ground truth
    start = produced.get("startLine")
    if not isinstance(start, int):
        return False
    end = produced.get("endLine")
    end = end if isinstance(end, int) else start
    lo = expected.line_start - drift
    hi = (expected.line_end or expected.line_start) + drift
    # ranges overlap
    return start <= hi and end >= lo


def _cwe_matches(expected_cwe: str, produced_cwe: Any,
                 family: bool) -> bool:
    if not produced_cwe:
        return False
    got = str(produced_cwe)
    if not got.upper().startswith("CWE-"):
        got = f"CWE-{got}"
    got = got.upper()
    if got == expected_cwe:
        return True
    return family and got in cwe_siblings(expected_cwe)


def finding_matches(expected: ExpectedFinding, produced: dict[str, Any],
                    tolerance: Tolerance) -> bool:
    """Full tolerance check for one (expected, produced) pair."""
    return (
        path_matches(expected.file, produced.get("file"))
        and _line_matches(expected, produced, tolerance.line_drift)
        and _cwe_matches(expected.cwe, produced.get("cwe_id"),
                         tolerance.cwe_family_match)
    )


def _basename(path: str | None) -> str:
    """Final normalised path component ("" for empty paths)."""
    if not path:
        return ""
    norm = _norm_rel(path)
    return norm.rsplit("/", 1)[-1] if norm else ""


def match_findings(
    expected: list[ExpectedFinding],
    produced: list[dict[str, Any]],
    tolerance: Tolerance,
) -> list[MatchResult]:
    """Match every expected finding against the produced set.

    One produced finding may satisfy several expected entries (a
    file-level benchmark case and a line-level CVE label can name the
    same code); that is correct for recall — each expected entry is
    an independent question.

    Produced findings are indexed by path basename before the full
    tolerance check: suffix agreement in either direction requires the
    final path components to be equal, so the index prunes candidates
    without changing which pairs can match (benchmark corpora put each
    case in its own file, collapsing the former
    len(expected) * len(produced) scan — which did not finish on
    3k-expected x 136k-produced inputs — to near-linear bucket walks).
    """
    by_basename: dict[str, list[dict[str, Any]]] = {}
    for p in produced:
        by_basename.setdefault(_basename(p.get("file")), []).append(p)

    results: list[MatchResult] = []
    for exp in expected:
        candidates = by_basename.get(_basename(exp.file), [])
        hits = [p for p in candidates if finding_matches(exp, p, tolerance)]
        tools = sorted({str(p.get("tool")) for p in hits if p.get("tool")})
        results.append(MatchResult(expected=exp, matched=bool(hits),
                                   tools=tools, hits=hits))
    return results


def clean_region_hits(
    clean: list[ExpectedFinding],
    produced: list[dict[str, Any]],
    tolerance: Tolerance,
) -> list[MatchResult]:
    """Findings landing in labelled-clean regions (secondary FP count).

    Same matcher, opposite meaning: a hit here is a false positive on
    ground-truth-clean code, reported alongside recall but never mixed
    into it.
    """
    return [r for r in match_findings(clean, produced, tolerance)
            if r.matched]
