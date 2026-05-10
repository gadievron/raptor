"""Test-fixture-circularity detection for security findings.

Implements the mechanical part of D-5 (test-harness circularity) per the
``/audit`` design — see ``stage-d-ruling.md`` and upstream
exploitation-validator#1 proposal 2 (CB-5 narrow case).

A finding is considered "test-harness-derived" when:
  1. its source file matches a test-fixture path pattern, AND
  2. the function the finding lives in is NOT reachable from any
     production entry point (i.e. only test code can drive it).

Both halves are needed: a finding in ``tests/conftest.py`` that's
ALSO callable from a production endpoint is a real bug (someone
left a debug surface in prod). A finding outside ``tests/`` that's
only reachable from test code is also a fixture-derived FP, but
the path-pattern check is the cheap pre-filter — most fixture
content lives in conventional paths.

The reachability gate is delegated to
:mod:`core.inventory.reachability`, which already has a
``exclude_test_files=True`` mode that excludes calls *from* test
files when answering "is this called?". A function with no
non-test callers gets ``NOT_CALLED``.

Verdict semantics:
  * ``true`` — fixture-path matches AND reachability says NOT_CALLED.
    The finding's preconditions originate in test code that can't
    drive production. Stage D's [D-5] rubric will rule this out
    with ``severity_demoted_to: INFORMATIONAL``.
  * ``false`` — fixture-path doesn't match, OR reachability says
    CALLED (a production caller exists). The finding is treated as
    real; D-5 doesn't fire.
  * ``candidate`` — fixture-path matches but reachability is
    UNCERTAIN (indirection-flag in a plausibly-calling file) OR
    the inventory lacks reachability data for this function. The
    LLM must verify before D-5 fires.

The verdict and supporting evidence are written to the finding so
downstream consumers (Stage D's LLM, /agentic's pre-flight skip,
the SARIF/report layer) all see the same signal.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Path-pattern match. Matches the conventions
# ``core.inventory.reachability._is_test_file`` already uses, plus a
# wider net (JS / Ruby / Go conventions) and explicit fixture
# directory names operators commonly use.
#
# Patterns are anchored to a path component boundary (``/`` or
# start-of-string) so substring "test" inside a real production
# path component (``test_runner.py`` is the binary, not a fixture
# — same example) doesn't false-match. Component-anchored matches
# are stricter than substring; this is the deliberate choice.
_FIXTURE_PATH_PATTERNS: Tuple[Tuple[str, str], ...] = (
    # Directory-anchored — the conventional containers.
    (r"(^|/)tests?/", "tests directory"),
    (r"(^|/)__tests__/", "JS __tests__ directory"),
    (r"(^|/)spec/", "spec directory (Ruby/JS/etc.)"),
    (r"(^|/)testdata/", "Go testdata directory"),
    (r"(^|/)fixtures?/", "fixtures directory"),
    # Filename-anchored — the conventional unit-test names.
    (r"(^|/)test_[^/]+\.py$", "Python test_*.py"),
    (r"(^|/)[^/]+_test\.py$", "Python *_test.py"),
    (r"(^|/)conftest\.py$", "pytest conftest.py"),
    (r"(^|/)[^/]+_test\.go$", "Go *_test.go"),
    (r"(^|/)[^/]+\.test\.[jt]sx?$", "JS/TS *.test.{js,ts,jsx,tsx}"),
    (r"(^|/)[^/]+\.spec\.[jt]sx?$", "JS/TS *.spec.{js,ts,jsx,tsx}"),
    (r"(^|/)Test[A-Z][^/]*\.java$", "Java Test*.java"),
    (r"(^|/)[^/]+Test\.java$", "Java *Test.java"),
)

_FIXTURE_PATH_RE = re.compile(
    "|".join(p for p, _ in _FIXTURE_PATH_PATTERNS),
)

_PATTERN_LABELS: Dict[str, str] = {
    p: label for p, label in _FIXTURE_PATH_PATTERNS
}


@dataclass(frozen=True)
class HarnessEvidence:
    """One piece of evidence supporting a fixture-detection verdict.

    ``type`` is one of:
      * ``fixture_path_match`` — path-pattern hit. ``path`` is the
        finding's file; ``pattern`` is the matched-pattern label
        (human-readable, not the regex itself).
      * ``reachability_check`` — outcome of the reachability gate.
        ``result`` is one of ``not_reachable_from_prod``,
        ``reachable_from_prod``, ``data_missing``,
        ``data_uncertain``. ``checked_against`` lists evidence
        sites returned by ``function_called``.
    """
    type: str
    path: str = ""
    pattern: str = ""
    result: str = ""
    checked_against: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type}
        if self.path:
            d["path"] = self.path
        if self.pattern:
            d["pattern"] = self.pattern
        if self.result:
            d["result"] = self.result
        if self.checked_against:
            d["checked_against"] = list(self.checked_against)
        return d


@dataclass(frozen=True)
class FixtureVerdict:
    """Mechanical detection result for a single finding.

    Consumers translate ``likely_test_harness`` to action:
      * ``true``  — auto-eligible for D-5 demotion (LLM verifies in
                    /validate; /agentic may skip the LLM analysis
                    entirely with a deterministic synthetic result)
      * ``false`` — D-5 does not apply; finding flows through
                    normally
      * ``candidate`` — LLM must verify before D-5 fires; never
                       auto-demote
    """
    likely_test_harness: str  # "true" | "false" | "candidate"
    evidence: Tuple[HarnessEvidence, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "likely_test_harness": self.likely_test_harness,
            "harness_evidence": [e.to_dict() for e in self.evidence],
        }


def is_fixture_path(file_path: str) -> Tuple[bool, str]:
    """Return ``(matched, label)`` for a path-pattern check.

    ``label`` is the human-readable pattern name (e.g. "pytest
    conftest.py"); empty when no match. Path is normalised to
    forward slashes before matching so Windows separators don't
    break the regex.
    """
    if not file_path:
        return (False, "")
    # Normalise BOTH separators — paths from a Windows operator
    # arrive with ``\``; same path matched against this code on a
    # Linux host needs explicit conversion (``os.sep`` alone is
    # the host separator, not the path's separator).
    normalised = file_path.replace("\\", "/")
    for pattern, label in _FIXTURE_PATH_PATTERNS:
        if re.search(pattern, normalised):
            return (True, label)
    return (False, "")


def detect_fixture(
    *,
    file_path: str,
    function: str,
    inventory: Optional[Dict[str, Any]] = None,
    qualified_name: Optional[str] = None,
) -> FixtureVerdict:
    """Mechanical fixture detection for a single finding.

    Args:
        file_path: repo-relative source file the finding is in.
        function: name of the enclosing function (used to construct
            the qualified name when ``qualified_name`` is None).
        inventory: project inventory dict, as returned by
            :func:`core.inventory.build_inventory`. When None, the
            reachability gate is skipped — verdict is at most
            ``candidate`` (path matched, reachability unknown).
        qualified_name: dotted name to query against reachability
            (e.g. ``"src.module.func"``). When None, fall back to
            ``"<file-stem>.<function>"`` — coarse but sufficient
            for the common case where the inventory's call-graph
            entries match.

    Returns:
        :class:`FixtureVerdict` with verdict + evidence list.
    """
    evidence: List[HarnessEvidence] = []

    matched, label = is_fixture_path(file_path)
    if not matched:
        # No fixture-path hit → finding is in production-shaped
        # code. D-5 doesn't apply regardless of reachability.
        return FixtureVerdict(likely_test_harness="false")

    evidence.append(HarnessEvidence(
        type="fixture_path_match",
        path=file_path,
        pattern=label,
    ))

    # Treat both ``None`` and empty/missing-files inventories the
    # same — no data to gate on. The resolver itself happily
    # returns NOT_CALLED for an empty inventory (no callers
    # found), which would falsely flag every fixture-path finding
    # as ``true`` and auto-demote it. Fall to ``candidate``
    # whenever the inventory can't actually inform the gate.
    if (
        inventory is None
        or not isinstance(inventory, dict)
        or not inventory.get("files")
    ):
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="data_missing",
        ))
        return FixtureVerdict(
            likely_test_harness="candidate",
            evidence=tuple(evidence),
        )

    qname = qualified_name or _default_qualified_name(file_path, function)
    if not qname or "." not in qname:
        # Reachability resolver requires a dotted name. Fall back
        # to candidate — path matched but we can't run the gate.
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="data_missing",
        ))
        return FixtureVerdict(
            likely_test_harness="candidate",
            evidence=tuple(evidence),
        )

    try:
        from core.inventory.reachability import (
            Verdict,
            function_called,
        )
    except Exception:
        # Reachability substrate unavailable — fall through to
        # candidate. Don't ever crash the consumer on import.
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="data_missing",
        ))
        return FixtureVerdict(
            likely_test_harness="candidate",
            evidence=tuple(evidence),
        )

    try:
        result = function_called(
            inventory, qname, exclude_test_files=True,
        )
    except Exception:
        # Bad inventory / qualified-name — don't crash, fall to
        # candidate so the LLM can verify. Broad catch is
        # deliberate: this helper is called from /agentic and
        # /validate hot paths and must never propagate.
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="data_missing",
        ))
        return FixtureVerdict(
            likely_test_harness="candidate",
            evidence=tuple(evidence),
        )

    if result.verdict == Verdict.CALLED:
        # Reachable from prod — fixture path doesn't matter; the
        # finding's call chain reaches non-test code. D-5 NOT
        # eligible.
        sites = tuple(
            f"{path}:{line}" for path, line in result.evidence
        )
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="reachable_from_prod",
            checked_against=sites[:5],  # cap evidence list size
        ))
        return FixtureVerdict(
            likely_test_harness="false",
            evidence=tuple(evidence),
        )

    if result.verdict == Verdict.NOT_CALLED:
        # No production caller. Confirmed test-harness-only.
        evidence.append(HarnessEvidence(
            type="reachability_check",
            result="not_reachable_from_prod",
        ))
        return FixtureVerdict(
            likely_test_harness="true",
            evidence=tuple(evidence),
        )

    # UNCERTAIN — indirection flags in plausibly-calling files.
    # LLM must verify; never auto-demote on uncertainty.
    indirection_sites = tuple(
        f"{path} ({flag})"
        for path, flag in result.uncertain_reasons[:5]
    )
    evidence.append(HarnessEvidence(
        type="reachability_check",
        result="data_uncertain",
        checked_against=indirection_sites,
    ))
    return FixtureVerdict(
        likely_test_harness="candidate",
        evidence=tuple(evidence),
    )


def _default_qualified_name(file_path: str, function: str) -> str:
    """Construct a fallback dotted name when consumers don't supply
    one. ``src/foo/bar.py + run`` → ``src.foo.bar.run``. Crude —
    consumers that have a richer module-path representation should
    pass ``qualified_name`` directly."""
    if not file_path or not function:
        return ""
    norm = file_path.replace(os.sep, "/")
    # Strip extension; common Python / JS / Go cases. Other
    # languages fall back to bare function name (rejected as
    # too-coarse by the resolver).
    for ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb"):
        if norm.endswith(ext):
            norm = norm[: -len(ext)]
            break
    parts = [p for p in norm.split("/") if p]
    parts.append(function)
    return ".".join(parts)
