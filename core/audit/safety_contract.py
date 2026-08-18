"""Shared safety contract for mechanical analysis tools.

All mechanical tools that feed into the /audit review pipeline must
return evidence through this contract.  The contract enforces a single
invariant:

    **No mechanical result may reduce coverage.**

That is: a mechanical tool cannot suppress, skip, or demote a function
from LLM review.  It can only BOOST (add findings, raise priority,
narrow scope to steer the LLM) or INFORM (inject evidence for the LLM
to evaluate).

Suppression — dropping a function from the review queue entirely — is
the exclusive domain of the SUPPRESS_SOURCES allowlist.  Any new tool
that wants to suppress must:

  1. Be added to SUPPRESS_SOURCES with a rationale.
  2. Be gated by a labelled corpus showing zero false-suppress.
  3. Flow through ``record_suppression`` in ``reach_chokepoint.py``.

Pre-existing suppression paths (prefilter, triage) are included in the
allowlist for completeness.  They already record through
``record_suppression`` and predate this contract.

Tools NOT on the allowlist produce ``BoostEvidence`` only.  Attempting
to construct ``SuppressEvidence`` from a non-allowlisted source raises
``ContractViolation``.

Why this matters
~~~~~~~~~~~~~~~~

Mechanical output carries implicit trust.  "No bypasses found" by the
bypass detector does NOT mean "function is safe" — it means the
detector's assumption model didn't cover a violation.  If that
non-finding quietly suppressed review, the coverage invariant breaks
and real bugs go unreviewed.

The same danger applies to CWE narrowing: telling the LLM "this
function has no SQL injection sinks" IS suppression at finer
granularity.  If the sink catalog is incomplete, a real SQL injection
goes unreviewed.  CWE narrowing is therefore scope-narrowing (steers
the LLM's focus) not scope-exclusion (drops the CWE from review).

Blind spots per tool
~~~~~~~~~~~~~~~~~~~~

Each tool has known blind spots that adversarial tests must cover:

**Compositional bypass loop:**
- "No bypasses detected" must not demote or suppress any finding.
- Wrong assumptions produce noise (extra findings), not silence.
- The LLM that synthesises assumptions may hallucinate enforcers.

**Taint approximation (Tier 1):**
- Stored XSS via database: source → DB.write; DB.read → sink.  The
  intraprocedural analyser sees no direct source→sink flow and would
  falsely report "no taint."
- Function-as-sink: ``write(user_data)`` — the function IS the sink,
  not something it calls.  Absence of callees ≠ absence of sinks.
- Incomplete sink catalog: any sink not in the catalog is invisible.
- "No sink calls" must not exclude sink-dependent CWEs; it narrows
  scope only.

**Constant resolution:**
- Conditional ``#define``: ``#ifdef DEBUG`` changes the value.  A
  constant resolved under one config is wrong under another.
- System header redefinition: ``<limits.h>`` values differ across
  platforms.  ``PATH_MAX`` is 1024 on macOS, 4096 on Linux.
- Macro composition: ``MAX(A, B)`` — resolving ``A`` and ``B``
  individually doesn't prove ``MAX(A, B)`` has a unique value.
- Only provably-unique constants (single definition, no conditional
  compilation, no platform variance) may feed SMT.
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ContractViolation(Exception):
    """A mechanical tool attempted an action its contract forbids."""


class EvidenceDirection(str, enum.Enum):
    BOOST = "boost"
    SUPPRESS = "suppress"


class ToolSource(str, enum.Enum):
    BYPASS_LOOP = "bypass_loop"
    TAINT_APPROX = "taint_approx"
    CONSTANT_RESOLUTION = "constant_resolution"
    SINK_PREFILTER = "sink_prefilter"
    FIELD_DISCOVERY = "field_discovery"
    GUARD_EQUIVALENCE = "guard_equivalence"
    COCCINELLE = "coccinelle"
    BINARY_ORACLE = "binary_oracle"
    SMT_INFEASIBILITY = "smt_infeasibility"
    REACHABILITY_GATE = "reachability_gate"
    SANITIZER_CUT = "sanitizer_cut"
    PREFILTER = "prefilter"
    TRIAGE = "triage"
    CONDITION_CPG = "condition_cpg"
    CONDITION_SMT = "condition_smt"
    TYPE_CONFUSION = "type_confusion"
    CONTRACT_PAIR = "contract_pair"


_TOOL_MAY_SUPPRESS: frozenset[str] = frozenset({
    ToolSource.BINARY_ORACLE.value,
    ToolSource.SMT_INFEASIBILITY.value,
    ToolSource.REACHABILITY_GATE.value,
    ToolSource.SANITIZER_CUT.value,
    ToolSource.PREFILTER.value,
    ToolSource.TRIAGE.value,
})

SUPPRESS_SOURCES: frozenset[str] = _TOOL_MAY_SUPPRESS


@dataclass(frozen=True)
class BoostEvidence:
    """Evidence that increases priority or adds findings.

    Any mechanical tool may return BoostEvidence.  It is injected into
    the LLM review context or spawns new findings — it never removes
    anything from the review queue.

    ``action`` describes what the consumer should do:

    - ``"add_finding"`` — create a new finding (bypass detected, etc.)
    - ``"raise_priority"`` — boost the function's review priority
    - ``"narrow_scope"`` — steer the LLM toward specific CWEs (but
      DO NOT exclude other CWEs from review)
    - ``"inject_context"`` — add evidence text to the LLM prompt
    - ``"annotate"`` — attach metadata to the function record
    """

    source: str
    action: str
    target_file: str = ""
    target_function: str = ""
    description: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        valid_actions = {
            "add_finding", "raise_priority", "narrow_scope",
            "inject_context", "annotate",
        }
        if self.action not in valid_actions:
            raise ContractViolation(
                f"BoostEvidence action must be one of {valid_actions}, "
                f"got {self.action!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "direction": EvidenceDirection.BOOST.value,
            "source": self.source,
            "action": self.action,
            "description": self.description,
        }
        if self.target_file:
            d["target_file"] = self.target_file
        if self.target_function:
            d["target_function"] = self.target_function
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass(frozen=True)
class SuppressEvidence:
    """Evidence that authorises dropping a function from review.

    Construction is gated by the SUPPRESS_SOURCES allowlist — only
    tools whose source string appears in the allowlist can create
    SuppressEvidence.  All others raise ContractViolation.

    The consumer MUST flow this through ``record_suppression`` in
    ``reach_chokepoint.py`` so the audit trail is preserved.
    """

    source: str
    verdict: str
    reason: str
    target_file: str = ""
    target_function: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source not in _TOOL_MAY_SUPPRESS:
            raise ContractViolation(
                f"SuppressEvidence source {self.source!r} is not in the "
                f"SUPPRESS_SOURCES allowlist: {sorted(_TOOL_MAY_SUPPRESS)}. "
                f"Mechanical tools that are not on the allowlist must "
                f"return BoostEvidence only."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": EvidenceDirection.SUPPRESS.value,
            "source": self.source,
            "verdict": self.verdict,
            "reason": self.reason,
            "target_file": self.target_file,
            "target_function": self.target_function,
            "detail": self.detail,
        }


def assert_boost_only(source: str) -> None:
    """Call at the top of any tool that must never suppress.

    Raises ContractViolation if ``source`` appears in the suppress
    allowlist (which would be a design error — a tool should not be
    both on the allowlist and calling assert_boost_only).
    """
    if source in _TOOL_MAY_SUPPRESS:
        raise ContractViolation(
            f"assert_boost_only called for {source!r}, but it IS in "
            f"the suppress allowlist. Remove the assert or the "
            f"allowlist entry."
        )


def record_boost(
    out_dir: Path,
    evidence: BoostEvidence,
) -> None:
    """Append a boost-evidence record to the audit trail.

    Writes to ``out_dir/boost-evidence.jsonl`` — the boost counterpart
    of ``suppressions.jsonl``.  Operators can audit what mechanical
    tools contributed to findings and priority decisions.
    """
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "boost-evidence.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(evidence.to_dict()) + "\n")
    except OSError as e:
        logger.debug("safety_contract: failed to write boost record: %s", e)


__all__ = [
    "ContractViolation",
    "EvidenceDirection",
    "SUPPRESS_SOURCES",
    "ToolSource",
    "BoostEvidence",
    "SuppressEvidence",
    "assert_boost_only",
    "record_boost",
]
