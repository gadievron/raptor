"""Demand-driven exploration during the audit review loop.

During review the LLM may need to chase hypotheses beyond the
pre-computed context.  This module provides:

1. Joern query dispatch — typed queries the LLM can invoke mid-review
   (callers, callees, taint_to_sinks, taint_from_sources, guards,
   data_deps).

2. Context expansion — fetch source + summary + evidence for a
   function the LLM wants to inspect, gated by an expansion budget.

3. Triage classifier — mechanical pre-review sort of every function
   into SKIP / GLANCE / INVESTIGATE / DEEP_DIVE buckets based on
   Joern reachability, binary oracle, call-graph position, complexity,
   and taint exposure.

The pre-sweep provides the map; the review loop is the exploration.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Joern query types ──────────────────────────────────────────────

class QueryType(str, Enum):
    CALLERS = "callers"
    CALLEES = "callees"
    TAINT_TO_SINKS = "taint_to_sinks"
    TAINT_FROM_SOURCES = "taint_from_sources"
    GUARDS = "guards"
    DATA_DEPS = "data_deps"


@dataclass
class JoernQuery:
    """A typed Joern query for mid-review hypothesis testing."""

    method_name: str
    query_type: QueryType
    file: str = ""
    extra_filter: str = ""

    def to_joern_script(self) -> str:
        method_sel = f'cpg.method.fullNameExact("{self.method_name}")'

        if self.query_type == QueryType.CALLERS:
            return f"{method_sel}.caller.fullName.l"
        if self.query_type == QueryType.CALLEES:
            return f"{method_sel}.callee.fullName.l"
        if self.query_type == QueryType.TAINT_TO_SINKS:
            return (
                f"implicit val ctx: EngineContext = EngineContext()\n"
                f"def src = {method_sel}.parameter\n"
                f"def sink = cpg.call.name(\"memcpy|strcpy|sprintf|exec|system|popen\").argument\n"
                f"sink.reachableByFlows(src).p"
            )
        if self.query_type == QueryType.TAINT_FROM_SOURCES:
            return (
                f"implicit val ctx: EngineContext = EngineContext()\n"
                f"def src = cpg.call.name(\"recv|read|fread|fgets|getenv\").argument\n"
                f"def sink = {method_sel}.parameter\n"
                f"sink.reachableByFlows(src).p"
            )
        if self.query_type == QueryType.GUARDS:
            return (
                f"{method_sel}.ast.isControlStructure"
                f'.controlStructureType("IF").condition.code.l'
            )
        if self.query_type == QueryType.DATA_DEPS:
            return f"{method_sel}.parameter.reachableBy(cpg.identifier).code.l"

        return f"{method_sel}.l"


# ── Context expansion ──────────────────────────────────────────────

@dataclass
class ExpansionBudget:
    """Tracks how many functions the LLM can expand during review."""

    max_expansions: int = 50
    _expanded: List[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def remaining(self) -> int:
        return max(0, self.max_expansions - len(self._expanded))

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def try_expand(self, function_key: str) -> bool:
        with self._lock:
            if function_key in self._expanded:
                return True
            if self.exhausted:
                return False
            self._expanded.append(function_key)
            return True

    def summary(self) -> str:
        return (
            f"Context expansion: {len(self._expanded)}/{self.max_expansions} "
            f"functions expanded ({self.remaining} remaining)"
        )


@dataclass
class ExpandedContext:
    """Context assembled for a demand-driven function inspection."""

    function: str
    file: str
    source: str = ""
    summary: Optional[Dict[str, Any]] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    taint_specs: List[Dict[str, Any]] = field(default_factory=list)

    def format_for_prompt(self) -> str:
        parts = [f"## Expanded context: {self.function} ({self.file})"]

        if self.source:
            parts.append(f"```\n{self.source}\n```")

        if self.summary:
            parts.append(f"Summary: {json.dumps(self.summary, indent=2)}")

        if self.evidence:
            parts.append(
                f"Evidence: {len(self.evidence)} items"
            )
            for ev in self.evidence[:5]:
                source = ev.get("source", "unknown")
                detail = ev.get("detail", "")
                parts.append(f"  - [{source}] {detail}")

        return "\n\n".join(parts)


# ── Triage classifier ─────────────────────────────────────────────

class TriageBucket(str, Enum):
    SKIP = "skip"
    GLANCE = "glance"
    INVESTIGATE = "investigate"
    DEEP_DIVE = "deep_dive"


_BUCKET_TOKEN_BUDGETS = {
    TriageBucket.SKIP: 0,
    TriageBucket.GLANCE: 500,
    TriageBucket.INVESTIGATE: 6000,
    TriageBucket.DEEP_DIVE: 22000,
}


@dataclass
class FunctionProfile:
    """Mechanical profile of a function for triage classification."""

    name: str
    file: str
    line_count: int = 0
    cyclomatic_complexity: int = 0
    is_entry_point: bool = False
    is_sink: bool = False
    is_trust_boundary: bool = False
    on_reachable_path: bool = False
    binary_present: bool = True
    has_taint_exposure: bool = False
    has_dangerous_callees: bool = False
    callee_count: int = 0
    caller_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "file": self.file,
            "line_count": self.line_count,
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "is_entry_point": self.is_entry_point,
            "is_sink": self.is_sink,
            "is_trust_boundary": self.is_trust_boundary,
            "on_reachable_path": self.on_reachable_path,
            "binary_present": self.binary_present,
            "has_taint_exposure": self.has_taint_exposure,
            "has_dangerous_callees": self.has_dangerous_callees,
        }


def classify_function(profile: FunctionProfile) -> TriageBucket:
    """Classify a function into a triage bucket.

    Mechanical classification based on call-graph position,
    complexity, and taint exposure.  No LLM calls.
    """
    if not profile.on_reachable_path and not profile.binary_present:
        return TriageBucket.SKIP

    if not profile.on_reachable_path and not profile.is_entry_point:
        return TriageBucket.SKIP

    if profile.is_entry_point or profile.is_sink or profile.is_trust_boundary:
        return TriageBucket.DEEP_DIVE

    if profile.has_taint_exposure and profile.cyclomatic_complexity > 10:
        return TriageBucket.DEEP_DIVE

    if profile.has_taint_exposure or profile.has_dangerous_callees:
        return TriageBucket.INVESTIGATE

    if profile.line_count < 20 and profile.cyclomatic_complexity <= 3:
        return TriageBucket.GLANCE

    return TriageBucket.INVESTIGATE


def get_token_budget(bucket: TriageBucket) -> int:
    return _BUCKET_TOKEN_BUDGETS[bucket]


@dataclass
class TriageResult:
    """Result of triaging all functions in the audit scope."""

    classifications: Dict[str, TriageBucket] = field(default_factory=dict)

    def add(self, function_key: str, bucket: TriageBucket) -> None:
        self.classifications[function_key] = bucket

    def bucket_counts(self) -> Dict[TriageBucket, int]:
        counts: Dict[TriageBucket, int] = {b: 0 for b in TriageBucket}
        for bucket in self.classifications.values():
            counts[bucket] += 1
        return counts

    def functions_in(self, bucket: TriageBucket) -> List[str]:
        return [
            k for k, v in self.classifications.items()
            if v == bucket
        ]

    def estimated_tokens(self) -> int:
        return sum(
            get_token_budget(b) for b in self.classifications.values()
        )

    def to_dict(self) -> Dict[str, Any]:
        counts = self.bucket_counts()
        return {
            "classifications": {
                k: v.value for k, v in self.classifications.items()
            },
            "summary": {
                b.value: counts[b] for b in TriageBucket
            },
            "estimated_tokens": self.estimated_tokens(),
        }


def triage_functions(
    profiles: List[FunctionProfile],
) -> TriageResult:
    result = TriageResult()
    for profile in profiles:
        key = f"{profile.file}:{profile.name}"
        bucket = classify_function(profile)
        result.add(key, bucket)
    return result


def save_triage(result: TriageResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2))


def format_triage_summary(result: TriageResult) -> str:
    counts = result.bucket_counts()
    total = sum(counts.values())
    if total == 0:
        return "Triage: no functions classified"

    parts = []
    for bucket in TriageBucket:
        count = counts[bucket]
        pct = count * 100.0 / total
        parts.append(f"{bucket.value}: {count} ({pct:.0f}%)")

    est_tokens = result.estimated_tokens()
    est_cost = est_tokens * 3e-6

    return (
        f"Triage: {total} functions — "
        + ", ".join(parts)
        + f" | est. {est_tokens:,} tokens (~${est_cost:.2f})"
    )
