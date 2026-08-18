"""Mid-audit concept discovery — mine review outcomes for invariants.

After the main review pass, clusters findings by CWE, extracts invariant
candidates from recurring patterns, and returns them for compilation.
The caller (orchestrator) compiles, runs prescreening, and queues any
new hits for a follow-up pass.

No LLM calls — invariants are derived mechanically from structured
review output (CWE, hypothesis mechanism, evidence tool).
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


_CWE_TEMPLATES: dict[str, tuple[str, str]] = {
    "CWE-476": (
        "Return values of fallible functions must be checked for "
        "NULL/error before use",
        "A call to a fallible function where the return value is "
        "used without a NULL/error check",
    ),
    "CWE-252": (
        "Return values of security-critical functions must be checked",
        "A call to a security-critical function whose return value "
        "is silently discarded",
    ),
    "CWE-415": (
        "Freed resources must not be freed again without intervening "
        "reallocation",
        "A resource is freed twice without an intervening allocation "
        "or nullification of the pointer",
    ),
    "CWE-416": (
        "Freed resources must not be accessed after deallocation",
        "A pointer is dereferenced or passed to a function after the "
        "underlying resource has been freed",
    ),
    "CWE-134": (
        "Format string arguments must be compile-time literals, not "
        "user-controlled variables",
        "A format string function receives a variable as its format "
        "argument instead of a string literal",
    ),
    "CWE-190": (
        "Arithmetic operations on external inputs must be bounds-checked "
        "before use in allocation or indexing",
        "An arithmetic operation on an external input is used in a size "
        "computation or array index without prior bounds validation",
    ),
    "CWE-362": (
        "Shared mutable state must be protected by synchronisation "
        "primitives",
        "A shared variable is read or written without holding the "
        "appropriate lock or using atomic operations",
    ),
    "CWE-120": (
        "Buffer write operations must validate that the source length "
        "fits the destination capacity",
        "A buffer write copies data without checking that the source "
        "length does not exceed the destination size",
    ),
    "CWE-122": (
        "Heap buffer allocations must account for the actual data size",
        "A heap allocation size is smaller than the data subsequently "
        "written into it",
    ),
    "CWE-787": (
        "Array and buffer accesses must be within allocated bounds",
        "An array or buffer access uses an index or offset that can "
        "exceed the allocated size",
    ),
    "CWE-401": (
        "Allocated resources must be freed on all exit paths",
        "A function allocates a resource but does not free it on one "
        "or more error/return paths",
    ),
}

_FUNC_NAME_RE = re.compile(r"\b([a-z_][a-z0-9_]{2,})\b")
_NOISE_WORDS = frozenset({
    "the", "and", "for", "not", "but", "with", "this", "that", "from",
    "are", "was", "can", "may", "has", "its", "via", "into", "when",
    "after", "before", "without", "between", "should", "could", "would",
    "missing", "check", "null", "error", "return", "value", "pointer",
    "function", "call", "use", "used", "using", "buffer", "size",
    "length", "data", "memory", "allocation", "free", "freed",
    "variable", "argument", "input", "output", "result",
})


def _extract_api_names(hypothesis: str) -> list[str]:
    """Extract plausible function/API names from hypothesis text."""
    tokens = _FUNC_NAME_RE.findall(hypothesis.lower())
    return [t for t in tokens if t not in _NOISE_WORDS and len(t) > 2]


def _normalise_cwe(raw: str) -> str:
    m = re.match(r"(CWE-\d+)", raw.upper().replace(" ", ""))
    return m.group(1) if m else ""


@dataclass
class InvariantCandidate:
    """A discovered invariant before deduplication."""
    cwe: str
    statement: str
    negation: str
    description: str
    evidence: list[str]
    api_names: list[str]


def discover_invariants(
    outcomes: dict[str, Any],
    existing_model: dict[str, Any] | None = None,
    *,
    min_cluster_size: int = 2,
    max_invariants: int = 5,
) -> list[InvariantCandidate]:
    """Scan review outcomes for recurring patterns and extract invariants.

    Groups non-clean outcomes by CWE. Clusters with *min_cluster_size*+
    members become invariant candidates. Deduplicates against the existing
    domain model.

    Returns at most *max_invariants* candidates, ordered by cluster size
    (most frequent first).
    """
    cwe_clusters: dict[str, list[dict[str, Any]]] = {}

    for key, outcome in outcomes.items():
        status = _get_status(outcome)
        if status not in ("finding", "suspicious"):
            continue

        cwe = _get_cwe(outcome)
        if not cwe:
            continue

        hypothesis = _get_hypothesis(outcome)
        file = _get_field(outcome, "file", "")
        function = _get_field(outcome, "function", "")

        cwe_clusters.setdefault(cwe, []).append({
            "key": key,
            "file": file,
            "function": function,
            "hypothesis": hypothesis,
            "cwe": cwe,
        })

    existing_cwes = set()
    if existing_model:
        for inv in existing_model.get("invariants", []):
            if not isinstance(inv, dict):
                continue
            for c in inv.get("relevant_cwes", []):
                existing_cwes.add(_normalise_cwe(c))

    candidates: list[tuple[int, InvariantCandidate]] = []

    for cwe, entries in cwe_clusters.items():
        if len(entries) < min_cluster_size:
            continue

        if cwe in existing_cwes:
            continue

        template = _CWE_TEMPLATES.get(cwe)
        if not template:
            continue

        statement, negation = template
        evidence = [f"{e['file']}:{e['function']}" for e in entries]

        all_apis: list[str] = []
        for e in entries:
            all_apis.extend(_extract_api_names(e["hypothesis"]))
        api_counts = Counter(all_apis)
        top_apis = [name for name, _ in api_counts.most_common(5) if api_counts[name] > 1]

        desc_parts = [f"Observed in {len(entries)} functions"]
        if top_apis:
            desc_parts.append(f"APIs: {', '.join(top_apis)}")

        candidates.append((
            len(entries),
            InvariantCandidate(
                cwe=cwe,
                statement=statement,
                negation=negation,
                description=". ".join(desc_parts),
                evidence=evidence,
                api_names=top_apis,
            ),
        ))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in candidates[:max_invariants]]


def candidates_to_model_entries(
    candidates: list[InvariantCandidate],
) -> list[dict[str, Any]]:
    """Convert candidates to domain model invariant dicts."""
    entries = []
    for c in candidates:
        inv_id = f"discovered_{c.cwe.lower().replace('-', '_')}"
        entries.append({
            "id": inv_id,
            "statement": c.statement,
            "negation": c.negation,
            "description": c.description,
            "confidence": "observed",
            "relevant_cwes": [c.cwe],
            "evidence": c.evidence[:10],
            "mechanical_rule": None,
        })
    return entries


def _get_status(outcome: Any) -> str:
    if isinstance(outcome, dict):
        return outcome.get("status", "")
    return getattr(outcome, "status", "")


def _get_cwe(outcome: Any) -> str:
    if isinstance(outcome, dict):
        raw = outcome.get("cwe", "")
        if not raw:
            rr = outcome.get("review_result") or {}
            raw = rr.get("cwe", "")
    else:
        rr = getattr(outcome, "review_result", None) or {}
        raw = rr.get("cwe", "") if isinstance(rr, dict) else ""
        if not raw:
            raw = getattr(outcome, "cwe", "") or ""
    return _normalise_cwe(raw) if raw else ""


def _get_hypothesis(outcome: Any) -> str:
    if isinstance(outcome, dict):
        return outcome.get("hypothesis", "") or ""
    return getattr(outcome, "hypothesis", "") or ""


def _get_field(outcome: Any, field: str, default: str = "") -> str:
    if isinstance(outcome, dict):
        return outcome.get(field, default) or default
    return getattr(outcome, field, default) or default
