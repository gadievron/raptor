"""Attacker-perspective synthesis — post-loop attack chain composition.

After individual function reviews produce findings, this module reasons
about attack chains: "Finding A gives primitive X. Finding B gives
primitive Y. Together, X+Y gives Z (e.g., info leak + heap overflow =
ASLR bypass + code execution = pre-auth RCE)."

Finds individually-low-severity findings that combine into critical
chains. Per-function review can't see this because each finding is
assessed in isolation (Cap 9).

Chain constraint verification: checks that primitive outputs match
next-step inputs and that all chain members share an attack surface.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

_CWE_PRIMITIVE: Dict[str, str] = {
    "CWE-120": "write",
    "CWE-121": "write",
    "CWE-122": "write",
    "CWE-787": "write",
    "CWE-416": "write",
    "CWE-415": "write",
    "CWE-190": "write",
    "CWE-200": "info_leak",
    "CWE-209": "info_leak",
    "CWE-532": "info_leak",
    "CWE-78": "execute",
    "CWE-77": "execute",
    "CWE-94": "execute",
    "CWE-502": "execute",
    "CWE-306": "auth_bypass",
    "CWE-287": "auth_bypass",
    "CWE-862": "auth_bypass",
    "CWE-863": "auth_bypass",
    "CWE-476": "dos",
    "CWE-400": "dos",
    "CWE-770": "dos",
    "CWE-20": "input_control",
    "CWE-79": "xss",
    "CWE-89": "execute",
    "CWE-22": "read",
    "CWE-362": "race",
}

_COMPOSABLE_PAIRS: Dict[tuple, str] = {
    ("info_leak", "write"): "ASLR bypass + memory corruption",
    ("info_leak", "execute"): "leak-assisted code execution",
    ("auth_bypass", "execute"): "pre-auth code execution",
    ("auth_bypass", "read"): "pre-auth data access",
    ("auth_bypass", "write"): "pre-auth data mutation",
    ("read", "execute"): "information-to-execution escalation",
    ("input_control", "execute"): "injection to code execution",
    ("input_control", "write"): "injection to memory corruption",
    ("xss", "auth_bypass"): "XSS-to-account-takeover",
    ("race", "write"): "TOCTOU to memory corruption",
}

# Maximum length for multi-step chains (transitive composition).
_MAX_CHAIN_LENGTH = 5

# Output→input type compatibility for chain step stitching.
# Maps (output_primitive, input_primitive) to a description of the data
# flowing between them.  A pair NOT in this table is a type mismatch.
_STEP_OUTPUT_INPUT: Dict[tuple, str] = {
    ("info_leak", "write"): "leaked address feeds ASLR bypass for write",
    ("info_leak", "execute"): "leaked address feeds ASLR bypass for execute",
    ("auth_bypass", "execute"): "bypass provides access for execution",
    ("auth_bypass", "read"): "bypass provides access for data read",
    ("auth_bypass", "write"): "bypass provides access for data write",
    ("auth_bypass", "input_control"): "bypass provides access for input injection",
    ("read", "execute"): "read data informs execution target",
    ("read", "write"): "read value informs write payload",
    ("input_control", "execute"): "controlled input drives execution",
    ("input_control", "write"): "controlled input drives memory corruption",
    ("xss", "auth_bypass"): "XSS steals credentials for auth bypass",
    ("race", "write"): "race window enables memory corruption",
    ("write", "execute"): "memory corruption enables code execution",
}

_IMPACT_SEVERITY: Dict[str, str] = {
    "pre-auth code execution": "critical",
    "ASLR bypass + memory corruption": "critical",
    "leak-assisted code execution": "critical",
    "pre-auth data access": "high",
    "pre-auth data mutation": "high",
    "XSS-to-account-takeover": "high",
    "injection to code execution": "critical",
    "injection to memory corruption": "high",
    "information-to-execution escalation": "high",
    "TOCTOU to memory corruption": "high",
}


@dataclass
class AttackPrimitive:
    """What a finding gives the attacker."""

    kind: str
    description: str
    constraints: List[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """A composed attack from multiple findings."""

    chain_id: str
    finding_keys: List[str]
    primitives: List[AttackPrimitive]
    combined_impact: str
    severity: str
    narrative: str
    chain_status: str = "confirmed"
    constraint_failures: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "chain_id": self.chain_id,
            "finding_keys": self.finding_keys,
            "primitives": [
                {
                    "kind": p.kind,
                    "description": p.description,
                    "constraints": p.constraints,
                }
                for p in self.primitives
            ],
            "combined_impact": self.combined_impact,
            "severity": self.severity,
            "narrative": self.narrative,
            "chain_status": self.chain_status,
            "constraint_failures": self.constraint_failures,
        }
        if self.mitigations:
            d["mitigations"] = self.mitigations
        return d


def classify_primitive(outcome: Any) -> AttackPrimitive:
    """Map a finding's CWE/hypothesis to an attacker primitive."""
    review = getattr(outcome, "review_result", None) or {}
    cwe = review.get("cwe_class") or review.get("cwe") or ""
    hypothesis = getattr(outcome, "hypothesis", "") or ""

    cwe_clean = cwe.upper().replace(" ", "").split(",")[0] if cwe else ""

    kind = _CWE_PRIMITIVE.get(cwe_clean, "")
    if not kind:
        kind = _infer_primitive_from_hypothesis(hypothesis)
    if not kind:
        kind = "unknown"

    constraints = _extract_constraints(outcome)

    return AttackPrimitive(
        kind=kind,
        description=hypothesis[:200] if hypothesis else f"{cwe} vulnerability",
        constraints=constraints,
    )


def group_by_reachability(
    outcomes: Sequence[Any],
    context_map: Optional[Dict[str, Any]] = None,
) -> List[List[int]]:
    """Group finding indices by shared entry points or call paths.

    Falls back to file-proximity grouping when no context map is available.
    Findings that end up in no shared group are collected into a single
    residual group — which may span files and entry points — so every
    finding stays visible to chain synthesis.
    """
    finding_indices = [
        i for i, o in enumerate(outcomes)
        if getattr(o, "status", "") == "finding"
    ]

    if len(finding_indices) < 2:
        return [finding_indices] if finding_indices else []

    entry_map: Dict[str, List[int]] = {}

    if context_map:
        entry_points = context_map.get("entry_points", [])
        call_edges = context_map.get("call_edges", {})

        for idx in finding_indices:
            o = outcomes[idx]
            key = f"{getattr(o, 'file', '')}:{getattr(o, 'function', '')}"
            reachable_entries = _find_reachable_entries(
                key, entry_points, call_edges,
            )
            if reachable_entries:
                for ep in reachable_entries:
                    entry_map.setdefault(ep, []).append(idx)
            else:
                entry_map.setdefault(getattr(o, "file", "unknown"), []).append(idx)
    else:
        for idx in finding_indices:
            o = outcomes[idx]
            file_key = getattr(o, "file", "unknown")
            entry_map.setdefault(file_key, []).append(idx)

    groups = [indices for indices in entry_map.values() if len(indices) >= 2]

    ungrouped = set(finding_indices)
    for g in groups:
        ungrouped -= set(g)
    if ungrouped:
        groups.append(sorted(ungrouped))

    return groups


def synthesize_chains(
    outcomes: Sequence[Any],
    context_map: Optional[Dict[str, Any]] = None,
) -> List[AttackChain]:
    """Synthesize attack chains from review outcomes.

    Groups findings by reachability, classifies primitives, checks
    composability, and verifies cross-finding constraints.
    """
    groups = group_by_reachability(outcomes, context_map)
    primitives_cache: Dict[int, AttackPrimitive] = {}

    chains: List[AttackChain] = []
    chain_counter = 0

    for group in groups:
        if len(group) < 2:
            continue

        group_primitives = []
        for idx in group:
            if idx not in primitives_cache:
                primitives_cache[idx] = classify_primitive(outcomes[idx])
            group_primitives.append((idx, primitives_cache[idx]))

        for i, (idx_a, prim_a) in enumerate(group_primitives):
            for idx_b, prim_b in group_primitives[i + 1:]:
                pair = (prim_a.kind, prim_b.kind)
                reverse_pair = (prim_b.kind, prim_a.kind)

                combined = _COMPOSABLE_PAIRS.get(pair) or _COMPOSABLE_PAIRS.get(reverse_pair)
                if not combined:
                    continue

                # Normalise step order: when only the reverse direction
                # is a valid output→input transition, swap so the chain
                # always follows the forward direction. This keeps the
                # strict multi-step step check, the symmetric pairwise
                # check, and the narrative order in agreement.
                forward_ok = (
                    pair in _STEP_OUTPUT_INPUT or pair in _COMPOSABLE_PAIRS
                )
                reverse_ok = (
                    reverse_pair in _STEP_OUTPUT_INPUT
                    or reverse_pair in _COMPOSABLE_PAIRS
                )
                if not forward_ok and reverse_ok:
                    first_idx, first_prim = idx_b, prim_b
                    second_idx, second_prim = idx_a, prim_a
                else:
                    first_idx, first_prim = idx_a, prim_a
                    second_idx, second_prim = idx_b, prim_b

                chain_counter += 1
                key_a = f"{getattr(outcomes[first_idx], 'file', '')}:{getattr(outcomes[first_idx], 'function', '')}"
                key_b = f"{getattr(outcomes[second_idx], 'file', '')}:{getattr(outcomes[second_idx], 'function', '')}"

                constraint_failures = _check_chain_constraints(
                    outcomes[first_idx], outcomes[second_idx],
                    first_prim, second_prim,
                )
                status = "hypothetical" if constraint_failures else "confirmed"
                severity = _IMPACT_SEVERITY.get(combined, "medium")

                narrative = _build_narrative(
                    outcomes[first_idx], outcomes[second_idx],
                    first_prim, second_prim, combined,
                )

                mitigations = _infer_chain_mitigations(
                    first_prim, second_prim, combined,
                )

                chains.append(AttackChain(
                    chain_id=f"CHAIN-{chain_counter:03d}",
                    finding_keys=[key_a, key_b],
                    primitives=[first_prim, second_prim],
                    combined_impact=combined,
                    severity=severity,
                    narrative=narrative,
                    chain_status=status,
                    constraint_failures=constraint_failures,
                    mitigations=mitigations,
                ))

        # --- Multi-step extension (3+ steps) ---
        pairwise_for_group = [
            c for c in chains if c.chain_id.startswith("CHAIN-")
            and all(
                fk in {
                    f"{getattr(outcomes[idx], 'file', '')}:{getattr(outcomes[idx], 'function', '')}"
                    for idx in group
                }
                for fk in c.finding_keys
            )
        ]
        multi, chain_counter = _build_multi_step_chains(
            outcomes, pairwise_for_group, primitives_cache,
            group, chain_counter,
        )
        chains.extend(multi)

    logger.info(
        "attacker synthesis: %d chains from %d findings "
        "(%d confirmed, %d hypothetical, %d multi-step)",
        len(chains),
        sum(len(g) for g in groups),
        sum(1 for c in chains if c.chain_status == "confirmed"),
        sum(1 for c in chains if c.chain_status == "hypothetical"),
        sum(1 for c in chains if len(c.finding_keys) > 2),
    )

    return chains


def write_attack_chains(
    chains: Sequence[AttackChain],
    out_dir: Path,
) -> Path:
    """Write attack-chains.json to the output directory."""
    out_path = out_dir / "attack-chains.json"
    data = {
        "chains": [c.to_dict() for c in chains],
        "summary": {
            "total": len(chains),
            "confirmed": sum(1 for c in chains if c.chain_status == "confirmed"),
            "hypothetical": sum(1 for c in chains if c.chain_status == "hypothetical"),
            "critical": sum(1 for c in chains if c.severity == "critical"),
            "high": sum(1 for c in chains if c.severity == "high"),
        },
    }
    out_path.write_text(json.dumps(data, indent=2))
    logger.info("wrote %d attack chains to %s", len(chains), out_path)
    return out_path


def format_chains_summary(chains: Sequence[AttackChain]) -> str:
    """Render a human-readable summary of attack chains."""
    if not chains:
        return "No attack chains discovered."

    confirmed = [c for c in chains if c.chain_status == "confirmed"]
    hypothetical = [c for c in chains if c.chain_status == "hypothetical"]

    lines = [
        f"### Attack chain synthesis: {len(chains)} chain(s) discovered",
    ]

    if confirmed:
        lines.append(f"\n**Confirmed ({len(confirmed)}):**")
        for c in confirmed:
            lines.append(
                f"- **{c.chain_id}** [{c.severity}]: {c.combined_impact}"
            )
            lines.append(f"  {c.narrative}")

    if hypothetical:
        lines.append(f"\n**Hypothetical ({len(hypothetical)}):**")
        for c in hypothetical:
            failures = "; ".join(c.constraint_failures)
            lines.append(
                f"- **{c.chain_id}** [{c.severity}]: {c.combined_impact} "
                f"(blocked: {failures})"
            )

    return "\n".join(lines)


def _build_multi_step_chains(
    outcomes: Sequence[Any],
    pairwise_chains: List[AttackChain],
    primitives_cache: Dict[int, AttackPrimitive],
    group_indices: List[int],
    chain_counter: int,
) -> tuple:
    """Extend pairwise chains to multi-step chains (3-5 steps).

    For each existing chain A->B, look for a finding C in the same group
    where B->C is composable, building chains up to ``_MAX_CHAIN_LENGTH``.

    Returns (new_chains, updated_chain_counter).
    """
    if len(group_indices) < 3 or not pairwise_chains:
        return [], chain_counter

    # Build an adjacency map: for each primitive kind, which indices produce it?
    kind_to_indices: Dict[str, List[int]] = {}
    for idx in group_indices:
        prim = primitives_cache.get(idx)
        if prim:
            kind_to_indices.setdefault(prim.kind, []).append(idx)

    # Seed with pairwise chains (as index lists).
    # Each seed is a list of outcome indices forming the chain.
    seeds: List[List[int]] = []
    for chain in pairwise_chains:
        # Recover the indices from finding_keys.
        idxs = _recover_chain_indices(chain, outcomes, group_indices)
        if len(idxs) == 2:
            seeds.append(idxs)

    multi_chains: List[AttackChain] = []
    seen_key_sets: Set[frozenset] = set()

    # BFS-style extension: grow each seed by one step at a time.
    queue = list(seeds)
    while queue:
        current = queue.pop(0)
        if len(current) >= _MAX_CHAIN_LENGTH:
            continue

        tail_idx = current[-1]
        tail_prim = primitives_cache.get(tail_idx)
        if not tail_prim:
            continue

        # Find composable next steps from the tail's output.
        for (out_kind, in_kind) in _STEP_OUTPUT_INPUT:
            if out_kind != tail_prim.kind:
                continue
            for candidate_idx in kind_to_indices.get(in_kind, []):
                if candidate_idx in current:
                    continue  # no cycles
                extended = current + [candidate_idx]
                key = frozenset(extended)
                if key in seen_key_sets:
                    continue
                seen_key_sets.add(key)

                # Build the chain.
                chain_counter += 1
                chain = _assemble_multi_step_chain(
                    extended, outcomes, primitives_cache, chain_counter,
                )
                if chain is not None:
                    multi_chains.append(chain)
                    # Allow further extension if not at cap.
                    if len(extended) < _MAX_CHAIN_LENGTH:
                        queue.append(extended)

    return multi_chains, chain_counter


def _recover_chain_indices(
    chain: AttackChain,
    outcomes: Sequence[Any],
    group_indices: List[int],
) -> List[int]:
    """Map a chain's finding_keys back to outcome indices."""
    indices: List[int] = []
    for fk in chain.finding_keys:
        for idx in group_indices:
            o = outcomes[idx]
            key = f"{getattr(o, 'file', '')}:{getattr(o, 'function', '')}"
            if key == fk and idx not in indices:
                indices.append(idx)
                break
    return indices


def _assemble_multi_step_chain(
    index_list: List[int],
    outcomes: Sequence[Any],
    primitives_cache: Dict[int, AttackPrimitive],
    counter: int,
) -> "AttackChain | None":
    """Assemble an AttackChain from an ordered list of outcome indices."""
    primitives = [primitives_cache[i] for i in index_list]
    finding_keys = [
        f"{getattr(outcomes[i], 'file', '')}:{getattr(outcomes[i], 'function', '')}"
        for i in index_list
    ]

    # Verify step-to-step output→input compatibility.
    constraint_failures: List[str] = []
    for step in range(len(primitives) - 1):
        src = primitives[step]
        dst = primitives[step + 1]
        pair = (src.kind, dst.kind)
        if pair not in _STEP_OUTPUT_INPUT:
            constraint_failures.append(
                f"type mismatch: {src.kind} output does not feed {dst.kind} input "
                f"(step {step + 1} -> {step + 2})"
            )

    # Also run pairwise constraint checks on each adjacent pair.
    for step in range(len(index_list) - 1):
        pairwise_failures = _check_chain_constraints(
            outcomes[index_list[step]], outcomes[index_list[step + 1]],
            primitives[step], primitives[step + 1],
        )
        constraint_failures.extend(pairwise_failures)

    status = "hypothetical" if constraint_failures else "confirmed"

    # Build combined impact from the full chain.
    kinds = [p.kind for p in primitives]
    combined = " -> ".join(kinds)
    # Check if the overall chain matches a known high-impact combination.
    first_last = (kinds[0], kinds[-1])
    named_impact = _COMPOSABLE_PAIRS.get(first_last)
    if named_impact:
        combined = f"{named_impact} ({len(primitives)}-step)"
    else:
        combined = f"multi-step chain: {combined}"

    severity = _IMPACT_SEVERITY.get(named_impact or "", "medium")

    # Build narrative.
    steps = []
    for i, idx in enumerate(index_list):
        fn = getattr(outcomes[idx], "function", "?")
        f = getattr(outcomes[idx], "file", "?")
        desc = primitives[i].description[:60]
        steps.append(f"Step {i + 1}: {primitives[i].kind} via `{fn}` ({f}) — {desc}")
    narrative = ". ".join(steps) + f". Combined: {combined}."

    mitigations = _infer_chain_mitigations(primitives[0], primitives[-1], combined)

    return AttackChain(
        chain_id=f"CHAIN-{counter:03d}",
        finding_keys=finding_keys,
        primitives=list(primitives),
        combined_impact=combined,
        severity=severity,
        narrative=narrative,
        chain_status=status,
        constraint_failures=constraint_failures,
        mitigations=mitigations,
    )


def _infer_primitive_from_hypothesis(hypothesis: str) -> str:
    """Infer primitive kind from hypothesis text."""
    hyp = hypothesis.lower()

    if any(w in hyp for w in ("buffer overflow", "out of bounds write",
                               "heap overflow", "stack overflow")):
        return "write"
    if any(w in hyp for w in ("use after free", "use-after-free", "double free")):
        return "write"
    if any(w in hyp for w in ("info leak", "information disclosure",
                               "memory disclosure", "uninitialized")):
        return "info_leak"
    if any(w in hyp for w in ("command injection", "code execution",
                               "code injection", "rce", "eval")):
        return "execute"
    if any(w in hyp for w in ("sql injection",)):
        return "execute"
    if any(w in hyp for w in ("auth bypass", "authentication bypass",
                               "missing auth", "unauthenticated")):
        return "auth_bypass"
    if any(w in hyp for w in ("null pointer", "null deref", "denial of service")):
        return "dos"
    if any(w in hyp for w in ("path traversal", "directory traversal")):
        return "read"
    if any(w in hyp for w in ("xss", "cross-site scripting")):
        return "xss"
    if any(w in hyp for w in ("race condition", "toctou")):
        return "race"

    return ""


def _extract_constraints(outcome: Any) -> List[str]:
    """Extract exploitation constraints from a finding."""
    constraints = []
    review = getattr(outcome, "review_result", None) or {}

    preconditions = review.get("preconditions", [])
    for p in preconditions:
        assumption = p.get("assumption", "")
        if assumption:
            constraints.append(assumption[:100])

    return constraints[:5]


def _find_reachable_entries(
    key: str,
    entry_points: list,
    call_edges: dict,
) -> List[str]:
    """Find which entry points can reach a given function."""
    ep_names = set()
    for ep in entry_points:
        if isinstance(ep, dict):
            ep_key = f"{ep.get('file', '')}:{ep.get('name', '')}"
        else:
            ep_key = str(ep)
        ep_names.add(ep_key)

    if key in ep_names:
        return [key]

    reachable = []
    visited: Set[str] = set()

    def _walk_callers(k: str) -> None:
        if k in visited:
            return
        visited.add(k)
        if k in ep_names:
            reachable.append(k)
            return
        for caller, callees in call_edges.items():
            if isinstance(callees, list) and k in callees:
                _walk_callers(caller)

    _walk_callers(key)
    return reachable[:5]


def _check_chain_constraints(
    outcome_a: Any,
    outcome_b: Any,
    prim_a: AttackPrimitive,
    prim_b: AttackPrimitive,
) -> List[str]:
    """Check whether two findings can compose into a chain.

    Returns a list of constraint failures (empty = composable).
    Checks both access-level constraints and output→input type
    compatibility between the two primitives.
    """
    failures = []

    for label, prim, other in (
        ("A", prim_a, prim_b),
        ("B", prim_b, prim_a),
    ):
        for constraint in prim.constraints:
            c_lower = constraint.lower()
            if "local" in c_lower and "only" in c_lower:
                failures.append(
                    f"Finding {label} ({prim.kind}) requires local access"
                )
            if "authentication required" in c_lower or "auth required" in c_lower:
                if other.kind == "auth_bypass":
                    pass
                else:
                    failures.append(
                        f"Finding {label} requires authentication"
                    )

    # Output→input type compatibility check.
    pair = (prim_a.kind, prim_b.kind)
    reverse = (prim_b.kind, prim_a.kind)
    if pair not in _STEP_OUTPUT_INPUT and reverse not in _STEP_OUTPUT_INPUT:
        # Only flag as a type mismatch if neither direction is compatible
        # AND the pair is also not in the pairwise composable table.
        if pair not in _COMPOSABLE_PAIRS and reverse not in _COMPOSABLE_PAIRS:
            failures.append(
                f"type mismatch: {prim_a.kind} output does not feed "
                f"{prim_b.kind} input"
            )

    return failures


def _build_narrative(
    outcome_a: Any,
    outcome_b: Any,
    prim_a: AttackPrimitive,
    prim_b: AttackPrimitive,
    combined_impact: str,
) -> str:
    """Build a human-readable attack narrative."""
    fn_a = getattr(outcome_a, "function", "?")
    fn_b = getattr(outcome_b, "function", "?")
    file_a = getattr(outcome_a, "file", "?")
    file_b = getattr(outcome_b, "file", "?")

    return (
        f"Step 1: {prim_a.kind} via `{fn_a}` ({file_a}) — "
        f"{prim_a.description[:80]}. "
        f"Step 2: {prim_b.kind} via `{fn_b}` ({file_b}) — "
        f"{prim_b.description[:80]}. "
        f"Combined: {combined_impact}."
    )


_PRIMITIVE_MITIGATIONS: Dict[str, List[str]] = {
    "write": ["ASLR", "stack canaries", "CFI", "safe heap allocator"],
    "info_leak": ["ASLR (partial mitigation)", "address-space isolation"],
    "execute": ["input validation", "sandboxing", "least-privilege execution"],
    "auth_bypass": ["multi-factor authentication", "rate limiting"],
    "dos": ["resource limits", "timeout enforcement"],
    "xss": ["Content-Security-Policy", "output encoding"],
    "read": ["chroot/namespace isolation", "mandatory access controls"],
    "race": ["mutex/lock discipline", "atomic operations"],
    "input_control": ["input validation", "allowlist enforcement"],
}

_CHAIN_MITIGATIONS: Dict[str, List[str]] = {
    "ASLR bypass + memory corruption": [
        "PIE + full ASLR", "CFI/shadow stack", "safe heap allocator",
    ],
    "leak-assisted code execution": [
        "W^X enforcement", "CFI", "address-space isolation",
    ],
    "pre-auth code execution": [
        "authentication at network boundary", "sandboxing",
    ],
    "pre-auth data access": [
        "authentication at network boundary", "data encryption at rest",
    ],
    "injection to code execution": [
        "input validation", "parameterised queries", "sandboxing",
    ],
    "XSS-to-account-takeover": [
        "Content-Security-Policy", "HttpOnly cookies", "SameSite cookies",
    ],
}


def _infer_chain_mitigations(
    prim_a: AttackPrimitive,
    prim_b: AttackPrimitive,
    combined_impact: str,
) -> List[str]:
    """Infer what mitigations could break the chain."""
    chain_specific = _CHAIN_MITIGATIONS.get(combined_impact, [])
    if chain_specific:
        return list(chain_specific)

    mitigations: List[str] = []
    for prim in (prim_a, prim_b):
        for m in _PRIMITIVE_MITIGATIONS.get(prim.kind, []):
            if m not in mitigations:
                mitigations.append(m)
    return mitigations[:5]
