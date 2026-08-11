"""Phase 2b: chaining detection for bug-first mode.

After Phase 2 classifies individual bugs, this module finds pairs of
quality-only bugs that compose into security issues.  Only considers
pairs on the same call chain or flow trace — not O(N^2).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

CHAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "chain_description": {
            "type": "string",
            "description": (
                "How the two bugs compose: what Bug A enables that "
                "Bug B exploits, or vice versa."
            ),
        },
        "primitive": {
            "type": "string",
            "enum": [
                "read", "write", "execute", "auth_bypass",
                "dos", "info_leak",
            ],
            "description": "The attacker primitive the chain provides.",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
        },
        "is_chain": {
            "type": "boolean",
            "description": (
                "true if these two bugs compose into a security issue "
                "that neither bug represents alone."
            ),
        },
    },
    "required": ["chain_description", "is_chain"],
}


def _build_call_graph(outcomes: List[Any]) -> Dict[str, Set[str]]:
    """Build adjacency from review_result caller/callee data.

    Returns a dict mapping ``file:function`` to the set of keys it
    directly connects to (callers + callees).
    """
    graph: Dict[str, Set[str]] = {}
    for o in outcomes:
        key = f"{o.file}:{o.function}"
        neighbours = graph.setdefault(key, set())
        rr = o.review_result or {}
        for c in rr.get("callers", []):
            if isinstance(c, dict) and c.get("file") and c.get("name"):
                n = f"{c['file']}:{c['name']}"
                neighbours.add(n)
                graph.setdefault(n, set()).add(key)
        for c in rr.get("callees", []):
            if isinstance(c, dict) and c.get("file") and c.get("name"):
                n = f"{c['file']}:{c['name']}"
                neighbours.add(n)
                graph.setdefault(n, set()).add(key)
    return graph


def _load_flow_trace_pairs(out_dir: Path) -> Set[Tuple[str, str]]:
    """Load pairs of functions on the same flow trace."""
    pairs: Set[Tuple[str, str]] = set()
    for ft_path in out_dir.glob("flow-trace-*.json"):
        try:
            ft = json.loads(ft_path.read_text(encoding="utf-8"))
            hops = ft.get("hops", [])[:50]
            keys = []
            for hop in hops:
                if isinstance(hop, dict) and hop.get("file") and hop.get("function"):
                    keys.append(f"{hop['file']}:{hop['function']}")
            for i, a in enumerate(keys):
                for b in keys[i + 1:]:
                    pair = tuple(sorted([a, b]))
                    pairs.add(pair)
        except Exception:
            continue
    return pairs


def find_chain_candidates(
    outcomes: List[Any],
    out_dir: Path,
    classifications: Dict[str, Dict[str, Any]],
) -> List[Tuple[Any, Any]]:
    """Find candidate pairs for chaining evaluation.

    Only pairs where:
    - Both are quality_finding (or unclassified finding/suspicious)
    - Both are on the same call chain or flow trace
    """
    quality_outcomes = []
    for o in outcomes:
        if o.status not in ("finding", "suspicious"):
            continue
        key = f"{o.file}:{o.function}"
        cls = classifications.get(key, {})
        if cls.get("classification") == "security_finding":
            continue
        quality_outcomes.append(o)

    if len(quality_outcomes) < 2:
        return []

    call_graph = _build_call_graph(outcomes)
    flow_pairs = _load_flow_trace_pairs(out_dir)

    candidates: List[Tuple[Any, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    for i, a in enumerate(quality_outcomes):
        a_key = f"{a.file}:{a.function}"
        for b in quality_outcomes[i + 1:]:
            b_key = f"{b.file}:{b.function}"
            pair_key = tuple(sorted([a_key, b_key]))
            if pair_key in seen:
                continue

            connected = (
                b_key in call_graph.get(a_key, set())
                or pair_key in flow_pairs
            )
            if connected:
                candidates.append((a, b))
                seen.add(pair_key)

    return candidates


def _build_chain_prompt(a: Any, b: Any) -> str:
    rr_a = a.review_result or {}
    rr_b = b.review_result or {}
    return (
        f"These bugs were found in the same call graph / data flow path:\n\n"
        f"Bug A: {a.file}:{a.function}\n"
        f"  Hypothesis: {a.hypothesis}\n"
        f"  Class: {rr_a.get('bug_class', 'unknown')}\n"
        f"  Description: {a.body}\n\n"
        f"Bug B: {b.file}:{b.function}\n"
        f"  Hypothesis: {b.hypothesis}\n"
        f"  Class: {rr_b.get('bug_class', 'unknown')}\n"
        f"  Description: {b.body}\n\n"
        "Do these bugs compose into a security issue?  For example:\n"
        "- Bug A weakens a bounds check + Bug B uses the unchecked value\n"
        "- Bug A leaks a pointer + Bug B uses the leaked address\n"
        "- Bug A skips authentication under error + Bug B triggers the error\n\n"
        "If they do NOT compose, set is_chain to false."
    )


def evaluate_chains(
    candidates: List[Tuple[Any, Any]],
    llm_client: Any,
    *,
    model_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Evaluate candidate pairs for security chaining.

    Returns a list of confirmed chain records.
    """
    if not candidates:
        return []

    kwargs: Dict[str, Any] = {"task_type": "audit"}
    if model_name:
        try:
            mc = llm_client.config.config_for_model(model_name)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    chains: List[Dict[str, Any]] = []
    for a, b in candidates:
        prompt = _build_chain_prompt(a, b)
        try:
            response = llm_client.generate_structured(
                prompt,
                CHAIN_SCHEMA,
                system_prompt=(
                    "You are a security analyst.  Given two verified "
                    "code defects on the same call path, decide whether "
                    "they compose into a security vulnerability that "
                    "neither defect represents alone."
                ),
                **kwargs,
            )
            result = response.result if hasattr(response, "result") else response[0]
        except Exception:
            logger.warning(
                "chain evaluation failed for %s:%s + %s:%s",
                a.file, a.function, b.file, b.function,
                exc_info=True,
            )
            continue

        if result.get("is_chain"):
            chain = {
                "bug_a": f"{a.file}:{a.function}",
                "bug_b": f"{b.file}:{b.function}",
                "chain_description": result.get("chain_description", ""),
                "primitive": result.get("primitive", ""),
                "confidence": result.get("confidence", "medium"),
            }
            chains.append(chain)
            logger.info(
                "Chain found: %s + %s → %s",
                chain["bug_a"], chain["bug_b"],
                chain.get("primitive", "?"),
            )

    return chains
