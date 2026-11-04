"""Chain detection: find pairs of individually non-exploitable items
that compose into a security vulnerability.

Two consumers:

1. **Bug-first mode (Phase 2b):** after Phase 2 classifies individual
   bugs, pairs of quality-only findings connected by call graph or flow
   trace are evaluated for security composition.
2. **Weakness chaining (SEC pass):** after the main review loop,
   weakness-status outcomes on the same call path are evaluated — two
   weaknesses that individually aren't exploitable may together form a
   real vulnerability.

Enumeration is O(N^2) over the candidate set, but only pairs connected
by a call-graph edge or a shared flow trace become candidates —
everything else is filtered out before any LLM submission.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from core.json import load_json
from core.llm.coerce import structured_result
from core.security.prompt_framing import with_audit_framing

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = logging.getLogger(__name__)

# Flow-trace artifacts are RAPTOR-written run output, parsed in a
# glob loop — the audit-artifact budget class.
_MAX_FLOW_TRACE_BYTES = 64 * 1024 * 1024

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


def _build_call_graph(outcomes: list[Any]) -> dict[str, set[str]]:
    """Build adjacency from review_result caller/callee data.

    Returns a dict mapping ``file:function`` to the set of keys it
    directly connects to (callers + callees).
    """
    graph: dict[str, set[str]] = {}
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


def _load_flow_trace_pairs(out_dir: Path) -> set[tuple[str, str]]:
    """Load pairs of functions on the same flow trace."""
    pairs: set[tuple[str, str]] = set()
    for ft_path in out_dir.glob("flow-trace-*.json"):
        try:
            ft = load_json(ft_path, max_bytes=_MAX_FLOW_TRACE_BYTES)
            if not isinstance(ft, dict):
                continue
            hops = ft.get("hops", [])[:50]
            keys = [f"{hop['file']}:{hop['function']}" for hop in hops if isinstance(hop, dict) and hop.get("file") and hop.get("function")]
            for i, a in enumerate(keys):
                for b in keys[i + 1:]:
                    pair = tuple(sorted([a, b]))
                    pairs.add(pair)  # type: ignore[arg-type]
        except Exception:
            logger.debug("flow trace pair load failed", exc_info=True)
            continue
    return pairs


def find_weakness_chain_candidates(
    outcomes: list[Any],
    out_dir: Path,
) -> list[tuple[Any, Any]]:
    """Find weakness pairs that may compose into a vulnerability.

    Filters to ``status == "weakness"`` outcomes connected by a
    call-graph edge or shared flow trace — no classifier needed.
    """
    weakness_outcomes = [o for o in outcomes if o.status == "weakness"]

    if len(weakness_outcomes) < 2:
        return []

    call_graph = _build_call_graph(outcomes)
    flow_pairs = _load_flow_trace_pairs(out_dir)

    candidates: list[tuple[Any, Any]] = []
    seen: set[tuple[str, str]] = set()

    for i, a in enumerate(weakness_outcomes):
        a_key = f"{a.file}:{a.function}"
        for b in weakness_outcomes[i + 1:]:
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
                seen.add(pair_key)  # type: ignore[arg-type]

    return candidates


_WEAKNESS_CHAIN_SYSTEM = with_audit_framing(
    "You are a security analyst.  Given two code weaknesses on the "
    "same call path, decide whether they compose into an exploitable "
    "vulnerability that neither weakness represents alone.\n\n"
    "Each weakness was individually assessed as not exploitable on its "
    "own.  The question is whether TOGETHER they create an attack "
    "path.\n\n"
    "Examples of weakness chains:\n"
    "- Weakness A: missing input length validation + Weakness B: "
    "fixed-size buffer copy using that length → buffer overflow\n"
    "- Weakness A: error path skips authentication + Weakness B: "
    "triggers that error path → auth bypass\n"
    "- Weakness A: leaks heap pointer via error message + Weakness B: "
    "use-after-free with attacker-controlled pointer → code "
    "execution\n\n"
    "If they do NOT compose, set is_chain to false.",
)


def _build_weakness_chain_prompt(
    a: Any, b: Any, *, model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped weakness-chain prompt.
    Returns ``(user, system)``."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    rr_a = a.review_result or {}
    rr_b = b.review_result or {}
    key_a = f"{a.file}:{a.function}"
    key_b = f"{b.file}:{b.function}"

    blocks = (
        UntrustedBlock(
            content=(
                f"Hypothesis: {a.hypothesis}\n"
                f"Description: {a.body}"
            ),
            kind="weakness-a",
            origin=key_a,
        ),
        UntrustedBlock(
            content=(
                f"Hypothesis: {b.hypothesis}\n"
                f"Description: {b.body}"
            ),
            kind="weakness-b",
            origin=key_b,
        ),
    )
    slots = {
        "weakness_a_location": TaintedString(
            value=key_a, trust="untrusted"),
        "weakness_a_class": TaintedString(
            value=str(rr_a.get("bug_class", "unknown")),
            trust="untrusted",
        ),
        "weakness_b_location": TaintedString(
            value=key_b, trust="untrusted"),
        "weakness_b_class": TaintedString(
            value=str(rr_b.get("bug_class", "unknown")),
            trust="untrusted",
        ),
    }
    return envelope_prompt(
        _WEAKNESS_CHAIN_SYSTEM, blocks, slots, model_id=model_id,
    )


def evaluate_weakness_chains(
    candidates: list[tuple[Any, Any]],
    llm_client: Any,
    *,
    model_name: str | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate weakness pairs for security composition.

    Same contract as :func:`evaluate_chains` but uses the
    weakness-specific prompt.
    """
    if not candidates:
        return []

    kwargs: dict[str, Any] = {"task_type": "audit"}
    if model_name:
        try:
            mc = llm_client.config.config_for_model(model_name)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    chains: list[dict[str, Any]] = []
    evaluated = 0
    for a, b in candidates:
        if should_stop is not None and should_stop():
            logger.info(
                "weakness chain evaluation stopped — environment guard "
                "concluded (%d/%d pair(s) evaluated, %d chain(s))",
                evaluated, len(candidates), len(chains),
            )
            break
        evaluated += 1
        prompt, system_prompt = _build_weakness_chain_prompt(
            a, b,
            model_id=(
                model_name
                or getattr(llm_client, "model_name", "")
                or ""
            ),
        )
        try:
            response = llm_client.generate_structured(
                prompt,
                CHAIN_SCHEMA,
                system_prompt=system_prompt,
                **kwargs,
            )
            result = structured_result(response, default={})
            from core.audit.evidence_grade import defang_model_fields
            result = defang_model_fields(result)
        except Exception:
            logger.warning(
                "weakness chain evaluation failed for %s:%s + %s:%s",
                a.file, a.function, b.file, b.function,
                exc_info=True,
            )
            continue

        if result.get("is_chain"):
            chain = {
                "weakness_a": f"{a.file}:{a.function}",
                "weakness_b": f"{b.file}:{b.function}",
                "chain_description": result.get(
                    "chain_description", ""),
                "primitive": result.get("primitive", ""),
                "confidence": result.get("confidence", "medium"),
            }
            chains.append(chain)
            logger.info(
                "Weakness chain: %s + %s → %s",
                chain["weakness_a"], chain["weakness_b"],
                chain.get("primitive", "?"),
            )

    return chains


# ── Chain-to-checker synthesis ─────────────────────────────────────
#
# When a confirmed weakness chain lacks tool receipts on one or both
# constituents, it cannot be promoted to a finding.  This function
# attempts to close the gap by synthesising a Semgrep taint-mode rule
# that captures the *composition* — the cross-function flow from source
# to sink — and running it against the target.  A positive hit earns
# a ``semgrep:chain-checker`` receipt; the orchestrator can then promote.

_PRIMITIVE_TO_CWE: dict[str, str] = {
    "write": "CWE-120",
    "read": "CWE-125",
    "execute": "CWE-94",
    "auth_bypass": "CWE-287",
    "dos": "CWE-400",
    "info_leak": "CWE-200",
}


def synthesise_chain_checker(
    chain: dict[str, Any],
    outcome_a: Any,
    outcome_b: Any,
    target_path: "Path",
    out_dir: "Path",
    llm_callable: Any,
    *,
    model_id: str = "",
) -> Any | None:
    """Synthesise a checker from a confirmed weakness chain.

    Builds a :class:`SeedBug` representing the *composition* and
    delegates to ``synthesise_and_run``.  The seed is anchored to the
    SINK function; the reasoning describes both functions and the
    connecting flow so the LLM produces a taint-mode rule.

    Returns a ``CheckerSynthesisResult`` on success, None on failure.
    """
    from pathlib import Path as _Path

    try:
        from packages.checker_synthesis.models import SeedBug
        from packages.checker_synthesis.synthesise import synthesise_and_run
    except ImportError:
        logger.debug("checker_synthesis not available for chain synthesis")
        return None

    _SINK_CLASSES = frozenset({
        "buffer_overflow", "auth_bypass", "code_injection",
        "command_injection", "sql_injection", "use_after_free",
        "format_string",
    })
    rr_a = getattr(outcome_a, "review_result", None) or {}
    rr_b = getattr(outcome_b, "review_result", None) or {}
    bc_a = rr_a.get("bug_class", "")
    bc_b = rr_b.get("bug_class", "")

    if bc_b in _SINK_CLASSES or bc_a not in _SINK_CLASSES:
        sink, source = outcome_b, outcome_a
    else:
        sink, source = outcome_a, outcome_b

    primitive = chain.get("primitive", "")
    cwe = _PRIMITIVE_TO_CWE.get(primitive, "CWE-20")

    from core.source.contained import read_text_capped

    sink_path = _Path(target_path) / sink.file
    source_path = _Path(target_path) / source.file
    pair = read_text_capped(sink_path)
    sink_snippet = pair[0] if pair else getattr(sink, "body", "")
    pair = read_text_capped(source_path)
    source_snippet = pair[0] if pair else getattr(source, "body", "")

    from core.audit.evidence_grade import defang_model_body

    chain_desc = defang_model_body(chain.get("chain_description", ""))
    source_hyp = defang_model_body(getattr(source, "hypothesis", ""))
    sink_hyp = defang_model_body(getattr(sink, "hypothesis", ""))
    reasoning = (
        f"CROSS-FUNCTION CHAIN: {source.file}:{source.function} → "
        f"{sink.file}:{sink.function}\n\n"
        f"SOURCE weakness ({source.file}:{source.function}): "
        f"{source_hyp}\n\n"
        f"SINK weakness ({sink.file}:{sink.function}): "
        f"{sink_hyp}\n\n"
        f"Chain composition: {chain_desc}\n\n"
        f"The checker should be a TAINT-MODE rule that tracks data "
        f"flow from the source function to the sink function."
    )

    positive_fixture = (
        f"// --- {source.file} ---\n{source_snippet}\n\n"
        f"// --- {sink.file} ---\n{sink_snippet}"
    )

    seed = SeedBug(
        file=sink.file,
        function=sink.function,
        line_start=0,
        line_end=0,
        cwe=cwe,
        reasoning=reasoning,
        snippet=sink_snippet,
        provenance=(
            f"weakness_chain:{source.file}:{source.function}+"
            f"{sink.file}:{sink.function}"
        ),
    )

    try:
        result = synthesise_and_run(
            seed=seed,
            repo_root=_Path(target_path),
            out_dir=_Path(out_dir),
            llm=llm_callable,
            max_retries=1,
            max_matches=10,
            model_id=model_id,
            ground_truth_fixtures=(positive_fixture, None),
        )
        if result.positive_control and result.matches:
            logger.info(
                "chain checker synthesis succeeded for %s + %s: "
                "%d match(es), rule_tier=%s",
                chain.get("weakness_a", "?"),
                chain.get("weakness_b", "?"),
                len(result.matches),
                result.rule_tier,
            )
            return result
        logger.info(
            "chain checker synthesis did not produce matches for %s + %s",
            chain.get("weakness_a", "?"),
            chain.get("weakness_b", "?"),
        )
        return None
    except Exception:
        logger.debug(
            "chain checker synthesis failed for %s + %s",
            chain.get("weakness_a", "?"),
            chain.get("weakness_b", "?"),
            exc_info=True,
        )
        return None
