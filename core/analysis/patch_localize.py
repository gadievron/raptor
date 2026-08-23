"""Patch localization: rank changed functions against an advisory,
expand to call chains, cluster the survivors.

The end-to-end recipe from the SiftRank paper's security evaluation
(arXiv:2512.06155 §4; see docs/references.md), for the situation
/cve-diff's discovery agent cannot solve: no published fix commit,
but a vendor patch is in hand and the changed functions are known
(from a source diff, or BinDiff + decompilation for binary patches).

Pipeline:
  1. Chains: each candidate function alone, plus caller→callee pairs
     where BOTH endpoints are candidates (paper: chains of length
     1–2 carry interprocedural context that isolated functions lack).
  2. Rank the chains against the advisory text with
     ``core.llm.ranking`` (listwise, batched, convergence-stopped).
  3. Keep the chains that survived more than one ranking iteration
     when any did (the paper's k>1 retrieval cut); otherwise keep
     everything — a corpus that converged in one iteration was never
     refined, so survival carries no signal.
  4. Cluster on the call graph with ``core.analysis.rank_clusters``
     (w = k/r weights, mass × density scoring).

The output is a review queue of clusters, most suspicious first —
not a verdict. Candidate names and text are untrusted (they come
from the patched target): this module length-caps both, and the
ranking module nonce-envelopes and control-char-escapes every
rendered document. The advisory is the *query* — operator-supplied
trusted input in the instruction position, not enveloped.

Functions are keyed by name only; same-named functions from
different files (C ``static`` collisions) merge — disambiguate names
upstream if that matters for the target.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# Per-function text cap. The paper ranks ~4-sentence summaries;
# decompiled bodies work too but batches of 5-10 must stay well
# inside the model's context. Function names are capped separately —
# they come from the same untrusted input.
DEFAULT_MAX_TEXT_CHARS = 1600
_MAX_NAME_CHARS = 200

# Chain-count ceiling. Chains cost O(chains) LLM calls per trial; a
# big vendor patch joined with a dense call graph can otherwise
# explode into tens of thousands of chains and burn the entire model
# budget on ordering noise. Singles are kept first (every candidate
# stays represented); pair chains fill the remainder in edge order,
# and the truncation is loud (log + report field).
DEFAULT_MAX_CHAINS = 2000
DEFAULT_QUERY_PREFIX = (
    "Below is a security advisory. Rank these changed-function call "
    "chains by how likely they contain or implement the fix for the "
    "vulnerability the advisory describes.\n\nAdvisory:\n"
)


def build_chains(
    candidates: list[dict[str, Any]],
    edges: Iterable[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Length-1 and length-2 chains over the candidate set.

    ``candidates``: dicts with ``function`` (name) and ``text``
    (summary or decompiled body). Pairs are added for each directed
    edge whose endpoints are BOTH candidates; duplicates and
    self-edges are dropped.
    """
    by_name: dict[str, str] = {}
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        name = str(cand.get("function") or "")
        if name and name not in by_name:
            by_name[name] = str(cand.get("text") or "")
    chains = [{"functions": [name]} for name in by_name]
    seen_pairs: set[tuple[str, str]] = set()
    for caller, callee in edges:
        caller, callee = str(caller), str(callee)
        if caller == callee or (caller, callee) in seen_pairs:
            continue
        if caller in by_name and callee in by_name:
            seen_pairs.add((caller, callee))
            chains.append({"functions": [caller, callee]})
    return chains


def normalize_edges(raw_edges: Any) -> list[tuple[str, str]]:
    """Validate and coerce a JSON edges payload.

    Accepts only a list of 2-element list/tuple pairs. Strings,
    dicts, and wrong-arity elements raise ValueError — a dict would
    otherwise silently unpack into its KEYS and destroy every pair
    signal without an error.
    """
    if not isinstance(raw_edges, list):
        raise ValueError("edges must be a JSON array")
    edges: list[tuple[str, str]] = []
    for entry in raw_edges:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError(
                f"edge must be a [caller, callee] pair, got: {entry!r:.100}",
            )
        caller, callee = entry
        edges.append((str(caller), str(callee)))
    return edges


def _render_chain(
    chain: dict[str, Any], texts: dict[str, str], max_chars: int,
) -> str:
    names = [n[:_MAX_NAME_CHARS] for n in chain["functions"]]
    parts = [f"call chain: {' -> '.join(names)}"]
    for full_name, name in zip(chain["functions"], names, strict=True):
        parts.append(f"--- {name} ---")
        parts.append(texts.get(full_name, "")[:max_chars])
    return "\n".join(parts)


def localize(
    candidates: list[dict[str, Any]],
    edges: list[tuple[str, str]],
    advisory: str,
    *,
    client: Any = None,
    model: str | None = None,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    max_chains: int = DEFAULT_MAX_CHAINS,
    seed: int | None = None,
    max_workers: int | None = None,
) -> dict[str, Any]:
    """Run the full localization pipeline. Returns a report dict.

    Report shape (stable, consumed by ``raptor-cve-diff localize``):
    ``chains`` (ranked, each with functions/rank/iterations),
    ``clusters`` (scored, best first), ``stats`` (LLM cost/calls,
    survivor counts). Raises ValueError on empty inputs; model-side
    failures degrade inside the ranking layer (input order, no
    signal) rather than raising.
    """
    if not candidates:
        raise ValueError("no candidate functions to localize over")
    from core.analysis.rank_clusters import rank_clusters
    from core.llm.ranking import rank_items

    if client is None:
        from core.llm.client import LLMClient
        client = LLMClient(pinned_model=model) if model else LLMClient()

    # First occurrence wins, matching build_chains' dedupe.
    texts: dict[str, str] = {}
    for cand in candidates:
        if isinstance(cand, dict) and cand.get("function"):
            texts.setdefault(
                str(cand["function"]), str(cand.get("text") or ""),
            )
    chains = build_chains(candidates, edges)
    chains_truncated = 0
    if len(chains) > max(1, max_chains):
        # Singles come first from build_chains, so every candidate
        # stays represented; excess pair chains are dropped loudly.
        chains_truncated = len(chains) - max_chains
        logger.warning(
            "localize: %d chains exceed the %d-chain cap; dropping %d "
            "pair chains (pass max_chains to raise)",
            len(chains), max_chains, chains_truncated,
        )
        chains = chains[:max_chains]
    query = DEFAULT_QUERY_PREFIX + advisory

    result = rank_items(
        chains, query, client=client,
        render=lambda ch: _render_chain(ch, texts, max_text_chars),
        seed=seed, max_workers=max_workers,
    )
    ranked_chains = [
        {
            "functions": item.item["functions"],
            "rank": item.rank,
            "iterations": item.iterations,
        }
        for item in result.ranked
    ]

    # Paper §4.2: keep chains that survived multiple ranking
    # iterations (k>1) when refinement happened at all.
    survivors = [c for c in ranked_chains if c["iterations"] > 1]
    if not survivors:
        survivors = ranked_chains

    report = rank_clusters(survivors, edges)
    return {
        "chains": ranked_chains,
        "survivors": len(survivors),
        "clusters": [
            {
                "seed": cl.seed,
                "radius": cl.radius,
                "members": list(cl.members),
                "mass": cl.mass,
                "density": cl.density,
                "score": cl.score,
            }
            for cl in report.clusters
        ],
        "stats": {
            "chains_total": len(ranked_chains),
            "chains_truncated": chains_truncated,
            "llm_calls": result.stats.llm_calls,
            "trials": result.stats.trials,
            "iterations": result.stats.iterations,
            "dropped_batches": result.stats.dropped_batches,
            "converged": result.stats.converged,
            "cost_usd": round(result.stats.cost, 4),
        },
    }
