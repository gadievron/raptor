"""Weakness composition engine.

Given a weakness inventory (from the structured pass's guard-shaped
refutations) and the existing call graph, mechanically produce
composed hypotheses — (weakness, unguarded path) pairs that together
constitute a vulnerability.

Guard matching is journal-driven and property-aware: the engine
checks whether a caller's review addressed the same guard_type
category, not just whether it was reviewed.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WeaknessRecord:
    """One guard-shaped refutation from the structured pass."""

    function: str
    file: str
    guard_type: str
    assumed_property: str
    mechanism: str
    guarded_by: tuple[str, ...]
    cwe_class: str | None = None
    source: str = "structured_pass"

    @property
    def fid(self) -> str:
        return f"{self.file}:{self.function}"


@dataclass
class UnguardedPath:
    """A call-chain from an entry point to a weak function."""

    chain: list[tuple[str, str]]  # [(file, func), ...] entry→...→weak
    depth_limited: bool = False


@dataclass
class ComposedHypothesis:
    weakness: WeaknessRecord
    unguarded_path: UnguardedPath
    hypothesis_text: str
    fids: list[str] = field(default_factory=list)
    verifiable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "weakness": {
                "function": self.weakness.function,
                "file": self.weakness.file,
                "guard_type": self.weakness.guard_type,
                "assumed_property": self.weakness.assumed_property,
                "mechanism": self.weakness.mechanism,
                "guarded_by": list(self.weakness.guarded_by),
                "cwe_class": self.weakness.cwe_class,
            },
            "path": [
                f"{f}:{fn}" for f, fn in self.unguarded_path.chain
            ],
            "depth_limited": self.unguarded_path.depth_limited,
            "hypothesis": self.hypothesis_text,
            "verifiable": self.verifiable,
        }


_VERIFIABLE_GUARD_TYPES = frozenset({
    "bounds", "null_safety", "validation", "sanitisation",
})


def build_weakness_inventory(
    journal_path: Path,
) -> list[WeaknessRecord]:
    """Read weakness records from journal entries."""
    from core.coverage.journal import load_entries

    entries = load_entries(journal_path)
    result: list[WeaknessRecord] = []
    for entry in entries:
        for w in entry.weaknesses or []:
            gt = w.get("guard_type", "")
            if not gt:
                continue
            result.append(WeaknessRecord(
                function=entry.function or "",
                file=entry.file or "",
                guard_type=gt,
                assumed_property=w.get("property", ""),
                mechanism=w.get("mechanism", ""),
                guarded_by=tuple(w.get("guarded_by") or ()),
                cwe_class=w.get("cwe_class"),
                source=w.get("source", "structured_pass"),
            ))
    return result


def _build_journal_index(
    journal_path: Path,
) -> dict[str, list[dict[str, Any]]]:
    """Index journal weaknesses by ``file:function``."""
    from core.coverage.journal import load_entries

    entries = load_entries(journal_path)
    index: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        fid = f"{entry.file}:{entry.function}"
        for w in entry.weaknesses or []:
            index.setdefault(fid, []).append(w)
    return index


def _caller_guards_property(
    caller_fid: str,
    weakness: WeaknessRecord,
    journal_index: dict[str, list[dict[str, Any]]],
    reviewed_fids: set[str],
) -> bool:
    """Does the caller's review show it establishes the guard?

    Returns True (guarded) when the caller was reviewed and does NOT
    have a weakness of the same guard_type mentioning the weak
    function — the review implicitly or explicitly found the property
    is handled.

    Returns False (unguarded) when the caller was never reviewed, or
    when its review produced a same-guard_type weakness about the
    callee (the weakness "passes through").
    """
    if caller_fid not in reviewed_fids:
        return False
    caller_weaknesses = journal_index.get(caller_fid, [])
    weak_func = weakness.function
    for cw in caller_weaknesses:
        if cw.get("guard_type") != weakness.guard_type:
            continue
        mechanism = cw.get("mechanism", "")
        assumed_by = cw.get("assumed_by", "")
        if weak_func in mechanism or weak_func in assumed_by:
            return False
    return True


FuncKey = tuple[str, str]


def find_unguarded_paths(
    weakness: WeaknessRecord,
    reverse_edges: dict[FuncKey, set[FuncKey]],
    entry_points: set[str],
    journal_index: dict[str, list[dict[str, Any]]],
    reviewed_fids: set[str],
    *,
    max_depth: int = 15,
) -> list[UnguardedPath]:
    """Walk backwards from the weakness's function to entry points.

    At each caller:
    - If the caller guards the property → stop this branch (safe).
    - If the caller has a same-guard_type weakness → continue (pass-through).
    - If the caller was never reviewed → continue (conservative).
    - If an entry point is reached → record unguarded path.
    - If depth cap hit → record as depth-limited.
    """
    weak_key: FuncKey = (weakness.file, weakness.function)
    results: list[UnguardedPath] = []

    # BFS backwards: (current_key, path_so_far)
    queue: deque[tuple[FuncKey, list[FuncKey]]] = deque([
        (weak_key, [weak_key]),
    ])
    visited: set[FuncKey] = {weak_key}

    while queue:
        current, path = queue.popleft()
        current_fid = f"{current[0]}:{current[1]}"

        if current_fid in entry_points and current != weak_key:
            results.append(UnguardedPath(
                chain=list(reversed(path)),
            ))
            continue

        if len(path) > max_depth:
            results.append(UnguardedPath(
                chain=list(reversed(path)),
                depth_limited=True,
            ))
            continue

        callers = reverse_edges.get(current, set())
        if not callers and current != weak_key:
            if not entry_points:
                results.append(UnguardedPath(
                    chain=list(reversed(path)),
                ))
            continue

        for caller_key in callers:
            if caller_key in visited:
                continue
            visited.add(caller_key)
            caller_fid = f"{caller_key[0]}:{caller_key[1]}"

            if _caller_guards_property(
                caller_fid, weakness, journal_index, reviewed_fids,
            ):
                continue

            queue.append((caller_key, path + [caller_key]))

    return results


def compose_hypotheses(
    weaknesses: list[WeaknessRecord],
    reverse_edges: dict[FuncKey, set[FuncKey]],
    entry_points: set[str],
    journal_index: dict[str, list[dict[str, Any]]],
    reviewed_fids: set[str],
    *,
    max_depth: int = 15,
    max_hypotheses: int = 50,
) -> list[ComposedHypothesis]:
    """For each weakness, find unguarded paths and produce hypotheses.

    Deduplicates to shortest path per weakness, filters by public
    entry points and verifiable guard types, and caps output.
    """
    all_hypotheses: list[ComposedHypothesis] = []
    seen: set[WeaknessRecord] = set()

    for w in weaknesses:
        if w in seen:
            continue
        seen.add(w)
        paths = find_unguarded_paths(
            w, reverse_edges, entry_points,
            journal_index, reviewed_fids,
            max_depth=max_depth,
        )
        if not paths:
            continue

        # Deduplicate: keep shortest path per weakness
        paths.sort(key=lambda p: len(p.chain))
        best = paths[0]

        verifiable = w.guard_type in _VERIFIABLE_GUARD_TYPES

        path_desc = " → ".join(
            f"{f}:{fn}" for f, fn in best.chain
        )
        text = (
            f"{w.mechanism} in {w.fid}. "
            f"The function assumes {w.assumed_property or w.guard_type} "
            f"is established by the caller, but the path {path_desc} "
            f"reaches it without establishing this guarantee."
        )

        all_hypotheses.append(ComposedHypothesis(
            weakness=w,
            unguarded_path=best,
            hypothesis_text=text,
            fids=[f"{f}:{fn}" for f, fn in best.chain],
            verifiable=verifiable,
        ))

    # Sort: verifiable first, then by path length (shorter = more reachable)
    all_hypotheses.sort(
        key=lambda h: (not h.verifiable, len(h.unguarded_path.chain)),
    )
    return all_hypotheses[:max_hypotheses]


def run_composition(
    journal_path: Path,
    call_graphs: dict[str, Any],
    entry_points: set[str],
    *,
    max_depth: int = 15,
    max_hypotheses: int = 50,
) -> list[ComposedHypothesis]:
    """End-to-end composition: load weaknesses, build graph, compose."""
    from core.inventory.call_graph import build_reverse_edges

    weaknesses = build_weakness_inventory(journal_path)
    if not weaknesses:
        logger.info("composition: no weaknesses in journal")
        return []

    reverse_edges = build_reverse_edges(call_graphs)
    journal_index = _build_journal_index(journal_path)

    reviewed_fids: set[str] = set()
    from core.coverage.journal import load_entries
    for entry in load_entries(journal_path):
        reviewed_fids.add(f"{entry.file}:{entry.function}")

    results = compose_hypotheses(
        weaknesses, reverse_edges, entry_points,
        journal_index, reviewed_fids,
        max_depth=max_depth,
        max_hypotheses=max_hypotheses,
    )
    logger.info(
        "composition: %d weaknesses → %d hypotheses",
        len(weaknesses), len(results),
    )
    return results


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Weakness composition engine",
    )
    parser.add_argument(
        "--journal", required=True,
        help="Path to journal directory or run output dir",
    )
    parser.add_argument(
        "--context-map",
        help="Path to context-map.json (for entry points)",
    )
    parser.add_argument("--max-depth", type=int, default=15)
    parser.add_argument("--max-hypotheses", type=int, default=50)
    args = parser.parse_args()

    journal = Path(args.journal)
    ep: set[str] = set()
    if args.context_map:
        cm = json.loads(Path(args.context_map).read_text())
        from core.audit._util import extract_context_map_set
        ep = extract_context_map_set(cm, "entry_points")

    # Load call graphs from the run's inventory
    from core.inventory.call_graph import FileCallGraph

    cg_path = journal / "call-graph.json"
    cg: dict[str, Any] = {}
    if cg_path.exists():
        raw = json.loads(cg_path.read_text())
        if isinstance(raw, dict):
            for k, v in raw.items():
                if isinstance(v, dict):
                    cg[k] = FileCallGraph.from_dict(v)
                else:
                    cg[k] = v

    results = run_composition(
        journal, cg, ep,
        max_depth=args.max_depth,
        max_hypotheses=args.max_hypotheses,
    )
    json.dump(
        [h.to_dict() for h in results],
        sys.stdout, indent=2,
    )
    print()
