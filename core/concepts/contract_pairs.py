"""Contract pair detection for /audit.

Detects pairs (or groups) of project-defined functions that share a
structural contract — one function's output is another's invariant.
When the LLM reviews one half of a pair and flags a potential bug,
the contract context guides it to check whether the other half
upholds its end before promoting.

Contract kinds
--------------
size_consumer
    A computes a size/count, B uses it as bounds.  Bug class:
    buffer overflow when A and B disagree on iteration logic.

alloc_free
    A acquires a resource, B releases it.  One-to-many: one alloc
    can have many free paths.  Bug class: leak, double-free, UAF.

lock_unlock
    A acquires a lock, B releases it.  One-to-many.  Bug class:
    deadlock (missed unlock on error), data race (missed lock).

ref_unref
    A increments a refcount, B decrements it.  One-to-many.
    Bug class: leak (extra get), UAF (extra put).

init_cleanup
    A initialises/registers, B tears down/unregisters.  One-to-many.
    Bug class: resource leak on teardown, dangling registration.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from itertools import combinations
from typing import Any, TYPE_CHECKING

from core.audit.prompt_defence import sanitise_for_prompt

if TYPE_CHECKING:
    from collections.abc import Sequence


# ── Data model ────────────────────────────────────────────────────────


class ContractKind(str, Enum):
    SIZE_CONSUMER = "size_consumer"
    ALLOC_FREE = "alloc_free"
    LOCK_UNLOCK = "lock_unlock"
    REF_UNREF = "ref_unref"
    INIT_CLEANUP = "init_cleanup"
    DISCOVERED = "discovered"


@dataclass
class ContractPartner:
    file: str
    function: str
    line: int = 0
    role: str = ""  # "producer" or "consumer"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "role": self.role,
        }


@dataclass
class ContractPairGroup:
    """A group of functions sharing a structural contract."""

    group_id: str
    contract_kind: ContractKind
    noun: str
    producers: list[ContractPartner] = field(default_factory=list)
    consumers: list[ContractPartner] = field(default_factory=list)
    invariant: str = ""
    callers_evidence: list[dict[str, Any]] = field(default_factory=list)
    discovery_source: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "group_id": self.group_id,
            "contract_kind": self.contract_kind.value,
            "noun": self.noun,
            "producers": [p.to_dict() for p in self.producers],
            "consumers": [c.to_dict() for c in self.consumers],
            "invariant": self.invariant,
        }
        if self.callers_evidence:
            d["callers_evidence"] = self.callers_evidence
        if self.discovery_source:
            d["discovery_source"] = self.discovery_source
        return d

    def all_partners(self) -> list[ContractPartner]:
        return self.producers + self.consumers

    def partners_of(self, function: str) -> list[ContractPartner]:
        """Return the contract partners of *function* (the other side)."""
        is_producer = any(p.function == function for p in self.producers)
        is_consumer = any(c.function == function for c in self.consumers)
        if is_producer:
            return list(self.consumers)
        if is_consumer:
            return list(self.producers)
        return []

    def role_of(self, function: str) -> str:
        if any(p.function == function for p in self.producers):
            return "producer"
        if any(c.function == function for c in self.consumers):
            return "consumer"
        return ""


# ── Verb tables ───────────────────────────────────────────────────────

# Each spec: (producer_verbs, consumer_verbs, contract_kind).
# A pair requires BOTH a producer and consumer with the same noun.

_CONTRACT_SPECS: list[tuple[frozenset[str], frozenset[str], ContractKind]] = [
    # size_consumer: count/measure → pull/fill/write
    (
        frozenset({
            "count", "calc", "calculate", "measure", "estimate",
            "sizeof", "num",
        }),
        frozenset({
            "pull", "fill", "consume", "emit", "drain", "flush",
        }),
        ContractKind.SIZE_CONSUMER,
    ),
    # alloc_free
    (
        frozenset({
            "alloc", "create", "new", "make", "construct", "spawn",
        }),
        frozenset({
            "free", "destroy", "delete", "dealloc", "dispose",
            "reclaim", "discard",
        }),
        ContractKind.ALLOC_FREE,
    ),
    # open_close (variant of alloc_free)
    (
        frozenset({"open"}),
        frozenset({"close"}),
        ContractKind.ALLOC_FREE,
    ),
    # lock_unlock
    (
        frozenset({"lock"}),
        frozenset({"unlock"}),
        ContractKind.LOCK_UNLOCK,
    ),
    # ref_unref  — "get"/"put" only paired with each other to avoid noise
    (
        frozenset({"get", "ref", "retain", "grab", "incref", "addref"}),
        frozenset({"put", "unref", "drop", "decref"}),
        ContractKind.REF_UNREF,
    ),
    # init_cleanup
    (
        frozenset({
            "init", "setup", "register", "attach", "connect",
            "mount", "bind", "start", "enable", "install", "load",
        }),
        frozenset({
            "exit", "cleanup", "fini", "deinit", "uninit", "teardown",
            "unregister", "deregister", "detach", "disconnect",
            "unmount", "unbind", "stop", "disable", "uninstall",
            "unload",
        }),
        ContractKind.INIT_CLEANUP,
    ),
]

# Nouns that are too generic to form meaningful pairs.
_NOISE_NOUNS: frozenset[str] = frozenset({
    "", "a", "an", "the", "it", "s", "x", "y",
    "data", "value", "info", "tmp", "temp",
    "arg", "args", "param", "params",
    "result", "ret", "err", "error", "ctx",
    "name", "key", "msg", "buf", "str", "val",
    "state", "status", "flag", "flags", "type",
    "table", "list", "map", "set", "node",
    "item", "entry", "obj", "object", "self",
    "all", "one", "next", "prev", "cur", "new",
    "in", "out", "src", "dst", "desc",
})

# Minimum noun length to avoid matching single-character remnants.
_MIN_NOUN_LEN = 2


# ── Verb extraction ──────────────────────────────────────────────────

def _all_verbs() -> frozenset[str]:
    """Collect every verb across all specs (for quick membership test)."""
    verbs: set[str] = set()
    for producers, consumers, _ in _CONTRACT_SPECS:
        verbs |= producers
        verbs |= consumers
    return frozenset(verbs)


_ALL_VERBS = _all_verbs()


_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _split_name(name: str) -> list[str]:
    """Split a function name into lowercase word parts.

    Handles underscore_case, camelCase, and PascalCase.
    """
    stripped = name.lstrip("_")
    if "_" in stripped:
        return [p.lower() for p in stripped.split("_") if p]
    parts = _CAMEL_RE.sub("_", stripped).split("_")
    return [p.lower() for p in parts if p]


def _extract_verb_noun(
    name: str,
    specs: (
        list[tuple[frozenset[str], frozenset[str], ContractKind]] | None
    ) = None,
) -> list[tuple[str, str, ContractKind, str]]:
    """Extract (verb, noun, contract_kind, role) from a function name.

    Tries each known verb as a contiguous word-boundary segment in the
    word parts of *name*.  Handles underscore_case, camelCase, and
    PascalCase.  Returns all matches (a function may match multiple
    specs — disambiguation happens when we look for partner existence).

    *specs* overrides the default ``_CONTRACT_SPECS``.  Pass a merged
    list (static + discovered) to use project-specific vocabulary.
    """
    parts = _split_name(name)
    if len(parts) < 2:
        return []

    results: list[tuple[str, str, ContractKind, str]] = []

    for producers, consumers, kind in (specs or _CONTRACT_SPECS):
        for verb_set, role in ((producers, "producer"), (consumers, "consumer")):
            for verb in verb_set:
                verb_parts = verb.split("_")
                vlen = len(verb_parts)
                for i in range(len(parts) - vlen + 1):
                    if parts[i : i + vlen] == verb_parts:
                        noun_parts = parts[:i] + parts[i + vlen:]
                        noun = "_".join(noun_parts)
                        if (
                            len(noun) >= _MIN_NOUN_LEN
                            and noun not in _NOISE_NOUNS
                        ):
                            results.append((verb, noun, kind, role))

    return results


# ── Verb discovery ──────────────────────────────────────────────────


def discover_project_verbs(
    functions: Sequence[dict[str, Any]],
    *,
    min_nouns: int = 2,
    max_verb_frequency: float = 0.15,
) -> list[tuple[frozenset[str], frozenset[str], ContractKind]]:
    """Mine verb pairs from function naming conventions.

    Instead of relying solely on the static verb table, this analyses
    the function inventory to find verbs that consistently pair across
    multiple nouns.

    **Anchored discovery** — one verb is already in the static table,
    the other is project-specific.  Example: ``alloc_skb`` is known;
    ``kfree_skb``, ``kfree_msg``, ``kfree_sock`` all share nouns with
    known producers → ``kfree`` is discovered as an alloc_free consumer.

    **Unanchored discovery** — neither verb is in the static table but
    they co-occur across *min_nouns*+ nouns.  Example: ``begin_transaction``
    / ``end_transaction`` AND ``begin_session`` / ``end_session`` →
    ``begin``/``end`` is a discovered pair (kind = DISCOVERED).

    Words that appear as the first part of >*max_verb_frequency* of
    functions are treated as module prefixes (not verbs) and rejected.
    """
    # Reject words used as first-word in too many functions (module
    # prefixes like ``af``, ``aead``, ``skcipher``).
    first_word_counts: dict[str, int] = defaultdict(int)
    total_with_parts = 0
    for func in functions:
        parts = _split_name(func.get("name", ""))
        if len(parts) >= 2:
            first_word_counts[parts[0]] += 1
            total_with_parts += 1

    prefix_words: set[str] = set()
    if total_with_parts > 0:
        # Floor of 3: never treat a verb that appears ≤3 times as a
        # prefix, even in tiny inventories.
        cap = max(min(total_with_parts * max_verb_frequency, 10), 3)
        prefix_words = {
            w for w, c in first_word_counts.items() if c > cap
        }

    noun_to_verbs: dict[str, set[str]] = defaultdict(set)
    for func in functions:
        parts = _split_name(func.get("name", ""))
        if len(parts) < 2:
            continue
        verb = parts[0]
        if verb in prefix_words:
            continue
        noun = "_".join(parts[1:])
        if len(noun) >= _MIN_NOUN_LEN and noun not in _NOISE_NOUNS:
            noun_to_verbs[noun].add(verb)

    pair_nouns: dict[tuple[str, str], set[str]] = defaultdict(set)
    for noun, verbs in noun_to_verbs.items():
        for v1, v2 in combinations(sorted(verbs), 2):
            pair_nouns[(v1, v2)].add(noun)

    results: list[tuple[frozenset[str], frozenset[str], ContractKind]] = []
    seen: set[tuple[str, str]] = set()

    for (v1, v2), nouns in pair_nouns.items():
        if len(nouns) < min_nouns:
            continue

        v1_role: tuple[ContractKind, str] | None = None
        v2_role: tuple[ContractKind, str] | None = None
        for producers, consumers, kind in _CONTRACT_SPECS:
            if v1 in producers:
                v1_role = (kind, "producer")
            elif v1 in consumers:
                v1_role = (kind, "consumer")
            if v2 in producers:
                v2_role = (kind, "producer")
            elif v2 in consumers:
                v2_role = (kind, "consumer")

        if v1_role and v2_role:
            continue
        if v1_role and not v2_role:
            kind, role = v1_role
            opposite = "consumer" if role == "producer" else "producer"
            key = (v2, opposite)
            if key not in seen:
                seen.add(key)
                if opposite == "producer":
                    results.append((frozenset({v2}), frozenset(), kind))
                else:
                    results.append((frozenset(), frozenset({v2}), kind))
        elif v2_role and not v1_role:
            kind, role = v2_role
            opposite = "consumer" if role == "producer" else "producer"
            key = (v1, opposite)
            if key not in seen:
                seen.add(key)
                if opposite == "producer":
                    results.append((frozenset({v1}), frozenset(), kind))
                else:
                    results.append((frozenset(), frozenset({v1}), kind))
        else:
            key_pair = (v1, v2)
            if key_pair not in seen:
                seen.add(key_pair)
                results.append((
                    frozenset({v1}),
                    frozenset({v2}),
                    ContractKind.DISCOVERED,
                ))

    return results


# ── Call-graph analysis ─────────────────────────────────────────────


def _enrich_with_call_graph(
    groups: list[ContractPairGroup],
    call_graphs: dict[str, Any],
) -> None:
    """Add caller co-occurrence evidence to existing contract pairs.

    For each group, finds callers that invoke both a producer and a
    consumer, recording the call sites as structural evidence.
    """
    callee_callers: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for filepath, cg in call_graphs.items():
        for call in cg.get("calls", []):
            caller = call.get("caller", "")
            chain = call.get("chain", [])
            callee = chain[-1] if chain else ""
            if caller and callee:
                callee_callers[callee].append(
                    (filepath, caller, call.get("line", 0)),
                )

    for group in groups:
        prod_names = {p.function for p in group.producers}
        cons_names = {c.function for c in group.consumers}

        evidence: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for pname in prod_names:
            for fpath, caller, line in callee_callers.get(pname, []):
                key = f"{fpath}\x00{caller}"
                evidence.setdefault(key, {"producers": [], "consumers": []})
                evidence[key]["producers"].append(
                    {"function": pname, "line": line},
                )
        for cname in cons_names:
            for fpath, caller, line in callee_callers.get(cname, []):
                key = f"{fpath}\x00{caller}"
                evidence.setdefault(key, {"producers": [], "consumers": []})
                evidence[key]["consumers"].append(
                    {"function": cname, "line": line},
                )

        for caller_key, ev in evidence.items():
            if ev["producers"] and ev["consumers"]:
                fpath, caller = caller_key.split("\x00", 1)
                group.callers_evidence.append({
                    "caller_file": fpath,
                    "caller": caller,
                    "producer_calls": ev["producers"],
                    "consumer_calls": ev["consumers"],
                })


def _discover_callgraph_pairs(
    functions: list[dict[str, Any]],
    call_graphs: dict[str, Any],
    already_paired: set[str] | None = None,
    *,
    min_callers: int = 2,
    max_caller_fanout: int = 12,
    min_jaccard: float = 0.3,
) -> list[ContractPairGroup]:
    """Discover function pairs from call-graph co-occurrence alone.

    Finds pairs of functions that are consistently invoked together by
    multiple callers, even when their names give no signal.  This is
    the ``foo``/``bar`` detector — pure structural discovery.

    Filters out utility functions (called from >*max_caller_fanout*
    callers) and pairs with low Jaccard similarity (co-occurrence is
    incidental, not structural).  Skips pairs where both functions
    are *already_paired* by name-based detection.
    """
    func_names = {f.get("name", "") for f in functions if f.get("name")}
    func_lookup: dict[str, dict[str, Any]] = {}
    for f in functions:
        name = f.get("name", "")
        if name:
            func_lookup[name] = f

    caller_to_callees: dict[tuple[str, str], set[str]] = defaultdict(set)
    callee_to_callers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for filepath, cg in call_graphs.items():
        for call in cg.get("calls", []):
            caller = call.get("caller", "")
            chain = call.get("chain", [])
            callee = chain[-1] if chain else ""
            if caller and callee and callee in func_names:
                key = (filepath, caller)
                caller_to_callees[key].add(callee)
                callee_to_callers[callee].add(key)

    # Skip utility functions called from too many callers.
    utility_funcs = {
        f for f, callers in callee_to_callers.items()
        if len(callers) > max_caller_fanout
    }

    pair_callers: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(
        list,
    )
    for caller_key, callees in caller_to_callees.items():
        filtered = sorted(callees - utility_funcs)
        for a, b in combinations(filtered, 2):
            pair_callers[(a, b)].append(caller_key)

    already = already_paired or set()
    results: list[ContractPairGroup] = []
    for (a, b), callers in pair_callers.items():
        if len(callers) < min_callers:
            continue
        if a in already and b in already:
            continue

        # Jaccard similarity: |callers_a ∩ callers_b| / |callers_a ∪ callers_b|
        callers_a = callee_to_callers.get(a, set())
        callers_b = callee_to_callers.get(b, set())
        intersection = len(callers_a & callers_b)
        union = len(callers_a | callers_b)
        if union > 0 and intersection / union < min_jaccard:
            continue

        fa = func_lookup.get(a, {})
        fb = func_lookup.get(b, {})

        group = ContractPairGroup(
            group_id=f"callgraph:{a}:{b}",
            contract_kind=ContractKind.DISCOVERED,
            noun="",
            producers=[ContractPartner(
                file=fa.get("file", ""),
                function=a,
                line=fa.get("line", 0) or fa.get("line_start", 0),
                role="partner",
            )],
            consumers=[ContractPartner(
                file=fb.get("file", ""),
                function=b,
                line=fb.get("line", 0) or fb.get("line_start", 0),
                role="partner",
            )],
            invariant=_INVARIANT_TEMPLATES[ContractKind.DISCOVERED],
            discovery_source="call_graph",
        )
        results.append(group)

    return results


# ── Persistence ─────────────────────────────────────────────────────


def save_project_verbs(
    path: Any,
    discovered: list[tuple[frozenset[str], frozenset[str], ContractKind]],
    callgraph_pairs: list[ContractPairGroup] | None = None,
) -> None:
    """Persist discovered vocabulary to a project directory.

    Writes ``verb-contracts.json`` so subsequent runs start with the
    project's learned vocabulary instead of re-discovering it.
    """
    import json
    from pathlib import Path

    out = Path(path) / "verb-contracts.json"
    # Deterministic order: the caller dedups via a set (frozenset
    # tuples), whose iteration order varies per process — an otherwise
    # unchanged vocabulary rewrote verb-contracts.json in a different
    # order every run, defeating diffing and content-hash comparisons.
    data: dict[str, Any] = {
        "discovered_verbs": sorted(
            (
                {
                    "producers": sorted(prods),
                    "consumers": sorted(cons),
                    "kind": kind.value,
                }
                for prods, cons, kind in discovered
            ),
            key=lambda e: (e["producers"], e["consumers"], e["kind"]),
        ),
    }
    if callgraph_pairs:
        data["callgraph_pairs"] = [g.to_dict() for g in callgraph_pairs]
    # Atomic replace: verb-contracts.json seeds every subsequent run's
    # vocabulary — a torn write would silently reset the project's
    # learned verbs (the loader treats unparseable JSON as absent).
    from core.atomic_fs import write_text_atomically
    write_text_atomically(out, json.dumps(data, indent=2))


def _load_verbs_from_file(
    vf: Any,
) -> list[tuple[frozenset[str], frozenset[str], ContractKind]]:
    """Parse verb-contracts.json into a list of verb specs."""
    from pathlib import Path

    from core.json import load_json

    vf = Path(vf)
    if not vf.is_file():
        return []
    data = load_json(vf, max_bytes=8 * 1024 * 1024)
    if not isinstance(data, dict):
        return []

    results: list[tuple[frozenset[str], frozenset[str], ContractKind]] = []
    for entry in data.get("discovered_verbs", []):
        try:
            kind = ContractKind(entry["kind"])
        except (KeyError, ValueError):
            continue
        producers = entry.get("producers", [])
        consumers = entry.get("consumers", [])
        if not isinstance(producers, list) or not isinstance(consumers, list):
            continue
        if not all(isinstance(v, str) for v in producers):
            continue
        if not all(isinstance(v, str) for v in consumers):
            continue
        results.append((
            frozenset(producers),
            frozenset(consumers),
            kind,
        ))
    return results


def load_project_verbs(
    path: Any,
) -> list[tuple[frozenset[str], frozenset[str], ContractKind]]:
    """Load previously discovered vocabulary from a project directory.

    Returns an empty list if no saved vocabulary exists.
    """
    from pathlib import Path

    return _load_verbs_from_file(Path(path) / "verb-contracts.json")


def load_project_verbs_with_siblings(
    path: Any,
) -> list[tuple[frozenset[str], frozenset[str], ContractKind]]:
    """Load verb vocabulary, searching sibling run directories if needed.

    First checks *path* itself, then walks sibling directories under
    the same parent (other runs in the same project workspace) in
    reverse-sorted order (newest first).  This enables cross-run
    vocabulary transfer within a project.

    Returns an empty list if no saved vocabulary exists anywhere.
    """
    from pathlib import Path

    p = Path(path)
    result = _load_verbs_from_file(p / "verb-contracts.json")
    if result:
        return result

    parent = p.parent
    if parent.exists():
        for sibling in sorted(parent.iterdir(), reverse=True):
            if sibling == p or sibling.is_symlink() or not sibling.is_dir():
                continue
            result = _load_verbs_from_file(sibling / "verb-contracts.json")
            if result:
                return result

    return []


# ── Detection ─────────────────────────────────────────────────────────


def _name_based_pairs(
    functions: list[dict[str, Any]],
    specs: list[tuple[frozenset[str], frozenset[str], ContractKind]],
    *,
    cross_file: bool = True,
    discovery_source: str = "",
) -> list[ContractPairGroup]:
    """Core name-based detection against a verb table (static or extended)."""
    buckets: dict[
        tuple[str, ContractKind],
        list[tuple[dict[str, Any], str, str]],
    ] = {}

    for func in functions:
        name = func.get("name", "")
        if not name:
            continue
        for verb, noun, kind, role in _extract_verb_noun(name, specs):
            key = (noun, kind)
            buckets.setdefault(key, []).append((func, verb, role))

    results: list[ContractPairGroup] = []
    seen_ids: set[str] = set()

    for (noun, kind), members in buckets.items():
        producers = [
            (func, verb) for func, verb, role in members if role == "producer"
        ]
        consumers = [
            (func, verb) for func, verb, role in members if role == "consumer"
        ]

        if not producers or not consumers:
            continue

        if not cross_file:
            prod_files = {f.get("file", "") for f, _ in producers}
            cons_files = {f.get("file", "") for f, _ in consumers}
            shared_files = prod_files & cons_files
            if not shared_files:
                continue
            producers = [
                (f, v) for f, v in producers
                if f.get("file", "") in shared_files
            ]
            consumers = [
                (f, v) for f, v in consumers
                if f.get("file", "") in shared_files
            ]
            if not producers or not consumers:
                continue

        group_id = f"contract:{kind.value}:{noun}"
        if group_id in seen_ids:
            continue
        seen_ids.add(group_id)

        group = ContractPairGroup(
            group_id=group_id,
            contract_kind=kind,
            noun=noun,
            producers=[
                ContractPartner(
                    file=f.get("file", ""),
                    function=f.get("name", ""),
                    line=f.get("line", 0) or f.get("line_start", 0),
                    role="producer",
                )
                for f, _ in producers
            ],
            consumers=[
                ContractPartner(
                    file=f.get("file", ""),
                    function=f.get("name", ""),
                    line=f.get("line", 0) or f.get("line_start", 0),
                    role="consumer",
                )
                for f, _ in consumers
            ],
            invariant=_INVARIANT_TEMPLATES.get(kind, _INVARIANT_TEMPLATES[ContractKind.DISCOVERED]),
            discovery_source=discovery_source,
        )
        results.append(group)

    return results


def detect_contract_pairs(
    functions: list[dict[str, Any]],
    *,
    cross_file: bool = True,
    call_graphs: dict[str, Any] | None = None,
    project_dir: Any | None = None,
) -> list[ContractPairGroup]:
    """Detect contract pairs among project functions.

    Three layers of detection, each composable:

    1. **Static verb table** — canned vocabulary for cold-start speed.
    2. **Verb discovery** — mines project-specific verbs from naming
       conventions (e.g. ``kfree``, ``begin``/``end``).  Persisted to
       *project_dir* so subsequent runs have the vocabulary ready.
    3. **Call-graph co-occurrence** — finds ``foo``/``bar`` pairs from
       caller patterns alone, when names give no signal.

    After name-based detection (layers 1+2), call-graph evidence is
    attached to ALL discovered pairs (layer 3 + reinforcement).

    Args:
        functions: List of dicts with at least ``name``, ``file``, and
            optionally ``line`` / ``line_start``.
        cross_file: If False, only pair functions within the same file.
        call_graphs: Per-file call graph dicts from the checklist.
            Each value has a ``calls`` list of ``{caller, chain, line}``
            dicts.  Enables call-graph enrichment and co-occurrence
            discovery.
        project_dir: Path to the project output directory.  If given,
            discovered verbs are loaded from (and saved to)
            ``verb-contracts.json`` in this directory.

    Returns:
        List of :class:`ContractPairGroup` objects.
    """
    if not functions:
        return []

    # Layer 1: static verb table.
    results = _name_based_pairs(
        functions, _CONTRACT_SPECS, cross_file=cross_file,
        discovery_source="static",
    )
    seen_ids = {g.group_id for g in results}

    # Layer 2: verb discovery — learn project-specific verbs.
    prior_verbs = (
        load_project_verbs_with_siblings(project_dir)
        if project_dir else []
    )
    fresh_verbs = discover_project_verbs(functions)
    all_discovered = prior_verbs + fresh_verbs

    if all_discovered:
        extended_specs = list(_CONTRACT_SPECS) + all_discovered
        discovered_pairs = _name_based_pairs(
            functions, extended_specs, cross_file=cross_file,
            discovery_source="verb_discovery",
        )
        for g in discovered_pairs:
            if g.group_id not in seen_ids:
                results.append(g)
                seen_ids.add(g.group_id)

    # Layer 3: call-graph co-occurrence.
    cg_pairs: list[ContractPairGroup] = []
    if call_graphs:
        already_paired = set()
        for g in results:
            for p in g.all_partners():
                already_paired.add(p.function)
        cg_pairs = _discover_callgraph_pairs(
            functions, call_graphs, already_paired,
        )
        for g in cg_pairs:
            if g.group_id not in seen_ids:
                results.append(g)
                seen_ids.add(g.group_id)

        # Enrich ALL pairs (layers 1+2+3) with caller evidence.
        _enrich_with_call_graph(results, call_graphs)

    if project_dir and (fresh_verbs or cg_pairs):
        merged = list({
            (frozenset(p), frozenset(c), k)
            for p, c, k in prior_verbs + fresh_verbs
        })
        try:
            save_project_verbs(project_dir, merged, callgraph_pairs=cg_pairs)
        except OSError:
            pass

    return results


def build_contract_index(
    pairs: list[ContractPairGroup],
) -> dict[str, list[ContractPairGroup]]:
    """Build a lookup from function name → contract pair groups."""
    index: dict[str, list[ContractPairGroup]] = {}
    for group in pairs:
        for partner in group.all_partners():
            index.setdefault(partner.function, []).append(group)
    return index


# ── Prompt formatting ─────────────────────────────────────────────────


def format_contract_pairs_for_prompt(
    groups: Sequence[ContractPairGroup],
    current_function: str,
) -> str:
    """Render contract pair context for a specific function.

    Tells the LLM which contract partners exist and what invariant
    they share, so it can check both sides before flagging a bug.
    """
    if not groups:
        return ""

    lines = [
        "### Contract partners",
        "",
        "This function is part of a contract pair.  Before flagging a "
        "bug in this function, check whether the partner function "
        "upholds its end of the contract.",
        "",
    ]

    for group in groups:
        kind_label = _KIND_LABELS.get(group.contract_kind, group.contract_kind.value)
        role = group.role_of(current_function)
        partners = group.partners_of(current_function)

        if not partners:
            continue

        partner_names = ", ".join(
            f"`{sanitise_for_prompt(p.function, content_type='name')}()`"
            f" ({sanitise_for_prompt(p.file, content_type='path')})"
            if p.file
            else f"`{sanitise_for_prompt(p.function, content_type='name')}()`"
            for p in partners
        )

        role_desc = role if role in ("producer", "consumer") else "partner"

        lines.append(
            f"- **{kind_label}** — this function is the {role_desc}; "
            f"partner(s): {partner_names}"
        )
        lines.append(f"  Invariant: {group.invariant}")

        if group.callers_evidence:
            for ev in group.callers_evidence:
                caller = sanitise_for_prompt(
                    ev["caller"], content_type="name",
                )
                caller_file = sanitise_for_prompt(
                    ev.get("caller_file", ""), content_type="path",
                )
                prod_lines = ", ".join(
                    str(pc.get("line", "?"))
                    for pc in ev.get("producer_calls", [])
                )
                cons_lines = ", ".join(
                    str(cc.get("line", "?"))
                    for cc in ev.get("consumer_calls", [])
                )
                if caller_file:
                    lines.append(
                        f"  Call-graph: `{caller}()` in {caller_file} "
                        f"invokes producer (line {prod_lines}) and "
                        f"consumer (line {cons_lines})"
                    )
                else:
                    lines.append(
                        f"  Call-graph: `{caller}()` invokes both "
                        f"(lines {prod_lines}, {cons_lines})"
                    )

        lines.append("")

    return "\n".join(lines)


# ── Invariant templates ───────────────────────────────────────────────

_INVARIANT_TEMPLATES: dict[ContractKind, str] = {
    ContractKind.SIZE_CONSUMER: (
        "The producer computes how many entries/bytes the consumer will "
        "write.  Before flagging the consumer for unbounded writes, "
        "verify that the producer's traversal logic matches — if they "
        "walk the same data structure with the same conditions, the "
        "consumer cannot exceed the computed count."
    ),
    ContractKind.ALLOC_FREE: (
        "The producer acquires a resource; the consumer(s) release it.  "
        "One-to-many: multiple code paths may free the same resource.  "
        "Before flagging a leak or double-free, check whether every "
        "path through the producer reaches exactly one consumer."
    ),
    ContractKind.LOCK_UNLOCK: (
        "The producer acquires a lock; the consumer(s) release it.  "
        "Before flagging a missing unlock, check ALL exit paths "
        "(including error and early-return paths) for a matching "
        "release."
    ),
    ContractKind.REF_UNREF: (
        "The producer increments a reference count; the consumer(s) "
        "decrement it.  Before flagging a refcount leak or UAF, verify "
        "that every increment has exactly one matching decrement on "
        "every path."
    ),
    ContractKind.INIT_CLEANUP: (
        "The producer initialises or registers a resource; the "
        "consumer(s) tear it down or unregister.  Before flagging "
        "incomplete cleanup, check whether the consumer undoes "
        "everything the producer sets up."
    ),
    ContractKind.DISCOVERED: (
        "These functions are consistently used together (discovered "
        "from naming conventions or call-graph co-occurrence).  Before "
        "flagging a bug in one, check whether its partner provides the "
        "invariant or guarantee you think is missing."
    ),
}

_KIND_LABELS: dict[ContractKind, str] = {
    ContractKind.SIZE_CONSUMER: "Size/consumer contract",
    ContractKind.ALLOC_FREE: "Alloc/free contract",
    ContractKind.LOCK_UNLOCK: "Lock/unlock contract",
    ContractKind.REF_UNREF: "Ref/unref contract",
    ContractKind.INIT_CLEANUP: "Init/cleanup contract",
    ContractKind.DISCOVERED: "Discovered contract",
}
