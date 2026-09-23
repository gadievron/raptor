"""Project verb-pair mining from function naming conventions.

Feeds /audit's consistency dimensions
(``core.audit.consistency_dimensions``): the discovered
producer/consumer verb pairs bind same-noun function families
(``begin_session``/``end_session``) so consistency review can group
them. Verbs come from the static contract table plus per-project
discovery over the function inventory — no hardcoded project APIs.

Contract kinds (the static table's vocabulary)
----------------------------------------------
size_consumer
    A computes a size/count, B uses it as bounds.

alloc_free
    A acquires a resource, B releases it.

lock_unlock
    A acquires a lock, B releases it.

ref_unref
    A increments a refcount, B decrements it.

init_cleanup
    A initialises/registers, B tears down/unregisters.

This module once carried a full contract-pair detection, persistence
(``verb-contracts.json``), call-graph enrichment, and prompt-formatting
surface. That surface was retired: no production path ever called it,
so its documented /audit prompt integration never ran, and its
call-graph pair discovery materialised C(K, 2) pair groups per caller
before any filter — hundreds of MiB at a single wide dispatcher, which
an untrusted scanned repo controls. Re-introducing detection must
bound per-caller fanout BEFORE generating combinations and route
persistence through the run pin (the retired sibling scan walked
cross-target run dirs).
"""

from __future__ import annotations

import re
from collections import defaultdict
from enum import Enum
from itertools import combinations
from typing import TYPE_CHECKING, Any

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


# ── Name splitting ───────────────────────────────────────────────────

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



# ── Verb discovery ───────────────────────────────────────────────────


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
