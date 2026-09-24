"""Function matching across two RE databases (bindiff-class).

`raptor-ghidra diff` matched functions by NAME, which dies exactly
where diffing matters: stripped binaries, renamed statics,
compiler-shifted addresses. This module matches functions by a
cascade of tiers, each consuming the residue of the previous, every
pair carrying its tier and score:

  1. exact name              (unique, non-auto-named on both sides)
  2. decompilation hash      (normalized: whitespace, hex constants,
                              auto-names and addresses masked)
  3. anchor fingerprints     (referenced string VALUES, then
                              imported-callee name multisets — both
                              survive stripping and rebasing)
  4. call-graph propagation  (matched neighbors vote for the
                              remaining candidates, to fixpoint)
  5. decompilation similarity (token-shingle Jaccard, unique best
                              with margin on BOTH sides, bounded
                              pairwise work)

Ambiguity is never guessed away: a tier only matches when its key is
UNIQUE on both sides (or, for tiers 4–5, when exactly one candidate
wins with margin). Unmatched functions are reported, not forced.

Residual limits (inherent to fingerprint matching, not fixable
mechanically): when a function's true counterpart is ABSENT — deleted,
inlined away, or consumed by an earlier wrong pair — a surviving
sibling with the same fingerprint can inherit its identity ("unique"
degrades to "only one left"). Size gates on tiers 2–3, the evidence
floor on tier 4, and the two-sided margin on tier 5 shrink this
window; the tier + score provenance on every pair is the consumer's
skepticism signal. String and import anchors are attacker-copyable:
a hostile NEW binary can plant an old function's strings to steal its
identity — the matched diff still compares the pair's bodies, so the
theft shows as a change, not silence.

Inputs are attacker-derived (names, decompilation, string values from
the binary): emitted names are clipped and control-scrubbed,
adjacency is deduplicated, shingling is token-capped, and the
pairwise tier is work-bounded so a hostile database cannot turn
matching into a CPU sink.
"""

from __future__ import annotations

import logging
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .model import REDatabase, REFunction

# Similarity primitives live in packages.ghidra.similarity (one home,
# two consumers: this 1:1 cascade and many-to-many peer clustering).
# Bound here under the historical private names so every internal
# call site keeps working unchanged; other consumers (the diff path,
# clustering) import the seam directly.
from .similarity import (
    decomp_hash as _decomp_hash,
    jaccard as _jaccard,
    shingles as _shingles,
)

logger = logging.getLogger(__name__)

_MAX_NAME_CHARS = 200
#: Pairwise-comparison budget for the similarity tier — beyond this
#: the tier stops with a loud note rather than melting the CPU.
_MAX_PAIRWISE = 250_000
#: Work budget for the similarity tier: Σ set-elements touched across
#: all pairwise comparisons. The pair-count budget alone under-counts
#: when a hostile database pads every decompilation to the shingle
#: cap.
_MAX_SIM_WORK = 50_000_000
#: Similarity thresholds: a candidate must clear ABS and beat the
#: runner-up by MARGIN — measured from BOTH sides — to match.
_SIM_ABS = 0.7
_SIM_MARGIN = 0.1
#: Minimum decompilation similarity for a tier-4 candidate when both
#: sides carry decompilation — matched-neighbor topology alone cannot
#: tell a renamed function from its replacement.
_T4_SIM_FLOOR = 0.25
#: Size tolerance for tier 2-4 candidates (either bound).
_SIZE_RATIO = 2.0
_SIZE_SLACK = 64
#: Extra full-pool sweeps after the tier-4 worklist drains (candidate
#: sets can shrink non-locally when a competing match consumes a
#: candidate); bounded so a hostile graph cannot force unbounded
#: re-scans. Candidate-ladder topologies needing one sweep per stage
#: exist, so exhaustion is reported, not silent.
_T4_MAX_SWEEPS = 32

_CONTROL = re.compile(
    "[\\x00-\\x1f\\x7f-\\x9f"          # C0/C1 control (incl. ESC)
    "\\u200b-\\u200f\\u2028\\u2029"     # zero-width, marks, line/para sep
    "\\u202a-\\u202e\\u2066-\\u2069"    # bidi embedding/override/isolate
    "\\ufeff]")
#: Auto-generated name shapes across engines. Not every importer sets
#: is_auto_named (r2 leaves it False on "fcn.00001234"), and an
#: address-derived name matching across two builds is coincidence,
#: not identity. Kept a superset of parser._looks_auto_named — the
#: predicate below also consults it so the two lists cannot drift.
_AUTO_NAME_FULL = re.compile(
    r"^(?:thunk_FUN|j_FUN|FUN|DAT|LAB|SUB|loc|fcn|sub|switchD|caseD)"
    r"[._][0-9a-fA-Fx._]+$"
    r"|^(?:entry|case|switch)\.\S*$"
    r"|^Ordinal_\d+$")


def _clip(text: object, limit: int = _MAX_NAME_CHARS) -> str:
    """Clip and control-scrub attacker-derived text for emission.

    Names flow into JSON artifacts an operator will `jq` straight to
    a terminal — ESC sequences and newlines are scrubbed here, at the
    single emission chokepoint.
    """
    s = _CONTROL.sub(" ", str(text or ""))
    return s if len(s) <= limit else s[:limit] + "…"


def _is_auto_named(func: REFunction) -> bool:
    if func.is_auto_named:
        return True
    name = str(func.name or "")
    if _AUTO_NAME_FULL.match(name):
        return True
    from .parser import _looks_auto_named
    return _looks_auto_named(name)


@dataclass
class _Side:
    """Per-database feature index (built once)."""

    db: REDatabase
    funcs: List[REFunction] = field(default_factory=list)
    by_addr: Dict[int, REFunction] = field(default_factory=dict)
    callers: Dict[int, FrozenSet[int]] = field(default_factory=dict)
    callees: Dict[int, FrozenSet[int]] = field(default_factory=dict)
    string_refs: Dict[int, FrozenSet[str]] = field(default_factory=dict)
    self_calls: FrozenSet[int] = frozenset()
    import_callees: Dict[int, Tuple[str, ...]] = field(
        default_factory=dict)
    decomp_hashes: Dict[int, str] = field(default_factory=dict)
    dropped_duplicates: int = 0
    _shingle_cache: Dict[int, FrozenSet[str]] = field(
        default_factory=dict)

    def shingles(self, addr: int) -> FrozenSet[str]:
        cached = self._shingle_cache.get(addr)
        if cached is None:
            cached = _shingles(self.by_addr[addr])
            self._shingle_cache[addr] = cached
        return cached

    def neighbors(self, addr: int) -> FrozenSet[int]:
        return self.callers.get(addr, frozenset()) \
            | self.callees.get(addr, frozenset())


def _build_side(db: REDatabase) -> _Side:
    side = _Side(db=db)
    side.funcs = sorted(
        (f for f in db.functions
         if isinstance(f.address, int)
         and not isinstance(f.address, bool)),
        key=lambda f: f.address,
    )
    for f in side.funcs:
        side.by_addr.setdefault(f.address, f)
    # functions shadowed by an earlier entry at the same address are
    # invisible to the whole cascade — surfaced as a note, not lost
    side.dropped_duplicates = len(side.funcs) - len(side.by_addr)

    # containment index (sized functions only)
    ordered = [f for f in side.funcs
               if isinstance(f.size, int) and f.size > 0]
    starts = [f.address for f in ordered]

    def containing(addr: object) -> Optional[REFunction]:
        if not isinstance(addr, int) or isinstance(addr, bool):
            return None
        i = bisect_right(starts, addr) - 1
        for j in range(i, max(-1, i - 64), -1):
            f = ordered[j]
            if f.address <= addr < f.address + f.size:
                return f
        return side.by_addr.get(addr)

    strings_by_addr: Dict[int, str] = {}
    for s in db.strings:
        if isinstance(s, dict) and isinstance(s.get("address"), int):
            strings_by_addr[s["address"]] = str(s.get("value", ""))

    # adjacency deduplicated at build time: a hostile binary emits
    # millions of duplicate call sites; the tier-4 voting loop must
    # never pay per-xref cost
    callers: Dict[int, Set[int]] = {}
    callees: Dict[int, Set[int]] = {}
    self_calls: Set[int] = set()
    string_sets: Dict[int, Set[str]] = {}
    for x in db.xrefs:
        kind = getattr(x, "kind", None)
        src = containing(getattr(x, "from_addr", None))
        if src is None:
            continue
        to_addr = getattr(x, "to_addr", None)
        if kind == "call":
            dst = side.by_addr.get(to_addr) \
                if isinstance(to_addr, int) else None
            if dst is not None:
                if dst.address == src.address:
                    self_calls.add(src.address)
                else:
                    callees.setdefault(src.address,
                                       set()).add(dst.address)
                    callers.setdefault(dst.address,
                                       set()).add(src.address)
        elif kind in ("data", "string"):
            val = strings_by_addr.get(to_addr) \
                if isinstance(to_addr, int) else None
            if val:
                string_sets.setdefault(src.address, set()).add(val)

    side.self_calls = frozenset(self_calls)
    side.callers = {a: frozenset(v) for a, v in callers.items()}
    side.callees = {a: frozenset(v) for a, v in callees.items()}
    side.string_refs = {a: frozenset(v)
                        for a, v in string_sets.items()}

    # imported/thunk callee names survive stripping (PLT names come
    # from the dynamic symbol table, not the stripped symtab)
    for f in side.funcs:
        names = []
        for callee_addr in side.callees.get(f.address, frozenset()):
            callee = side.by_addr.get(callee_addr)
            if callee is not None and (callee.is_external
                                       or callee.is_thunk):
                names.append(str(callee.name))
        if names:
            side.import_callees[f.address] = tuple(sorted(names))

    for f in side.funcs:
        h = _decomp_hash(f)
        if h:
            side.decomp_hashes[f.address] = h
    return side


@dataclass
class MatchPair:
    old_name: str
    old_address: int
    new_name: str
    new_address: int
    tier: int
    score: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "old_name": _clip(self.old_name),
            "old_address": self.old_address,
            "new_name": _clip(self.new_name),
            "new_address": self.new_address,
            "tier": self.tier,
            "score": round(self.score, 3),
        }


@dataclass
class MatchResult:
    pairs: List[MatchPair] = field(default_factory=list)
    unmatched_old: List[Dict[str, object]] = field(default_factory=list)
    unmatched_new: List[Dict[str, object]] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    #: Call adjacency (address → callee addresses) per side, for
    #: consumers that compare a matched pair's call targets through
    #: the match mapping (rebase-invariant). Not serialized.
    callees_old: Dict[int, FrozenSet[int]] = field(
        default_factory=dict, repr=False)
    callees_new: Dict[int, FrozenSet[int]] = field(
        default_factory=dict, repr=False)
    self_calls_old: FrozenSet[int] = frozenset()
    self_calls_new: FrozenSet[int] = frozenset()

    def to_dict(self) -> Dict[str, object]:
        return {
            "pairs": [p.to_dict() for p in self.pairs],
            "unmatched_old": self.unmatched_old,
            "unmatched_new": self.unmatched_new,
            "stats": dict(self.stats),
            "notes": list(self.notes),
        }

    def old_to_new(self) -> Dict[int, int]:
        """old address → new address for matched pairs."""
        return {p.old_address: p.new_address for p in self.pairs}


def _size_compatible(a: REFunction, b: REFunction) -> bool:
    sa = a.size if isinstance(a.size, int) and a.size > 0 else None
    sb = b.size if isinstance(b.size, int) and b.size > 0 else None
    if sa is None or sb is None:
        return True
    lo, hi = sorted((sa, sb))
    return hi <= lo * _SIZE_RATIO + _SIZE_SLACK


def _unique_key_matches(
    old_side: _Side, new_side: _Side,
    old_pool: set, new_pool: set,
    key_fn, tier: int, score: float,
    size_gate: bool = True,
) -> List[MatchPair]:
    """Match functions whose key is unique within BOTH pools.

    ``size_gate`` additionally requires the pair to be size-compatible
    — a fingerprint key says nothing about identity when the true
    counterpart is absent and a differently-sized function inherited
    the key.
    """
    old_by_key: Dict[object, List[int]] = {}
    for addr in old_pool:
        k = key_fn(old_side, addr)
        if k is not None:
            old_by_key.setdefault(k, []).append(addr)
    new_by_key: Dict[object, List[int]] = {}
    for addr in new_pool:
        k = key_fn(new_side, addr)
        if k is not None:
            new_by_key.setdefault(k, []).append(addr)
    out: List[MatchPair] = []
    for k, olds in old_by_key.items():
        news = new_by_key.get(k)
        if news is None or len(olds) != 1 or len(news) != 1:
            continue
        of = old_side.by_addr[olds[0]]
        nf = new_side.by_addr[news[0]]
        if size_gate and not _size_compatible(of, nf):
            continue
        out.append(MatchPair(
            old_name=str(of.name), old_address=of.address,
            new_name=str(nf.name), new_address=nf.address,
            tier=tier, score=score,
        ))
    return out


def _t4_evidence_ok(old_side: _Side, new_side: _Side,
                    old_addr: int, new_addr: int,
                    votes: int) -> bool:
    """Corroboration gate for a tier-4 candidate.

    Matched-neighbor topology alone converts one deletion into a
    cascade of wrong pairs (the deleted subsystem's replacement wins
    every "only one left" vote). Decompilation similarity is the
    strongest available check and can never be overridden: string
    anchors are attacker-copyable, so an overlapping planted string
    must not outvote code that disproves the pair — and disjoint
    strings are absence of corroboration, not disproof, so they must
    not block a pair the code supports. With no text on either side,
    overlapping strings corroborate; with nothing at all, require a
    second independent voting neighbor.
    """
    sim = _jaccard(old_side.shingles(old_addr),
                   new_side.shingles(new_addr))
    if sim is not None:
        return sim >= _T4_SIM_FLOOR
    so = old_side.string_refs.get(old_addr)
    sn = new_side.string_refs.get(new_addr)
    if so and sn and (so & sn):
        return True
    return votes >= 2


def match_databases(old: REDatabase, new: REDatabase) -> MatchResult:
    """Match functions between *old* and *new* by the tier cascade."""
    old_side = _build_side(old)
    new_side = _build_side(new)

    old_pool = {f.address for f in old_side.funcs}
    new_pool = {f.address for f in new_side.funcs}
    result = MatchResult(callees_old=dict(old_side.callees),
                         callees_new=dict(new_side.callees),
                         self_calls_old=old_side.self_calls,
                         self_calls_new=new_side.self_calls)
    for label, side in (("old", old_side), ("new", new_side)):
        if side.dropped_duplicates:
            result.notes.append(
                f"{side.dropped_duplicates} {label}-side function(s) "
                "share an address with an earlier entry and were "
                "excluded from matching")

    def _apply(pairs: List[MatchPair],
               label: str) -> List[MatchPair]:
        applied: List[MatchPair] = []
        for p in pairs:
            if p.old_address in old_pool and p.new_address in new_pool:
                result.pairs.append(p)
                old_pool.discard(p.old_address)
                new_pool.discard(p.new_address)
                applied.append(p)
        result.stats[label] = (result.stats.get(label, 0)
                               + len(applied))
        return applied

    # ---- tier 1: exact non-auto name --------------------------------
    _apply(_unique_key_matches(
        old_side, new_side, old_pool, new_pool,
        lambda side, addr: (
            side.by_addr[addr].name
            if not _is_auto_named(side.by_addr[addr])
            and side.by_addr[addr].name else None),
        tier=1, score=1.0, size_gate=False,
    ), "tier1_name")

    # ---- tier 2: normalized decompilation hash ----------------------
    _apply(_unique_key_matches(
        old_side, new_side, old_pool, new_pool,
        lambda side, addr: side.decomp_hashes.get(addr),
        tier=2, score=0.95,
    ), "tier2_decomp_hash")

    # ---- tier 3a: referenced string values --------------------------
    _apply(_unique_key_matches(
        old_side, new_side, old_pool, new_pool,
        lambda side, addr: side.string_refs.get(addr) or None,
        tier=3, score=0.9,
    ), "tier3_strings")

    # ---- tier 3b: imported-callee multiset ---------------------------
    # size stays OUT of the key: quantized buckets let a grown
    # function vacate its bucket and a deleted sibling inherit its
    # identity; the continuous size gate filters instead
    _apply(_unique_key_matches(
        old_side, new_side, old_pool, new_pool,
        lambda side, addr: side.import_callees.get(addr),
        tier=3, score=0.85,
    ), "tier3_imports")

    # ---- tier 4: call-graph propagation (worklist fixpoint) ----------
    o2n = {p.old_address: p.new_address for p in result.pairs}

    def _t4_candidates(old_addr: int) -> Dict[int, int]:
        """new-address candidate → count of distinct voting neighbors."""
        votes: Dict[int, Set[int]] = {}
        for rel_old, is_caller in ((old_side.callers, True),
                                   (old_side.callees, False)):
            for nb in rel_old.get(old_addr, frozenset()):
                counterpart = o2n.get(nb)
                if counterpart is None:
                    continue
                # candidate = the counterpart's corresponding
                # neighbors on the new side, restricted to the
                # unmatched pool
                if is_caller:
                    cands = new_side.callees.get(counterpart,
                                                 frozenset())
                else:
                    cands = new_side.callers.get(counterpart,
                                                 frozenset())
                for c in cands:
                    if c in new_pool:
                        votes.setdefault(c, set()).add(nb)
        return {c: len(nbs) for c, nbs in votes.items()}

    def _t4_round(scan: Set[int]) -> List[MatchPair]:
        proposals: Dict[int, Set[int]] = {}
        for old_addr in sorted(scan & old_pool):
            candidates = _t4_candidates(old_addr)
            if len(candidates) != 1:
                continue
            cand, votes = next(iter(candidates.items()))
            of = old_side.by_addr[old_addr]
            nf = new_side.by_addr[cand]
            if not _size_compatible(of, nf):
                continue
            if not _t4_evidence_ok(old_side, new_side,
                                   old_addr, cand, votes):
                continue
            proposals.setdefault(cand, set()).add(old_addr)
        pairs = []
        for new_addr, olds in proposals.items():
            if len(olds) != 1:
                continue  # two old functions claim one new: ambiguous
            old_addr = next(iter(olds))
            of = old_side.by_addr[old_addr]
            nf = new_side.by_addr[new_addr]
            pairs.append(MatchPair(
                old_name=str(of.name), old_address=of.address,
                new_name=str(nf.name), new_address=nf.address,
                tier=4, score=0.75,
            ))
        return pairs

    def _t4_run(seed_scan: Set[int]) -> None:
        scan = seed_scan
        while scan:
            fresh = _apply(_t4_round(scan), "tier4_callgraph")
            for p in fresh:
                o2n[p.old_address] = p.new_address
            # next round: only unmatched functions adjacent to a
            # fresh match can gain a new vote
            scan = set()
            for p in fresh:
                scan |= old_side.neighbors(p.old_address)

    _t4_run(set(old_pool))
    # candidate sets can also SHRINK non-locally (a competing match
    # consumed a candidate elsewhere in the graph); bounded full
    # sweeps catch those without reopening the quadratic rescan
    for _ in range(_T4_MAX_SWEEPS):
        before = len(result.pairs)
        _t4_run(set(old_pool))
        if len(result.pairs) == before:
            break
    else:
        before = len(result.pairs)
        _t4_run(set(old_pool))
        if len(result.pairs) != before:
            result.notes.append(
                "tier-4 sweep budget reached; propagation may be "
                "incomplete")

    # ---- tier 5: decompilation similarity (bounded) ------------------
    old_rem = [a for a in sorted(old_pool)
               if old_side.by_addr[a].decompilation]
    new_rem = [a for a in sorted(new_pool)
               if new_side.by_addr[a].decompilation]
    if old_rem and new_rem:
        if len(old_rem) * len(new_rem) > _MAX_PAIRWISE:
            result.notes.append(
                f"similarity tier skipped: {len(old_rem)}x"
                f"{len(new_rem)} exceeds the pairwise budget")
        elif (work := (
                len(new_rem) * sum(len(old_side.shingles(a))
                                   for a in old_rem)
                + len(old_rem) * sum(len(new_side.shingles(a))
                                     for a in new_rem))) > _MAX_SIM_WORK:
            result.notes.append(
                f"similarity tier skipped: estimated set work "
                f"{work} exceeds the budget")
        else:
            # claimants[new] = scored old-side winners; the margin is
            # enforced from BOTH sides — an old function must clearly
            # prefer one new function, and a new function must be
            # clearly claimed by one old function
            claimants: Dict[int, List[Tuple[float, int]]] = {}
            for oa in old_rem:
                sa = old_side.shingles(oa)
                if not sa:
                    continue
                scored = []
                for na in new_rem:
                    sb = new_side.shingles(na)
                    if not sb:
                        continue
                    if not _size_compatible(old_side.by_addr[oa],
                                            new_side.by_addr[na]):
                        continue
                    sim = _jaccard(sa, sb)
                    if sim is not None:
                        scored.append((sim, na))
                scored.sort(reverse=True)
                if not scored or scored[0][0] < _SIM_ABS:
                    continue
                if (len(scored) > 1
                        and scored[0][0] - scored[1][0] < _SIM_MARGIN):
                    continue  # no clear winner: ambiguous
                sim, na = scored[0]
                claimants.setdefault(na, []).append((sim, oa))
            pairs = []
            for na, claims in claimants.items():
                claims.sort(reverse=True)
                if (len(claims) > 1
                        and claims[0][0] - claims[1][0] < _SIM_MARGIN):
                    continue  # two old claimants too close: refuse
                sim, oa = claims[0]
                of = old_side.by_addr[oa]
                nf = new_side.by_addr[na]
                pairs.append(MatchPair(
                    old_name=str(of.name), old_address=of.address,
                    new_name=str(nf.name), new_address=nf.address,
                    tier=5, score=sim,
                ))
            _apply(pairs, "tier5_similarity")

    result.pairs.sort(key=lambda p: p.old_address)
    result.unmatched_old = [
        {"name": _clip(old_side.by_addr[a].name), "address": a}
        for a in sorted(old_pool)
    ]
    result.unmatched_new = [
        {"name": _clip(new_side.by_addr[a].name), "address": a}
        for a in sorted(new_pool)
    ]
    result.stats["matched"] = len(result.pairs)
    result.stats["unmatched_old"] = len(result.unmatched_old)
    result.stats["unmatched_new"] = len(result.unmatched_new)
    if old_side.dropped_duplicates or new_side.dropped_duplicates:
        result.stats["duplicate_addresses_dropped"] = (
            old_side.dropped_duplicates + new_side.dropped_duplicates)
    return result
