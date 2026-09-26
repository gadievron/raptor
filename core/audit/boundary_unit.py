"""Boundary/unit consistency census.

Two legs over two established site extractions — no new walker:

* **bound-expression leg** — the guard-predicate census's loop sites
  (``for``/``while`` header joined to the first subscript below),
  regrouped along the orthogonal axis: peers share
  ``(base, index, operator)`` and the vote is over the BOUND
  EXPRESSION text ("four loops stop at ``n``; the fifth at
  ``n - 1``").  The guard-predicate census votes the operator at a
  fixed bound; this leg votes the bound at a fixed operator — one
  extraction, two orthogonal censuses.
* **unit-scale leg** — the argument-site extraction
  (``consistency_dimensions._extract_arg_sites``), per callee and
  position, over integer-LITERAL arguments only: when a modal-ratio
  majority of the literals shares the millis-style scale (multiples
  of 1000) and the deviant's does not (or vice versa), the site is a
  unit-scale suspect ("peers pass 5000/10000/30000 to one timeout API; this
  site passes 30").  Groups whose majority literals are all EQUAL
  are skipped — an exact-value majority is the flag/mode dimension's
  territory, deliberately not re-reported here.

Verdict discipline: detection-grade THROUGHOUT — a differing bound
or scale is frequently intentional, so every deviation rides the
single consistency namespace as ``consistency:boundary-unit-majority``
(prepass-lead-only, aggregation-eligible, never a finding alone).
Enumerated inconclusive reasons:

* ``bound-data-dependent`` — the group's bound is computed by a
  call; bound texts are not comparable across sites.
* ``scale-unresolved`` — a site's argument is not an integer
  literal; it is excluded from the scale vote, never guessed.

Hostile-repo bounds: named caps on groups and total vote work with
an in-band ``caps_hit`` marker; over-cap group survivors are
SEEDED-RANDOM, never a deterministic prefix (sites arrive in
sorted-file order and a first-N cut would let conforming decoys
evict the real deviant).
"""

from __future__ import annotations

import logging
import os
import random
from dataclasses import dataclass
from typing import Any

from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

DIMENSION_BOUNDARY_UNIT = "boundary-unit"

# Peer floor and majority ratio for a boundary/unit lead.  Inline per
# the threshold-residence convention (registry-enumerated in
# consistency_stats, overridable via the audit run-config only).
# 3/0.75 are the engine-wide group floors (one site outvoting another
# is not a majority; a higher ratio hides drift in small families).
BOUNDARY_UNIT_MIN_SITES = 3
BOUNDARY_UNIT_RATIO = 0.75

KIND_BOUND_EXPR = "bound-expr"
KIND_UNIT_SCALE = "unit-scale"

REASON_BOUND_DATA_DEPENDENT = "bound-data-dependent"
REASON_SCALE_UNRESOLVED = "scale-unresolved"

#: Groups voted per run (the census cap class shared with the
#: enum-switch and guard-predicate censuses; both directions: more
#: admits a group-per-file flood, fewer drops real families).
MAX_BOUND_GROUPS = 500

#: Members per group at vote intake (the comparator family ceiling
#: class — consistency_dimensions.MAX_FAMILY_MEMBERS rationale).
MAX_SITES_PER_GROUP = 32

#: Total vote work per run.  Both directions: higher re-opens the
#: generated-tree DoS; lower truncates legitimately loop-heavy trees
#: (truncation is marked in-band, never partial-silent).
MAX_BOUND_OPS = 200_000

#: Deviations returned per run (engine-wide deviation cap class).
MAX_DEVIATIONS = 80

#: The millis-vs-seconds scale class boundary.  A literal that is a
#: nonzero multiple of this factor sits in the "scaled" class; the
#: vote fires when a modal-ratio majority (BOUNDARY_UNIT_RATIO) of
#: the group's literals sit on one side and the deviant is the other.
UNIT_SCALE_FACTOR = 1000


@dataclass
class BoundaryUnitDeviation:
    """One site whose bound expression / literal scale deviates."""

    kind: str              # KIND_BOUND_EXPR | KIND_UNIT_SCALE
    group_key: str
    file: str
    line: int
    enclosing_function: str
    n: int
    conforming: int
    majority_repr: str
    deviant_repr: str
    cwe: str = ""
    #: When the group exceeded MAX_SITES_PER_GROUP at intake, the
    #: ORIGINAL group size (0 = no sampling).
    sampled_from: int = 0
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        what = (
            "bound the loop with" if self.kind == KIND_BOUND_EXPR
            else "pass"
        )
        base = (
            f"{self.conforming}/{self.n} sites of {self.group_key} "
            f"{what} `{self.majority_repr}`; "
            f"{self.enclosing_function} uses `{self.deviant_repr}` "
            f"[{self.kind}]"
        )
        if self.sampled_from:
            base += (
                f" (vote over a seeded sample of {self.n} of the "
                f"group's {self.sampled_from} sites)"
            )
        return base

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "group_key": self.group_key,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "majority": self.majority_repr,
            "deviant": self.deviant_repr,
            "cwe": self.cwe,
        }
        if self.sampled_from:
            d["sampled_from"] = self.sampled_from
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


def _count(reasons: dict[str, int], key: str, by: int = 1) -> None:
    reasons[key] = reasons.get(key, 0) + by


def _off_by_one_exprs(a: str, b: str) -> bool:
    """True when one bound expression is the other ± 1 (textually:
    ``n`` vs ``n - 1`` / ``n + 1`` after normalization)."""
    for base, longer in ((a, b), (b, a)):
        for op in ("-", "+"):
            if longer in (f"{base} {op} 1", f"({base}) {op} 1"):
                return True
    return False


def _scale_class(value: int) -> str:
    return (
        "scaled" if value != 0 and value % UNIT_SCALE_FACTOR == 0
        else "raw"
    )


def detect_boundary_unit_deviations(
    source_texts: dict[str, str],
    *,
    min_sites: int = BOUNDARY_UNIT_MIN_SITES,
    ratio: float = BOUNDARY_UNIT_RATIO,
    seed: bytes | None = None,
) -> tuple[list[BoundaryUnitDeviation], dict[str, Any]]:
    """Run the census.  Returns ``(deviations, stats)``.

    ``stats``: ``sites`` (loop sites + literal argument views),
    ``groups`` (groups that reached a vote), ``bound_ops`` (vote work
    performed — the cost-rail pin reads it), ``caps_hit``,
    ``inconclusive_reasons`` (enumerated, module docstring).

    *seed* keys the over-cap survivor sampling; callers leave it
    ``None`` (fresh entropy per run) outside tests.
    """
    reasons: dict[str, int] = {}
    stats: dict[str, Any] = {
        "sites": 0, "groups": 0, "bound_ops": 0,
        "caps_hit": False, "inconclusive_reasons": reasons,
    }
    rnd = random.Random(seed if seed is not None else os.urandom(16))
    deviations: list[BoundaryUnitDeviation] = []
    state = {"ops": 0, "groups": 0}

    def _vote_group(
        key_repr: str,
        members: list[Any],
        value_of: Any,
        repr_of: Any,
        kind: str,
        cwe_of: Any,
    ) -> bool:
        """Shared modal-value vote.  Returns False when a run-level
        cap closed the census."""
        if len(members) < min_sites:
            return True
        if state["groups"] >= MAX_BOUND_GROUPS:
            stats["caps_hit"] = True
            return False
        sampled_from = 0
        if len(members) > MAX_SITES_PER_GROUP:
            # SEEDED-RANDOM survivors, never a deterministic prefix
            # (module docstring — anti-eviction).
            sampled_from = len(members)
            members = rnd.sample(members, MAX_SITES_PER_GROUP)
            stats["caps_hit"] = True
        n = len(members)
        if state["ops"] + n > MAX_BOUND_OPS:
            stats["caps_hit"] = True
            return True
        state["ops"] += n
        state["groups"] += 1
        counts: dict[Any, int] = {}
        for m in members:
            v = value_of(m)
            counts[v] = counts.get(v, 0) + 1
        modal, c = sorted(
            counts.items(), key=lambda kv: (-kv[1], repr(kv[0])),
        )[0]
        if c == n or c / n < ratio:
            return True
        conforming = [m for m in members if value_of(m) == modal]
        exhibits = [
            PeerExhibit(m.file, m.line, m.snippet)
            for m in conforming[:3]
        ]
        for m in members:
            if value_of(m) == modal:
                continue
            deviations.append(BoundaryUnitDeviation(
                kind=kind,
                group_key=key_repr,
                file=m.file,
                line=m.line,
                enclosing_function=m.enclosing_function,
                n=n,
                conforming=c,
                majority_repr=repr_of(modal, conforming[0]),
                deviant_repr=repr_of(value_of(m), m),
                cwe=cwe_of(modal, value_of(m)),
                sampled_from=sampled_from,
                peer_evidence=PeerEvidence(
                    dimension=DIMENSION_BOUNDARY_UNIT,
                    formation=(
                        "loop_bound" if kind == KIND_BOUND_EXPR
                        else "same_callee"
                    ),
                    group_key=key_repr,
                    n=n,
                    conforming=c,
                    ratio=c / n,
                    deviant=PeerExhibit(m.file, m.line, m.snippet),
                    exhibits=exhibits,
                    contract_source="majority",
                    provenance=f"boundary_unit:{kind}",
                ),
            ))
            if len(deviations) >= MAX_DEVIATIONS:
                stats["caps_hit"] = True
                return False
        return True

    # ── bound-expression leg (loop sites, orthogonal regrouping) ───
    from .consistency_dimensions import _function_spans
    from .guard_predicate import loop_guard_sites

    spans = _function_spans(source_texts)
    loop_sites = loop_guard_sites(spans) if spans else []
    stats["sites"] = len(loop_sites)

    by_idiom: dict[tuple[str, str, str], list[Any]] = {}
    for s in loop_sites:
        by_idiom.setdefault(
            (s.base, s.index, s.relop), [],
        ).append(s)

    open_census = True
    for key in sorted(by_idiom):
        members = by_idiom[key]
        if len(members) >= min_sites and any(
            m.bound_is_call for m in members
        ):
            # Bound texts computed by calls are not comparable.
            _count(reasons, REASON_BOUND_DATA_DEPENDENT)
            continue
        base, index, relop = key
        if not _vote_group(
            f"{base}[{index}] ({relop})",
            members,
            value_of=lambda m: m.bound_expr,
            repr_of=lambda v, m: f"{m.tested_var} {m.relop} {v}",
            kind=KIND_BOUND_EXPR,
            cwe_of=lambda modal, dev: (
                "CWE-193" if _off_by_one_exprs(str(modal), str(dev))
                else "CWE-682"
            ),
        ):
            open_census = False
            break

    # ── unit-scale leg (literal argument views) ────────────────────
    if open_census:
        from .consistency_dimensions import (
            _MAX_ARG_POSITIONS,
            _extract_arg_sites,
            _parse_int_literal,
        )

        @dataclass
        class _LitView:
            file: str
            line: int
            enclosing_function: str
            snippet: str
            value: int

        by_callee = _extract_arg_sites(source_texts)
        for callee in sorted(by_callee):
            if not open_census:
                break
            arg_sites = by_callee[callee]
            if len(arg_sites) < min_sites:
                continue
            max_pos = max(len(s.args) for s in arg_sites)
            for pos in range(min(max_pos, _MAX_ARG_POSITIONS)):
                views: list[_LitView] = []
                unresolved = 0
                for s in arg_sites:
                    if len(s.args) <= pos:
                        continue
                    value = _parse_int_literal(s.args[pos])
                    if value is None:
                        unresolved += 1
                        continue
                    views.append(_LitView(
                        file=s.file,
                        line=s.line,
                        enclosing_function=s.enclosing_function,
                        snippet=s.snippet,
                        value=value,
                    ))
                # Count BEFORE the floor check: a family whose sites
                # are all (or mostly) non-literal is dropped by the
                # floor, and that drop must still be enumerated.
                if unresolved:
                    _count(
                        reasons, REASON_SCALE_UNRESOLVED, unresolved,
                    )
                if len(views) < min_sites:
                    continue
                values = [v.value for v in views]
                if len(set(values)) <= 1:
                    continue
                # Exact-value majorities are flag/mode territory —
                # skip when the modal VALUE already forms one.
                value_counts: dict[int, int] = {}
                for v in values:
                    value_counts[v] = value_counts.get(v, 0) + 1
                if max(value_counts.values()) / len(values) >= ratio:
                    continue
                if not _vote_group(
                    f"{callee}(arg{pos})",
                    views,
                    value_of=lambda m: _scale_class(m.value),
                    repr_of=lambda v, m: f"{m.value} ({v})",
                    kind=KIND_UNIT_SCALE,
                    cwe_of=lambda _modal, _dev: "CWE-682",
                ):
                    open_census = False
                    break

    stats["bound_ops"] = state["ops"]
    stats["groups"] = state["groups"]
    deviations.sort(key=lambda d: (d.file, d.line, d.kind))
    if deviations or stats["caps_hit"]:
        logger.info(
            "boundary-unit census: %d loop sites, %d groups, %d "
            "deviation(s), %d ops%s",
            stats["sites"], state["groups"], len(deviations),
            state["ops"],
            " (caps hit)" if stats["caps_hit"] else "",
        )
    return deviations[:MAX_DEVIATIONS], stats
