"""Guard-predicate consistency census.

"Four sibling loops bound the index with ``i < n``; the fifth uses
``i <= n``."  The guard-PRESENCE dimension sees only whether a guard
exists; this census compares WHAT the guards test, across peers that
guard the same operation.  Two legs, both linear:

* **loop leg** — ``for``/``while`` headers with a single relational
  condition, joined to the first subscript access below the header.
  Peers share ``(base, index, bound)``; the vote is over the
  comparison operator (off-by-one drift), over whether the tested
  identifier IS the subscript index (wrong-variable drift), and over
  the tested identifier's declared signedness (signedness mix).
* **deref-guard leg** — ``if`` conjunctions containing a
  dereference comparison (``p->len < max``).  Peers share
  ``(field, operator, bound)``; the vote is over the presence of the
  null-test arm on the dereferenced base (``p && p->len < max`` vs
  ``q->len < max``).

Diffing is majority-profile-vs-member — one profile per group, each
member compared against it — never pairwise.

Verdict discipline: deviations here are census statistics.  The
adjudicator (``consistency_verify.guard_predicate_verdict``) owns the
grading — a ``condition_smt`` escalation can upgrade a deviant to a
promote-capable ``smt_witness`` confirmation; everything else stays
detection-grade under the single consistency namespace
(``consistency:guard-predicate-majority``) and never classifies code
alone.

Enumerated inconclusive reasons, never guesses:

* ``predicate-data-dependent`` — the bound is computed by a call; the
  predicate's value space is not comparable across sites.
* ``macro-divergent`` — the deviant's condition carries a different
  macro-token set than its peers; the drift may live in preprocessor
  configuration, not code.
* ``type-context-differs`` — the deviant's tested identifier resolves
  to a different declared signedness than the majority's; an operator
  difference may be forced by the type.
* ``census-degraded`` — a run-level budget excluded the group; an
  absence-of-drift claim over a truncated walk would lie.

Hostile-repo bounds: group count, per-group membership, and total
vote work are all attacker-generatable, so each carries a named cap
with an in-band ``caps_hit`` marker.  Over-cap survivors are
SEEDED-RANDOM, never a deterministic prefix — sites arrive in
sorted-file order, and a first-N cut would let a flood of conforming
decoys in early-sorting file names evict the real deviant.
"""

from __future__ import annotations

import logging
import os
import random
import re
from dataclasses import dataclass, field
from typing import Any

from .peer_evidence import FamilyMember, PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

DIMENSION_GUARD_PREDICATE = "guard-predicate"

# Peer floor and majority ratio for a predicate-drift lead.  Inline
# per the threshold-residence convention (registry-enumerated in
# consistency_stats, overridable via the audit run-config only).
# 3/0.75 are the engine-wide group floors: below three peers a
# "majority" is one site outvoting another; a lower ratio flags
# legitimately mixed idioms, a higher one hides real drift in small
# clone families.
GUARD_PREDICATE_MIN_SITES = 3
GUARD_PREDICATE_RATIO = 0.75

# Deviation kinds (each names the drift the description asserts).
KIND_OFF_BY_ONE = "off-by-one"
KIND_OPERATOR_MISMATCH = "operator-mismatch"
KIND_SIGNEDNESS_MIX = "signedness-mix"
KIND_MISSING_NULL_ARM = "missing-null-arm"
KIND_WRONG_VARIABLE = "guard-variable-mismatch"

_KIND_CWE = {
    KIND_OFF_BY_ONE: "CWE-193",
    KIND_OPERATOR_MISMATCH: "CWE-697",
    KIND_SIGNEDNESS_MIX: "CWE-195",
    KIND_MISSING_NULL_ARM: "CWE-476",
    KIND_WRONG_VARIABLE: "CWE-697",
}

# Enumerated inconclusive reasons (module docstring).
REASON_PREDICATE_DATA_DEPENDENT = "predicate-data-dependent"
REASON_MACRO_DIVERGENT = "macro-divergent"
REASON_TYPE_CONTEXT_DIFFERS = "type-context-differs"
REASON_CENSUS_DEGRADED = "census-degraded"

#: Predicate groups voted per run.  Both directions: more admits a
#: generated group-per-file flood into the vote loop; fewer drops
#: real families on large trees.  500 mirrors the enum-switch and
#: interface-slot census cap class.
MAX_PREDICATE_GROUPS = 500

#: Members per group at vote intake.  Both directions: an uncapped
#: hub group makes a single deviant statistical noise and multiplies
#: per-member type lookups; too low splits genuinely wide clone
#: families.  32 matches the comparator-intake family ceiling
#: (consistency_dimensions.MAX_FAMILY_MEMBERS).
MAX_SITES_PER_GROUP = 32

#: Total vote work per run (member-vote + type-lookup steps).  Both
#: axes are attacker-generatable and the per-group caps still admit
#: 500×32 member votes plus per-member declared-type lookups — the
#: run-level budget keeps the census inside the prepass wall-clock
#: class.  Both directions: higher re-opens the DoS; lower truncates
#: legitimately loop-heavy trees (truncation is marked in-band and
#: excludes the untouched groups, never partial-silent).
MAX_PREDICATE_OPS = 200_000

#: Deviations returned per run (the engine-wide deviation cap class).
MAX_DEVIATIONS = 80

# Lookahead (lines) from a loop header to its first subscript access.
# Bounded so the join stays linear on pathological bodies; a farther
# subscript means fewer candidates, never a wrong vote.
_SUBSCRIPT_WINDOW = 12

_LOOP_HEAD_RE = re.compile(r"^\s*(?:}\s*)?(for|while)\s*\(")
_IF_HEAD_RE = re.compile(r"^\s*(?:}\s*)?(?:else\s+)?if\s*\(")

# Single relational comparison: identifier path, operator, bound
# expression.  Shift operators are excluded by lookarounds; ``->`` is
# consumed by the identifier path so its ``>`` never reads as a
# comparison.  The bound starts at its first non-space (no
# overlapping whitespace spans — linearity fold; the consumer
# rstrips) and runs to end of line.
_COND_RE = re.compile(
    r"^\s*([A-Za-z_]\w*(?:(?:->|\.)\w+)*)\s*"
    r"(<=|>=|<(?!<)|>(?!>))\s*(\S.*)$",
)

# Dereference comparison conjunct: ``base->field OP bound`` /
# ``base.field OP bound``.  Same bound fold as _COND_RE.
_DEREF_CMP_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*(\w+)\s*"
    r"(<=|>=|==|!=|<(?!<)|>(?!>))\s*(\S.*)$",
)

_SUBSCRIPT_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]",
)

_MACRO_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")

# Residual relational operator in a bound expression (an unparsed
# chained comparison) — ``->`` is not a comparison.
_RESIDUAL_REL_RE = re.compile(r"(?<!-)[<>]")

# Off-by-one operator pairs: strict vs inclusive, same direction.
_OFF_BY_ONE_PAIRS = frozenset({
    frozenset({"<", "<="}),
    frozenset({">", ">="}),
})

# Hypothesis shapes asserting a guard-PREDICATE deviation (peer
# language handled by the consistency router; this matcher narrows
# to predicate/bound/comparison claims so return-check hypotheses
# never detour here).
_GUARD_PREDICATE_HYPOTHESIS_RE = re.compile(
    r"(?:\boff[- ]by[- ]one\b"
    r"|\bpredicate\b"
    r"|\b(?:bounds?|guards?|loops?|comparisons?)\b"
    r"[^.]{0,120}?(?:<=|>=|\bwith\s+<|\bwith\s+>"
    r"|\buses?\s+<|\buses?\s+>)"
    r"|(?:<=|>=)\s*(?:vs\.?|versus|instead\s+of|where\s+peers\s+use)"
    r")",
    re.IGNORECASE | re.DOTALL,
)


def is_guard_predicate_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts predicate drift against peers
    ("3/4 sibling loops bound i with < n; this uses <=")."""
    return bool(text) and bool(_GUARD_PREDICATE_HYPOTHESIS_RE.search(text))


@dataclass
class _PredicateSite:
    """One guarded-operation view (loop or deref-guard leg)."""

    file: str
    line: int
    enclosing_function: str
    leg: str               # "loop" | "deref"
    base: str              # subscript base / deref base
    index: str             # subscript index ("" on the deref leg)
    field_name: str        # deref field ("" on the loop leg)
    tested_var: str
    relop: str
    bound_expr: str        # whitespace-normalized
    bound_is_call: bool
    macro_tokens: frozenset[str]
    has_null_arm: bool
    snippet: str


@dataclass
class GuardPredicateDeviation:
    """One site whose guard predicate deviates from its peers'."""

    kind: str
    group_key: str
    file: str
    line: int
    enclosing_function: str
    n: int
    conforming: int
    majority_repr: str
    deviant_repr: str
    tested_var: str = ""
    relop: str = ""
    majority_relop: str = ""
    bound_expr: str = ""
    cwe: str = ""
    #: When the group exceeded MAX_SITES_PER_GROUP at intake, the
    #: ORIGINAL group size — the vote ran over a seeded sample of n
    #: members, and the description says so (0 = no sampling).
    sampled_from: int = 0
    #: The deviant's own dominating guard conditions, for the
    #: condition_smt escalation in the verdict layer.
    deviant_guards: list[Any] = field(default_factory=list)
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        base = (
            f"{self.conforming}/{self.n} sites guard {self.group_key} "
            f"with `{self.majority_repr}`; "
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


def _paren_content(line: str, open_idx: int) -> str | None:
    """The text inside the paren group opening at ``line[open_idx]``,
    or None when unbalanced on this line (multi-line headers are out
    of the census's narrow shape)."""
    depth = 0
    for i in range(open_idx, len(line)):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[open_idx + 1:i]
    return None


def _normalize_expr(text: str) -> str:
    return " ".join(text.split())


def _parse_condition(cond: str) -> tuple[str, str, str] | None:
    """(tested_var, relop, bound_expr) for a single relational
    condition, or None for compound / non-relational shapes."""
    if "&&" in cond or "||" in cond or "?" in cond:
        return None
    m = _COND_RE.match(cond)
    if not m:
        return None
    tested, relop, bound = m.group(1), m.group(2), m.group(3)
    if _RESIDUAL_REL_RE.search(bound.replace("->", "")):
        return None
    return tested, relop, _normalize_expr(bound)


def loop_guard_sites(
    spans: list[tuple[str, str, int, list[str]]],
) -> list[_PredicateSite]:
    """Loop-leg sites: single-condition ``for``/``while`` headers
    joined to the first subscript access within the lookahead window.
    Exported for the bound-expression census, which votes the same
    sites along the orthogonal axis (bound expression at fixed
    operator vs operator at fixed bound)."""
    sites: list[_PredicateSite] = []
    for file_path, name, start, body in spans:
        for idx, line in enumerate(body):
            m = _LOOP_HEAD_RE.match(line)
            if not m:
                continue
            open_idx = line.find("(", m.start(1))
            if open_idx < 0:
                continue
            content = _paren_content(line, open_idx)
            if content is None:
                continue
            if m.group(1) == "for":
                clauses = content.split(";")
                if len(clauses) != 3:
                    continue
                cond = clauses[1]
            else:
                cond = content
            parsed = _parse_condition(cond)
            if parsed is None:
                continue
            tested, relop, bound = parsed
            # First subscript at/below the header (bounded window).
            sub = None
            window_end = min(len(body), idx + 1 + _SUBSCRIPT_WINDOW)
            tail = line[open_idx + len(content) + 2:]
            for probe in [tail] + body[idx + 1:window_end]:
                sm = _SUBSCRIPT_RE.search(probe)
                if sm:
                    sub = sm
                    break
            if sub is None:
                continue
            sites.append(_PredicateSite(
                file=file_path,
                line=start + idx,
                enclosing_function=name,
                leg="loop",
                base=sub.group(1),
                index=sub.group(2),
                field_name="",
                tested_var=tested,
                relop=relop,
                bound_expr=bound,
                bound_is_call="(" in bound,
                macro_tokens=frozenset(
                    _MACRO_TOKEN_RE.findall(cond),
                ),
                has_null_arm=False,
                snippet=line.strip()[:200],
            ))
    return sites


def _is_null_arm(conjunct: str, base: str) -> bool:
    c = conjunct.strip()
    if c == base:
        return True
    b = re.escape(base)
    return bool(re.fullmatch(
        rf"(?:{b}\s*!=\s*(?:NULL|nullptr|0)"
        rf"|(?:NULL|nullptr|0)\s*!=\s*{b})", c,
    ))


def _deref_guard_sites(
    spans: list[tuple[str, str, int, list[str]]],
) -> list[_PredicateSite]:
    """Deref-guard-leg sites: ``if`` conjunctions carrying a
    dereference comparison, with the null-arm presence recorded.
    Disjunctions and negations are skipped — their arm structure is
    not a conjunct census."""
    sites: list[_PredicateSite] = []
    for file_path, name, start, body in spans:
        for idx, line in enumerate(body):
            m = _IF_HEAD_RE.match(line)
            if not m:
                continue
            open_idx = line.find("(", m.end() - 1)
            if open_idx < 0:
                continue
            content = _paren_content(line, open_idx)
            if content is None:
                continue
            if "||" in content or "?" in content \
                    or re.search(r"!(?!=)", content):
                continue
            conjuncts = [c for c in content.split("&&")]
            for ci, conjunct in enumerate(conjuncts):
                dm = _DEREF_CMP_RE.match(conjunct)
                if not dm:
                    continue
                base, fld, relop, bound = (
                    dm.group(1), dm.group(2), dm.group(3),
                    _normalize_expr(dm.group(4)),
                )
                if _RESIDUAL_REL_RE.search(bound.replace("->", "")):
                    continue
                null_arm = any(
                    _is_null_arm(other, base)
                    for oi, other in enumerate(conjuncts)
                    if oi != ci
                )
                sites.append(_PredicateSite(
                    file=file_path,
                    line=start + idx,
                    enclosing_function=name,
                    leg="deref",
                    base=base,
                    index="",
                    field_name=fld,
                    tested_var=f"{base}->{fld}",
                    relop=relop,
                    bound_expr=bound,
                    bound_is_call="(" in bound,
                    macro_tokens=frozenset(
                        _MACRO_TOKEN_RE.findall(content),
                    ),
                    has_null_arm=null_arm,
                    snippet=line.strip()[:200],
                ))
                break  # one deref comparison per if is plenty
    return sites


def _count(reasons: dict[str, int], key: str, by: int = 1) -> None:
    reasons[key] = reasons.get(key, 0) + by


def collect_predicate_sites(
    source_texts: dict[str, str],
) -> list[_PredicateSite]:
    """Every predicate site of both legs — the census's own input,
    exported so the hypothesis-adjudication path can bind a claim to
    a site/group without duplicating the extraction."""
    from .consistency_dimensions import _function_spans

    spans = _function_spans(source_texts)
    if not spans:
        return []
    return loop_guard_sites(spans) + _deref_guard_sites(spans)


def predicate_group_key(site: _PredicateSite) -> tuple[str, ...]:
    """The peer-group key a site votes under (leg-specific)."""
    if site.leg == "loop":
        return ("loop", site.base, site.index, site.bound_expr)
    return ("deref", site.field_name, site.relop, site.bound_expr)


class _SignednessCache:
    """Per-(function, var) declared-signedness memo.  The lookup is
    scoped to the ENCLOSING FUNCTION's span (a same-named local in a
    sibling function must never answer for this one), and memoised so
    the census prices it once per identifier, not once per vote."""

    def __init__(
        self, bodies: dict[tuple[str, str], str],
    ) -> None:
        self._bodies = bodies
        self._memo: dict[tuple[str, str, str], bool | None] = {}
        self.lookups = 0

    def get(self, site: _PredicateSite) -> bool | None:
        var = site.tested_var.split("->")[0].split(".")[0]
        key = (site.file, site.enclosing_function, var)
        if key not in self._memo:
            from .condition_smt import declared_signedness
            self.lookups += 1
            self._memo[key] = declared_signedness(
                var,
                self._bodies.get(
                    (site.file, site.enclosing_function),
                ) or "",
            )
        return self._memo[key]


def _majority(values: list[Any]) -> tuple[Any, int]:
    """(modal value, count) — deterministic tie-break by repr."""
    counts: dict[Any, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    best = sorted(
        counts.items(), key=lambda kv: (-kv[1], repr(kv[0])),
    )[0]
    return best


def _dominating_guards(
    source_texts: dict[str, str], file_path: str, line: int,
) -> list[Any]:
    from .consistency_dimensions import _dominating_guards_for_line
    return _dominating_guards_for_line(source_texts, file_path, line)


def detect_guard_predicate_deviations(
    source_texts: dict[str, str],
    *,
    min_sites: int = GUARD_PREDICATE_MIN_SITES,
    ratio: float = GUARD_PREDICATE_RATIO,
    seed: bytes | None = None,
) -> tuple[list[GuardPredicateDeviation], dict[str, Any]]:
    """Run the census.  Returns ``(deviations, stats)``.

    ``stats``: ``sites``, ``groups`` (groups that reached a vote),
    ``predicate_ops`` (vote + type-lookup work performed — the
    cost-rail pin reads it), ``caps_hit`` (any bound truncated the
    census), ``inconclusive_reasons`` (enumerated, module docstring).

    Vote-provenance disclosure (the hypothesis adjudicator's refute
    leg reads these — group SIZE alone is not a vote, so a refutation
    must be able to prove the census actually voted the claimed site):

    * ``voted_sites`` — ``(file, line, leg)`` of every member of a
      COMPLETED vote (a group the deviation cap closed mid-vote is
      excluded — its members were only partially compared).
    * ``group_skips`` — group key → enumerated reason for groups the
      census saw but never voted (call-shaped bound, ops budget,
      macro divergence below the floor, mid-run closure).
    * ``excluded_sites`` — ``(file, line, leg)`` → reason for members
      individually excluded from an otherwise-voted group (macro
      divergence, seeded sampling).

    *seed* keys the over-cap survivor sampling; callers leave it
    ``None`` (fresh entropy per run) outside tests.
    """
    reasons: dict[str, int] = {}
    voted_sites: set[tuple[str, int, str]] = set()
    group_skips: dict[tuple[str, ...], str] = {}
    excluded_sites: dict[tuple[str, int, str], str] = {}
    stats: dict[str, Any] = {
        "sites": 0, "groups": 0, "predicate_ops": 0,
        "caps_hit": False, "inconclusive_reasons": reasons,
        "voted_sites": voted_sites, "group_skips": group_skips,
        "excluded_sites": excluded_sites,
    }
    from .consistency_dimensions import _function_spans

    spans = _function_spans(source_texts)
    if not spans:
        return [], stats

    sites = loop_guard_sites(spans) + _deref_guard_sites(spans)
    stats["sites"] = len(sites)
    if not sites:
        return [], stats

    groups: dict[tuple[str, ...], list[_PredicateSite]] = {}
    for s in sites:
        groups.setdefault(predicate_group_key(s), []).append(s)

    rnd = random.Random(seed if seed is not None else os.urandom(16))
    bodies = {
        (fp, fn): "\n".join(body)
        for fp, fn, _start, body in spans
    }
    signedness = _SignednessCache(bodies)
    deviations: list[GuardPredicateDeviation] = []
    ops = 0
    n_groups = 0

    def _emit(dev: GuardPredicateDeviation) -> bool:
        deviations.append(dev)
        if len(deviations) >= MAX_DEVIATIONS:
            # The cap truncates the census — say so in-band, exactly
            # like every other bound here.
            stats["caps_hit"] = True
            return False
        return True

    for key in sorted(groups):
        members = groups[key]
        if len(members) < min_sites:
            continue
        if n_groups >= MAX_PREDICATE_GROUPS:
            stats["caps_hit"] = True
            break
        sampled_from = 0
        if len(members) > MAX_SITES_PER_GROUP:
            # SEEDED-RANDOM survivors, never a deterministic prefix
            # (module docstring — anti-eviction).
            sampled_from = len(members)
            survivors = rnd.sample(members, MAX_SITES_PER_GROUP)
            chosen = {id(m) for m in survivors}
            for m in members:
                if id(m) not in chosen:
                    excluded_sites[(m.file, m.line, m.leg)] = (
                        REASON_CENSUS_DEGRADED
                    )
            members = survivors
            stats["caps_hit"] = True
        n = len(members)
        # Vote budget: operator + null-arm + wrong-var votes are one
        # pass each over the members; signedness adds per-member type
        # lookups. Charge before the walk; over budget → the group is
        # EXCLUDED (loud), never half-voted.
        group_cost = 4 * n
        if ops + group_cost > MAX_PREDICATE_OPS:
            stats["caps_hit"] = True
            _count(reasons, REASON_CENSUS_DEGRADED)
            group_skips[key] = REASON_CENSUS_DEGRADED
            continue
        ops += group_cost
        n_groups += 1

        if members[0].bound_is_call:
            # The bound expression is part of the group key, so a
            # call-shaped bound is a group-level property.
            _count(reasons, REASON_PREDICATE_DATA_DEPENDENT)
            group_skips[key] = REASON_PREDICATE_DATA_DEPENDENT
            continue

        # Macro-token divergence excludes a member from EVERY vote:
        # its predicate may differ through preprocessor configuration,
        # so treating it as a code deviant (or a conforming voter)
        # would compare different programs.
        modal_macros, _mc = _majority(
            [s.macro_tokens for s in members],
        )
        voters = [s for s in members if s.macro_tokens == modal_macros]
        if len(voters) != len(members):
            _count(
                reasons, REASON_MACRO_DIVERGENT,
                len(members) - len(voters),
            )
            for s in members:
                if s.macro_tokens != modal_macros:
                    excluded_sites[(s.file, s.line, s.leg)] = (
                        REASON_MACRO_DIVERGENT
                    )
        n = len(voters)
        if n < min_sites:
            group_skips[key] = REASON_MACRO_DIVERGENT
            continue

        if voters[0].leg == "deref":
            _vote_null_arm(voters, key, n, ratio, source_texts, _emit)
        else:
            if not _vote_operator(
                voters, key, n, ratio, reasons, signedness,
                source_texts, sampled_from, _emit,
            ):
                group_skips[key] = REASON_CENSUS_DEGRADED
                break
            _vote_wrong_variable(
                voters, key, n, ratio, sampled_from, _emit,
            )
            _vote_signedness(
                voters, key, n, min_sites, ratio, signedness,
                sampled_from, _emit,
            )
        if len(deviations) >= MAX_DEVIATIONS:
            stats["caps_hit"] = True
            # The cap closed the census mid-group: this group's later
            # votes never ran, so its members are NOT recorded voted.
            group_skips[key] = REASON_CENSUS_DEGRADED
            break
        voted_sites.update(
            (s.file, s.line, s.leg) for s in voters
        )

    stats["groups"] = n_groups
    stats["predicate_ops"] = ops + signedness.lookups
    deviations.sort(key=lambda d: (d.file, d.line, d.kind))
    if deviations or stats["caps_hit"]:
        logger.info(
            "guard-predicate census: %d sites, %d groups, %d "
            "deviation(s), %d ops%s",
            stats["sites"], n_groups, len(deviations),
            stats["predicate_ops"],
            " (caps hit)" if stats["caps_hit"] else "",
        )
    return deviations[:MAX_DEVIATIONS], stats


def _group_repr(key: tuple[str, ...]) -> str:
    if key[0] == "loop":
        return f"{key[1]}[{key[2]}]"
    return f"*->{key[1]}"


def _evidence(
    key: tuple[str, ...],
    deviant: _PredicateSite,
    conforming: list[_PredicateSite],
    n: int,
    sampled_from: int,
) -> PeerEvidence:
    # ``sampled_from`` disclosure travels on the deviation (and its
    # description); the receipt's integers describe the VOTED sample.
    return PeerEvidence(
        dimension=DIMENSION_GUARD_PREDICATE,
        formation=(
            "loop_guard" if deviant.leg == "loop" else "deref_guard"
        ),
        group_key=_group_repr(key),
        n=n,
        conforming=len(conforming),
        ratio=len(conforming) / n if n else 0.0,
        deviant=PeerExhibit(deviant.file, deviant.line, deviant.snippet),
        exhibits=[
            PeerExhibit(s.file, s.line, s.snippet)
            for s in conforming[:3]
        ],
        family=[
            FamilyMember(s.file, s.enclosing_function, s.line)
            for s in conforming
        ],
        contract_source="majority",
        provenance=f"guard_predicate:{deviant.leg}",
    )


def _vote_operator(
    members: list[_PredicateSite],
    key: tuple[str, ...],
    n: int,
    ratio: float,
    reasons: dict[str, int],
    signedness: _SignednessCache,
    source_texts: dict[str, str],
    sampled_from: int,
    emit: Any,
) -> bool:
    """Comparison-operator vote (off-by-one / operator drift).
    Returns False when the deviation cap closed the census."""
    modal_op, count = _majority([s.relop for s in members])
    if count == n or count / n < ratio:
        return True
    conforming = [s for s in members if s.relop == modal_op]
    for s in members:
        if s.relop == modal_op:
            continue
        dev_sign = signedness.get(s)
        maj_signs = [signedness.get(c) for c in conforming]
        resolved = [v for v in maj_signs if v is not None]
        if dev_sign is not None and resolved:
            modal_sign, sc = _majority(resolved)
            if sc == len(resolved) and dev_sign != modal_sign:
                _count(reasons, REASON_TYPE_CONTEXT_DIFFERS)
                continue
        kind = (
            KIND_OFF_BY_ONE
            if frozenset({s.relop, modal_op}) in _OFF_BY_ONE_PAIRS
            else KIND_OPERATOR_MISMATCH
        )
        ok = emit(GuardPredicateDeviation(
            kind=kind,
            group_key=_group_repr(key),
            file=s.file,
            line=s.line,
            enclosing_function=s.enclosing_function,
            n=n,
            conforming=len(conforming),
            majority_repr=f"{s.tested_var} {modal_op} {s.bound_expr}",
            deviant_repr=f"{s.tested_var} {s.relop} {s.bound_expr}",
            tested_var=s.tested_var,
            relop=s.relop,
            majority_relop=modal_op,
            bound_expr=s.bound_expr,
            cwe=_KIND_CWE[kind],
            sampled_from=sampled_from,
            deviant_guards=_dominating_guards(
                source_texts, s.file, s.line,
            ),
            peer_evidence=_evidence(
                key, s, conforming, n, sampled_from,
            ),
        ))
        if not ok:
            return False
    return True


def _vote_wrong_variable(
    members: list[_PredicateSite],
    key: tuple[str, ...],
    n: int,
    ratio: float,
    sampled_from: int,
    emit: Any,
) -> None:
    """Tested-identifier-vs-subscript-index vote (wrong-variable
    drift): peers test the index they subscript with; the deviant
    tests something else."""
    matches = [s.tested_var == s.index for s in members]
    conforming = [s for s, ok in zip(members, matches) if ok]
    c = len(conforming)
    if c == n or not c or c / n < ratio:
        return
    for s, ok in zip(members, matches):
        if ok:
            continue
        if not emit(GuardPredicateDeviation(
            kind=KIND_WRONG_VARIABLE,
            group_key=_group_repr(key),
            file=s.file,
            line=s.line,
            enclosing_function=s.enclosing_function,
            n=n,
            conforming=c,
            majority_repr=f"{s.index} {s.relop} {s.bound_expr}",
            deviant_repr=f"{s.tested_var} {s.relop} {s.bound_expr}",
            tested_var=s.tested_var,
            relop=s.relop,
            majority_relop=s.relop,
            bound_expr=s.bound_expr,
            cwe=_KIND_CWE[KIND_WRONG_VARIABLE],
            sampled_from=sampled_from,
            peer_evidence=_evidence(
                key, s, conforming, n, sampled_from,
            ),
        )):
            return


def _vote_signedness(
    members: list[_PredicateSite],
    key: tuple[str, ...],
    n: int,
    min_sites: int,
    ratio: float,
    signedness: _SignednessCache,
    sampled_from: int,
    emit: Any,
) -> None:
    """Declared-signedness vote: the majority's tested identifiers
    resolve to one signedness, the deviant's to the other.  Sites
    whose declaration does not resolve are excluded from the vote —
    never guessed."""
    resolved = [
        (s, sign) for s in members
        if (sign := signedness.get(s)) is not None
    ]
    if len(resolved) < min_sites:
        return
    modal_sign, c = _majority([sign for _s, sign in resolved])
    total = len(resolved)
    if c == total or c / total < ratio:
        return
    conforming = [s for s, sign in resolved if sign == modal_sign]
    for s, sign in resolved:
        if sign == modal_sign:
            continue
        maj_word = "unsigned" if modal_sign else "signed"
        dev_word = "unsigned" if sign else "signed"
        if not emit(GuardPredicateDeviation(
            kind=KIND_SIGNEDNESS_MIX,
            group_key=_group_repr(key),
            file=s.file,
            line=s.line,
            enclosing_function=s.enclosing_function,
            n=total,
            conforming=c,
            majority_repr=(
                f"{maj_word} {s.tested_var} {s.relop} {s.bound_expr}"
            ),
            deviant_repr=(
                f"{dev_word} {s.tested_var} {s.relop} {s.bound_expr}"
            ),
            tested_var=s.tested_var,
            relop=s.relop,
            majority_relop=s.relop,
            bound_expr=s.bound_expr,
            cwe=_KIND_CWE[KIND_SIGNEDNESS_MIX],
            sampled_from=sampled_from,
            peer_evidence=_evidence(
                key, s, conforming, total, sampled_from,
            ),
        )):
            return


def _vote_null_arm(
    members: list[_PredicateSite],
    key: tuple[str, ...],
    n: int,
    ratio: float,
    source_texts: dict[str, str],
    emit: Any,
) -> None:
    """Null-arm presence vote on the deref-guard leg."""
    conforming = [s for s in members if s.has_null_arm]
    c = len(conforming)
    if c == n or not c or c / n < ratio:
        return
    for s in members:
        if s.has_null_arm:
            continue
        if not emit(GuardPredicateDeviation(
            kind=KIND_MISSING_NULL_ARM,
            group_key=_group_repr(key),
            file=s.file,
            line=s.line,
            enclosing_function=s.enclosing_function,
            n=n,
            conforming=c,
            majority_repr=(
                f"{s.base} && {s.base}->{s.field_name} {s.relop} "
                f"{s.bound_expr}"
            ),
            deviant_repr=(
                f"{s.base}->{s.field_name} {s.relop} {s.bound_expr}"
            ),
            tested_var=s.tested_var,
            relop=s.relop,
            majority_relop=s.relop,
            bound_expr=s.bound_expr,
            cwe=_KIND_CWE[KIND_MISSING_NULL_ARM],
            deviant_guards=_dominating_guards(
                source_texts, s.file, s.line,
            ),
            peer_evidence=_evidence(key, s, conforming, n, 0),
        )):
            return
