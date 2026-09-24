"""Disasm-level check vectors for binary peer-group members.

Feeds :mod:`core.audit.sibling_analysis`'s property-vector comparison
with per-member safety properties extracted from the binary lane's
PERSISTED artifacts — no new disassembler pass runs here. Two vector
families:

* **Called-helper presence** (``calls:<key>``) — which cluster-
  frequent distinctive helpers each member calls, keyed by fid when
  the substrate carries one, name otherwise, from a persisted call
  substrate (re-database xrefs, map call subgraph, edge cache).
  Evidence tier: ``xref_backed``.
* **Compare-operand constants** (``cmp:<const>``, plus the derived
  ``null_check_present`` / ``length_cap_present``) — decoded
  compare facts where a producer persisted them
  (``decoded_instruction`` tier), else constants parsed from the
  member's persisted decompilation (``decompiler_inferred`` tier —
  the honesty gap between the two is carried per member, never
  averaged away). A member with NEITHER source contributes no
  compare properties at all: absence of evidence must not read as
  absence of the check, so the engine's majority count simply never
  sees that member for those properties.

The comparison itself stays in ``sibling_analysis.find_asymmetries``
— this module only fills ``SiblingPath.properties`` and returns the
member×check matrix for the artifact writer.

Honesty (also emitted with every artifact): check presence is
SYNTACTIC. A call edge or a decoded compare proves the instruction
exists, not that it executes before the dangerous operation, not
that it dominates it, and not that its result is honoured. Every
consumer must render outliers as review leads with a disproof
recipe, never as findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.evidence import EvidenceTier

from .sibling_analysis import SiblingGroup

#: Callee-presence checks per group. Both directions: more checks
#: give the engine more columns but let one flooded member (a decoy
#: calling hundreds of planted helpers) inflate every sibling's
#: matrix and prompt; fewer can miss the one helper the outlier
#: skips. 12 covers real validator/emitter/logging splits; selection
#: is frequency-then-name deterministic, so a flood shifts nothing.
MAX_CALLEE_CHECKS = 12

#: Compare-constant checks per group — same trade-off as above; a
#: hostile decompilation can embed thousands of distinct constants,
#: so only constants at least two members compare against become
#: columns, capped frequency-first.
MAX_CONSTANT_CHECKS = 12

#: Decompiled text scanned per member for compare constants. Both
#: directions: a longer window reads more of a genuinely huge
#: function but hands hostile multi-MB pseudo-code a per-member
#: regex budget; shorter misses late checks in long bodies. Matches
#: the similarity seam's shingle text cap — one notion of "enough
#: decompilation".
MAX_DECOMP_SCAN_CHARS = 262_144

#: Decoded compare records consumed per member — a planted evidence
#: file must not turn the matrix build quadratic. Real check-sites
#: per function are a handful.
MAX_DECODED_RECORDS = 64

#: Constants 0 and 1 are flag/null idioms, not length caps; a
#: relational compare against >= this value is counted as a bound.
_MIN_LENGTH_CAP_CONST = 2

# Relational / equality compares against an integer literal, both
# orders. Hostile pseudo-code runs through these, so every span is
# BOUNDED: the operator-to-operand gap is one character class with a
# fixed window (no adjacent overlapping repeats), literals carry
# length ceilings, and the leading-digit branch is guarded so a long
# digit run is one attempt, not one per digit. The relational atom
# is shift-guarded — ``x << 2`` / ``x >>= 2`` are arithmetic, not
# bounds checks, and an unguarded ``[<>]`` read them as compares
# (junk cmp: columns and a false length_cap_present on shift-dense
# members).
_REL_OP = r"(?<![<>])[<>](?![<>])=?"
_CMP_RE = re.compile(
    rf"(?:{_REL_OP}|[!=]=)[\s(]{{0,8}}"
    r"(0x[0-9a-fA-F]{1,16}|\d{1,10})(?![\w.])"
    r"|(?<![\w.])(0x[0-9a-fA-F]{1,16}|\d{1,10})[\s)]{0,8}"
    rf"(?:{_REL_OP}|[!=]=)",
)
_RELATIONAL_RE = re.compile(
    rf"{_REL_OP}[\s(]{{0,8}}"
    r"(0x[0-9a-fA-F]{1,16}|\d{1,10})(?![\w.])"
    r"|(?<![\w.])(0x[0-9a-fA-F]{1,16}|\d{1,10})[\s)]{0,8}"
    rf"{_REL_OP}",
)
# Null-pointer idioms in decompiler pseudo-C: `== NULL`, `!= 0x0`
# (with an optional cast), `if (!ptr)`.
_NULL_RE = re.compile(
    r"[=!]=\s*(?:\([^)]{0,40}\)\s*)?(?:NULL|nullptr|0x0)\b"
    r"|\bif\s*\(\s*!\s*[A-Za-z_]",
)

# Tier values ride into artifacts and the hypothesis intake, whose
# loader refuses unknown spellings — derive from the canonical enum
# so a vocabulary change breaks here, not at the consumer.
_TIER_XREF = EvidenceTier.XREF_BACKED.value
_TIER_DECODED = EvidenceTier.DECODED_INSTRUCTION.value
_TIER_DECOMP = EvidenceTier.DECOMPILER_INFERRED.value
_NO_EVIDENCE = "no_evidence"

CHECKS_ARE_SYNTACTIC_NOTE = (
    "Check presence is syntactic: a call edge or decoded compare "
    "proves the instruction exists, not that it executes, dominates "
    "the dangerous operation, or has its result honoured. A dead or "
    "dominated check satisfies every column here."
)


@dataclass
class MemberVector:
    """One member's row in the check matrix."""

    function: str
    fid: str | None = None
    #: check key → True/False; a key ABSENT from this dict means "no
    #: evidence either way" and is withheld from the engine.
    checks: dict[str, bool] = field(default_factory=dict)
    #: check key → evidence tier value (core.evidence spelling), or
    #: ``no_evidence`` in the compare summary below.
    tiers: dict[str, str] = field(default_factory=dict)
    #: Where this member's compare facts came from:
    #: decoded_instruction / decompiler_inferred / no_evidence.
    compare_source: str = _NO_EVIDENCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "fid": self.fid,
            "checks": dict(self.checks),
            "tiers": dict(self.tiers),
            "compare_source": self.compare_source,
        }


@dataclass
class GroupCheckVectors:
    """The member×check matrix for one peer group."""

    group_id: str
    check_keys: list[str] = field(default_factory=list)
    members: list[MemberVector] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "check_keys": list(self.check_keys),
            "members": [m.to_dict() for m in self.members],
            "notes": list(self.notes),
        }


def _escape(value: Any) -> str:
    from core.security.log_sanitisation import escape_nonprintable
    return escape_nonprintable(str(value))[:200]


def _parse_const(value: Any) -> int | None:
    """Non-negative int from an int or hex/decimal string; junk
    collapses to None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        text = value.strip().lower()
        try:
            parsed = int(text, 16) if text.startswith("0x") else int(text)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _decoded_member_compares(records: Any) -> list[int] | None:
    """Compare constants from persisted decoded evidence.

    Consume-if-present seam: a record is any dict carrying an
    ``operand`` / ``constant`` value (the decoded parser-tracing
    producers' shape). Returns ``None`` when no usable record exists
    — the caller then falls back to decompilation.
    """
    if not isinstance(records, list):
        return None
    consts: list[int] = []
    usable = False
    for record in records[:MAX_DECODED_RECORDS]:
        if not isinstance(record, dict):
            continue
        value = record.get("operand", record.get("constant"))
        parsed = _parse_const(value)
        if parsed is not None:
            usable = True
            consts.append(parsed)
    return sorted(set(consts)) if usable else None


def _decomp_compare_facts(
    text: str,
) -> tuple[list[int], bool, bool]:
    """(compare constants, null_check_present, length_cap_present)
    parsed from persisted decompiled pseudo-code."""
    subject = str(text)[:MAX_DECOMP_SCAN_CHARS]
    consts: set[int] = set()
    for m in _CMP_RE.finditer(subject):
        parsed = _parse_const(m.group(1) or m.group(2))
        if parsed is not None:
            consts.add(parsed)
    null_check = bool(_NULL_RE.search(subject))
    length_cap = False
    for m in _RELATIONAL_RE.finditer(subject):
        parsed = _parse_const(m.group(1) or m.group(2))
        if parsed is not None and parsed >= _MIN_LENGTH_CAP_CONST:
            length_cap = True
            break
    return sorted(consts), null_check, length_cap


def extract_group_check_vectors(
    group: SiblingGroup,
    *,
    callees_by_function: dict[str, set[str]] | None = None,
    distinctive_callees: set[str] | None = None,
    fid_by_function: dict[str, str | None] | None = None,
    callee_fids: dict[str, str] | None = None,
    decomp_texts: dict[str, str] | None = None,
    decoded_compares: dict[str, Any] | None = None,
) -> GroupCheckVectors:
    """Fill ``group``'s member properties and return the check matrix.

    Mutates each :class:`SiblingPath`'s ``properties`` in place — the
    same intake ``find_asymmetries`` reads for every source-lane
    vector — and returns the artifact-facing matrix with per-check
    evidence tiers.

    ``distinctive_callees`` (when given) restricts callee checks to
    the caller's distinctiveness set (the peer-group hub ceiling);
    without it every cluster-frequent callee is eligible.
    ``callee_fids`` maps callee names to fids so check columns key on
    identity, not spelling, where the substrate allows.
    """
    callees_by_function = callees_by_function or {}
    fid_by_function = fid_by_function or {}
    callee_fids = callee_fids or {}
    decomp_texts = decomp_texts or {}
    decoded_compares = decoded_compares or {}

    result = GroupCheckVectors(group_id=group.group_id)
    members = list(group.siblings)
    if not members:
        return result

    vectors: dict[str, MemberVector] = {}
    for sib in members:
        vectors[sib.function] = MemberVector(
            function=sib.function,
            fid=fid_by_function.get(sib.function),
        )

    # ── Called-helper presence ────────────────────────────────────
    # Withholding discipline (same as the compare family below): a
    # member ABSENT from the substrate (no caller record at all —
    # indirect-call-only bodies, substrate gaps) contributes NO calls
    # columns. Counting it as "calls nothing" would mint a false
    # outlier wearing the xref_backed label; absence of evidence is
    # not absence of the call.
    member_callees: dict[str, set[str]] = {
        sib.function: set(callees_by_function[sib.function])
        for sib in members
        if sib.function in callees_by_function
    }
    counts: dict[str, int] = {}
    for callee_set in member_callees.values():
        for callee in callee_set:
            counts[callee] = counts.get(callee, 0) + 1
    eligible = [
        callee for callee, count in counts.items()
        if count >= 2 and (
            distinctive_callees is None or callee in distinctive_callees
        )
    ]
    # Frequency-first then name: deterministic, and a flood of
    # single-member decoy callees never displaces the real columns.
    eligible.sort(key=lambda c: (-counts[c], c))
    for callee in eligible[:MAX_CALLEE_CHECKS]:
        callee_key = callee_fids.get(callee) or _escape(callee)
        key = f"calls:{callee_key}"
        result.check_keys.append(key)
        for sib in members:
            if sib.function not in member_callees:
                continue  # withheld: no substrate record at all
            present = callee in member_callees[sib.function]
            vec = vectors[sib.function]
            vec.checks[key] = present
            vec.tiers[key] = _TIER_XREF
            sib.properties[key] = present
    if len(eligible) > MAX_CALLEE_CHECKS:
        result.notes.append(
            f"callee checks capped at {MAX_CALLEE_CHECKS} of "
            f"{len(eligible)} (kept frequency-first)"
        )

    # ── Compare-operand constants ─────────────────────────────────
    member_consts: dict[str, list[int]] = {}
    member_flags: dict[str, tuple[bool, bool]] = {}
    for sib in members:
        vec = vectors[sib.function]
        decoded = _decoded_member_compares(
            decoded_compares.get(sib.function))
        if decoded is not None:
            member_consts[sib.function] = decoded
            # Decoded producers persist raw compare sites; derive the
            # two contract booleans from the same facts.
            member_flags[sib.function] = (
                0 in decoded,
                any(c >= _MIN_LENGTH_CAP_CONST for c in decoded),
            )
            vec.compare_source = _TIER_DECODED
            continue
        text = decomp_texts.get(sib.function)
        if text:
            consts, null_check, length_cap = _decomp_compare_facts(text)
            member_consts[sib.function] = consts
            member_flags[sib.function] = (null_check, length_cap)
            vec.compare_source = _TIER_DECOMP
        # else: no evidence — contributes nothing (absence of
        # evidence is not absence of the check).

    const_counts: dict[int, int] = {}
    for consts in member_consts.values():
        for const in consts:
            const_counts[const] = const_counts.get(const, 0) + 1
    frequent = [c for c, n in const_counts.items() if n >= 2]
    frequent.sort(key=lambda c: (-const_counts[c], c))
    for const in frequent[:MAX_CONSTANT_CHECKS]:
        key = f"cmp:{const:#x}"
        result.check_keys.append(key)
        for sib in members:
            if sib.function not in member_consts:
                continue  # withheld: no compare evidence at all
            vec = vectors[sib.function]
            present = const in member_consts[sib.function]
            vec.checks[key] = present
            vec.tiers[key] = vec.compare_source
            sib.properties[key] = present
    if len(frequent) > MAX_CONSTANT_CHECKS:
        result.notes.append(
            f"compare-constant checks capped at {MAX_CONSTANT_CHECKS} "
            f"of {len(frequent)} (kept frequency-first)"
        )

    for key, index in (("null_check_present", 0),
                       ("length_cap_present", 1)):
        emitted = False
        for sib in members:
            flags = member_flags.get(sib.function)
            if flags is None:
                continue
            vec = vectors[sib.function]
            vec.checks[key] = flags[index]
            vec.tiers[key] = vec.compare_source
            sib.properties[key] = flags[index]
            emitted = True
        if emitted:
            result.check_keys.append(key)

    result.members = [vectors[sib.function] for sib in members]
    result.notes.append(CHECKS_ARE_SYNTACTIC_NOTE)
    return result


__all__ = [
    "CHECKS_ARE_SYNTACTIC_NOTE",
    "GroupCheckVectors",
    "MAX_CALLEE_CHECKS",
    "MAX_CONSTANT_CHECKS",
    "MemberVector",
    "extract_group_check_vectors",
]
