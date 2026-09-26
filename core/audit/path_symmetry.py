"""Path-symmetry consistency census (paired-path parity).

"Four set_*/get_* pairs validate on the write side; the fifth
setter doesn't."  Reader/writer, parser/serializer and getter/setter
pairs are two paths over the same state; this census forms 1:1 verb
pairs over the tree's own function definitions and votes safety
properties per SIDE across the cohort of pairs — does the mutating
side carry the checks its cohort's mutating sides carry (and the
reading side likewise)?

Pairing vocabulary is a small generic verb seed (get/set,
read/write, parse/serialize, ...) extended by verb heads learned
from the study's ``paired_operations`` — project API names are never
hardcoded here.  Pairing is 1:1 by stem join, never a combination
materialization: a stem with several candidates on either side is
the enumerated ``pairing-unresolved`` inconclusive.

Verdict discipline: every deviation is a majority statistic —
detection-grade leads under the single consistency namespace
(``consistency:path-symmetry-majority``), prepass-lead-only, never a
finding on their own.  Enumerated inconclusive reasons:

* ``pairing-unresolved`` — the stem joins ambiguously; picking a
  counterpart would be a guess.
* ``asymmetry-by-contract`` — a study contract covers the deviant
  function; the asymmetry may be declared, so the lead is withheld.

Hostile-repo bounds: verb-pair vocabulary, families, cohort
membership and total vote work carry named caps with an in-band
``caps_hit`` marker; over-cap cohort survivors are SEEDED-RANDOM,
never a deterministic prefix (pairs arrive in sorted-name order, and
a first-N cut would let conforming decoy pairs evict the real
deviant).
"""

from __future__ import annotations

import logging
import os
import random
import re
from dataclasses import dataclass
from typing import Any

from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

DIMENSION_PATH_SYMMETRY = "path-symmetry"

# Cohort floor and majority ratio for a parity lead.  Inline per the
# threshold-residence convention (registry-enumerated in
# consistency_stats, overridable via the audit run-config only).
# 3/0.75 are the engine-wide group floors: below three pairs a
# "majority" is one pair outvoting another; a lower ratio flags
# legitimately mixed cohorts, a higher one hides real drift in small
# families.
PATH_SYMMETRY_MIN_PAIRS = 3
PATH_SYMMETRY_RATIO = 0.75

REASON_PAIRING_UNRESOLVED = "pairing-unresolved"
REASON_ASYMMETRY_BY_CONTRACT = "asymmetry-by-contract"

#: Generic English verb pairs, (reading side, mutating side).  A
#: SEED, not a project vocabulary — study-learned verb heads extend
#: it at run time.
_SEED_VERB_PAIRS: tuple[tuple[str, str], ...] = (
    ("get", "set"),
    ("read", "write"),
    ("load", "store"),
    ("parse", "serialize"),
    ("decode", "encode"),
    ("unpack", "pack"),
    ("recv", "send"),
)

#: Verb pairs voted per run (seed + learned).  Both directions: more
#: lets a hostile study/domain-model flood mint a vocabulary-per-run;
#: fewer drops learned project verbs.  24 comfortably covers the
#: seed plus a real study's discovered pairs.
MAX_VERB_PAIRS = 24

#: Pairs per cohort at vote intake (the comparator family ceiling
#: class — consistency_dimensions.MAX_FAMILY_MEMBERS rationale).
MAX_PAIRS_PER_FAMILY = 32

#: Total vote work per run (pair-property checks).  Both directions:
#: higher re-opens the generated-cohort DoS; lower truncates
#: legitimately getter-heavy trees (truncation is marked in-band,
#: never partial-silent).
MAX_VOTE_OPS = 100_000

#: Deviations returned per run (engine-wide deviation cap class).
MAX_DEVIATIONS = 80

_VERB_RE = re.compile(r"^[a-z][a-z0-9]{2,15}$")

_SIDE_READ = "read"
_SIDE_WRITE = "write"

_PROPERTY_CWE = {
    "auth_check": "CWE-862",
    "null_guard": "CWE-20",
    "bounds_guard": "CWE-20",
    "error_handling": "CWE-20",
}


@dataclass
class _PairedFunction:
    """One resolved pair member."""

    file: str
    line: int
    name: str
    properties: dict[str, bool]


@dataclass
class _ResolvedPair:
    """One 1:1 verb pair (reading side, mutating side)."""

    stem: str
    read: _PairedFunction
    write: _PairedFunction

    def side(self, side: str) -> _PairedFunction:
        return self.read if side == _SIDE_READ else self.write

    def other(self, side: str) -> _PairedFunction:
        return self.write if side == _SIDE_READ else self.read


@dataclass
class PathSymmetryDeviation:
    """One pair whose side lacks a property its cohort's sides carry."""

    verb_pair: str         # "get/set"
    side: str              # "read" | "write"
    property_name: str
    file: str
    line: int
    enclosing_function: str
    counterpart: str       # the pair's other-side function name
    counterpart_has: bool  # property present on the other side
    n: int
    conforming: int
    cwe: str = ""
    #: When the cohort exceeded MAX_PAIRS_PER_FAMILY at intake, the
    #: ORIGINAL cohort size (0 = no sampling).
    sampled_from: int = 0
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        base = (
            f"{self.conforming}/{self.n} {self.verb_pair} pairs "
            f"perform {self.property_name} on the {self.side} side; "
            f"{self.enclosing_function} does not"
        )
        if self.counterpart_has:
            base += (
                f" (its own counterpart {self.counterpart} does — "
                f"the check exists in the pair's other path)"
            )
        if self.sampled_from:
            base += (
                f" (vote over a seeded sample of {self.n} of the "
                f"cohort's {self.sampled_from} pairs)"
            )
        return base

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "verb_pair": self.verb_pair,
            "side": self.side,
            "property": self.property_name,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "counterpart": self.counterpart,
            "counterpart_has": self.counterpart_has,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "cwe": self.cwe,
        }
        if self.sampled_from:
            d["sampled_from"] = self.sampled_from
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


def _verb_heads(a_name: str, b_name: str) -> tuple[str, str] | None:
    """The differing verb segments of a learned operation pair —
    prefix-verb style first (``open_dev``/``close_dev`` → open/close),
    suffix-verb style second (``dev_open``/``dev_close`` → same)."""
    a_parts, b_parts = a_name.split("_"), b_name.split("_")
    if a_parts[0] != b_parts[0]:
        return a_parts[0], b_parts[0]
    if a_parts[-1] != b_parts[-1]:
        return a_parts[-1], b_parts[-1]
    return None


def verb_pair_vocabulary(
    domain_model: dict[str, Any] | None,
) -> list[tuple[str, str]]:
    """Seed verb pairs plus verb heads learned from the study's
    ``paired_operations`` (charset-validated, deduplicated, capped).
    The learned entry's (acquire, release) order maps to
    (read, write) order positionally — the census only needs a
    consistent side labelling within one vocabulary entry."""
    vocab: list[tuple[str, str]] = list(_SEED_VERB_PAIRS)
    seen = {p for p in vocab}
    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        heads = _verb_heads(
            str(entry.get("acquire") or "").strip(),
            str(entry.get("release") or "").strip(),
        )
        if heads is None:
            continue
        a, b = heads
        if not (_VERB_RE.match(a) and _VERB_RE.match(b)):
            continue
        pair = (a, b)
        if pair in seen or (b, a) in seen:
            continue
        if len(vocab) >= MAX_VERB_PAIRS:
            break
        seen.add(pair)
        vocab.append(pair)
    return vocab


def _stem_of(name: str, verb: str) -> str | None:
    """The stem of *name* under *verb* prefix — snake (``get_foo`` →
    ``foo``) or camel (``getFoo`` → ``Foo``); styles never cross-join
    (the stem keeps its case)."""
    if name.startswith(verb + "_") and len(name) > len(verb) + 1:
        return name[len(verb) + 1:]
    if (
        name.startswith(verb)
        and len(name) > len(verb)
        and name[len(verb)].isupper()
    ):
        return name[len(verb):]
    return None


def _contract_names(domain_model: dict[str, Any] | None) -> frozenset[str]:
    names: set[str] = set()
    for entry in (domain_model or {}).get("contracts") or []:
        if not isinstance(entry, dict):
            continue
        name = str(
            entry.get("function") or entry.get("name") or "",
        ).strip()
        if name:
            names.add(name)
    return frozenset(names)


def detect_path_symmetry_deviations(
    source_texts: dict[str, str],
    *,
    domain_model: dict[str, Any] | None = None,
    min_pairs: int = PATH_SYMMETRY_MIN_PAIRS,
    ratio: float = PATH_SYMMETRY_RATIO,
    seed: bytes | None = None,
) -> tuple[list[PathSymmetryDeviation], dict[str, Any]]:
    """Run the census.  Returns ``(deviations, stats)``.

    ``stats``: ``pairs`` (resolved 1:1 pairs), ``families`` (cohorts
    that reached a vote), ``vote_ops`` (pair-property work performed
    — the cost-rail pin reads it), ``caps_hit``,
    ``inconclusive_reasons`` (enumerated, module docstring).

    *seed* keys the over-cap survivor sampling; callers leave it
    ``None`` (fresh entropy per run) outside tests.
    """
    reasons: dict[str, int] = {}
    stats: dict[str, Any] = {
        "pairs": 0, "families": 0, "vote_ops": 0,
        "caps_hit": False, "inconclusive_reasons": reasons,
    }
    from .consistency_dimensions import (
        _function_spans,
        _interface_properties,
    )

    spans = _function_spans(source_texts)
    if not spans:
        return [], stats

    functions: dict[str, _PairedFunction] = {}
    duplicated: set[str] = set()
    for file_path, name, start, body in spans:
        if not name or name == "<module>":
            continue
        if name in functions:
            # Same-named definitions (per-platform variants): the
            # stem join below must not pick one arbitrarily.
            duplicated.add(name)
            continue
        functions[name] = _PairedFunction(
            file=file_path,
            line=start,
            name=name,
            properties=_interface_properties("\n".join(body)),
        )

    vocab = verb_pair_vocabulary(domain_model)
    contract_covered = _contract_names(domain_model)
    rnd = random.Random(seed if seed is not None else os.urandom(16))

    deviations: list[PathSymmetryDeviation] = []
    ops = 0
    n_pairs = 0
    n_families = 0
    for read_verb, write_verb in vocab:
        # Stem indexes per side, linear over the name set.
        by_stem: dict[str, dict[str, list[str]]] = {}
        for name in functions:
            for side, verb in (
                (_SIDE_READ, read_verb), (_SIDE_WRITE, write_verb),
            ):
                stem = _stem_of(name, verb)
                if stem is not None:
                    by_stem.setdefault(
                        stem, {_SIDE_READ: [], _SIDE_WRITE: []},
                    )[side].append(name)
        pairs: list[_ResolvedPair] = []
        for stem in sorted(by_stem):
            sides = by_stem[stem]
            reads = sides[_SIDE_READ]
            writes = sides[_SIDE_WRITE]
            if not reads or not writes:
                continue
            if (
                len(reads) > 1 or len(writes) > 1
                or reads[0] in duplicated
                or writes[0] in duplicated
            ):
                reasons[REASON_PAIRING_UNRESOLVED] = (
                    reasons.get(REASON_PAIRING_UNRESOLVED, 0) + 1
                )
                continue
            pairs.append(_ResolvedPair(
                stem=stem,
                read=functions[reads[0]],
                write=functions[writes[0]],
            ))
        if len(pairs) < min_pairs:
            continue
        n_pairs += len(pairs)

        sampled_from = 0
        if len(pairs) > MAX_PAIRS_PER_FAMILY:
            # SEEDED-RANDOM survivors, never a deterministic prefix
            # (module docstring — anti-eviction).
            sampled_from = len(pairs)
            pairs = rnd.sample(pairs, MAX_PAIRS_PER_FAMILY)
            stats["caps_hit"] = True
        n = len(pairs)
        group_cost = 2 * len(_PROPERTY_CWE) * n
        if ops + group_cost > MAX_VOTE_OPS:
            stats["caps_hit"] = True
            continue
        ops += group_cost
        n_families += 1

        verb_pair = f"{read_verb}/{write_verb}"
        for side in (_SIDE_WRITE, _SIDE_READ):
            for prop, cwe in _PROPERTY_CWE.items():
                conforming = [
                    p for p in pairs if p.side(side).properties[prop]
                ]
                c = len(conforming)
                if c == n or not c or c / n < ratio:
                    continue
                exhibits = [
                    PeerExhibit(
                        p.side(side).file, p.side(side).line,
                        f"{p.side(side).name} performs {prop}",
                    )
                    for p in conforming[:3]
                ]
                for p in pairs:
                    member = p.side(side)
                    if member.properties[prop]:
                        continue
                    if member.name in contract_covered:
                        reasons[REASON_ASYMMETRY_BY_CONTRACT] = (
                            reasons.get(
                                REASON_ASYMMETRY_BY_CONTRACT, 0,
                            ) + 1
                        )
                        continue
                    other = p.other(side)
                    deviations.append(PathSymmetryDeviation(
                        verb_pair=verb_pair,
                        side=side,
                        property_name=prop,
                        file=member.file,
                        line=member.line,
                        enclosing_function=member.name,
                        counterpart=other.name,
                        counterpart_has=other.properties[prop],
                        n=n,
                        conforming=c,
                        cwe=cwe,
                        sampled_from=sampled_from,
                        peer_evidence=PeerEvidence(
                            dimension=DIMENSION_PATH_SYMMETRY,
                            formation="verb_pair",
                            group_key=f"{verb_pair}:{side}:{prop}",
                            n=n,
                            conforming=c,
                            ratio=c / n,
                            deviant=PeerExhibit(
                                member.file, member.line,
                                f"{member.name} lacks {prop} on the "
                                f"{side} side",
                            ),
                            exhibits=exhibits,
                            contract_source="majority",
                            provenance=f"path_symmetry:{verb_pair}",
                        ),
                    ))
                    if len(deviations) >= MAX_DEVIATIONS:
                        stats["caps_hit"] = True
                        break
                if len(deviations) >= MAX_DEVIATIONS:
                    break
            if len(deviations) >= MAX_DEVIATIONS:
                break
        if len(deviations) >= MAX_DEVIATIONS:
            break

    stats["pairs"] = n_pairs
    stats["families"] = n_families
    stats["vote_ops"] = ops
    deviations.sort(
        key=lambda d: (d.file, d.line, d.property_name, d.side),
    )
    if deviations or stats["caps_hit"]:
        logger.info(
            "path-symmetry census: %d pairs, %d cohorts, %d "
            "deviation(s), %d ops%s",
            n_pairs, n_families, len(deviations), ops,
            " (caps hit)" if stats["caps_hit"] else "",
        )
    return deviations[:MAX_DEVIATIONS], stats
