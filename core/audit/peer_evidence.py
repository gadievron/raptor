"""PeerEvidence — the first-class receipt type for consistency evidence.

One shared receipt for every "n peers do X, this one differs" claim
(design §4.1): the return-check census, the flag/mode and cleanup
comparators, ``negative_space`` retro-fits, ``fail_open``'s
``corroboration[]`` (this type *is* the majority-evidence leg that
design planned ad hoc), and the review-prompt renderer all consume the
same shape.

Namespace policy (§4.2): every dimension emits rule-ids under the
single ``consistency`` tool namespace — ``consistency:<dimension>``
for verification-role verdicts (registry-grade contract witness) and
``consistency:<dimension>-majority`` for detection-role variants.
One namespace, deliberately: all dimensions share the majority-
statistic epistemology, so two consistency dimensions agreeing must
never count as two independent namespaces in the aggregation
posterior (the self-corroboration firewall — the same reasoning that
keeps ``git_history`` a corroboration kind, applied to statistics).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Single tool namespace for every consistency dimension (§4.2).
CONSISTENCY_NAMESPACE = "consistency"

# Detection-role rule-id variants carry this suffix; they may never
# promote alone (evidence_grade refuses them as standalone tool
# evidence) and participate in cross-namespace aggregation only.
DETECTION_VARIANT_SUFFIX = "-majority"

# Cap on conforming-sibling exhibits carried per receipt (§4.1).
MAX_EXHIBITS = 3

# Contract sources that are registry-grade (promote-capable premise),
# in §2.2 strength order. ``type_witness`` is the §3.6 argument-shape
# premise: a deterministic declared-type fact (sizeof over a pointer
# where the siblings pass the pointed-to buffer's size) — provable
# without any majority, so it is registry-grade like the other
# deterministic sources. ``smt_witness`` is its §3.4 guard-presence
# sibling: the condition_smt sufficiency checker proved the deviant's
# unguarded path feasible (concrete witness) — a deterministic solver
# fact, with the sibling majority as corroboration.
_REGISTRY_SOURCES_ORDERED = (
    "wur", "annotation", "domain_model", "iris_spec", "convention",
    "fix_commit", "tier_a", "type_witness", "smt_witness",
)

REGISTRY_CONTRACT_SOURCES = frozenset(_REGISTRY_SOURCES_ORDERED)

# Every contract source a PeerEvidence receipt can carry (§2.2 order):
# the registry-grade premises, then the detection-grade statistical
# source and the explicit absence marker.
CONTRACT_SOURCES = (*_REGISTRY_SOURCES_ORDERED, "majority", "none")


def rule_id(dimension: str, *, detection: bool) -> str:
    """``consistency:<dimension>`` / ``consistency:<dimension>-majority``."""
    base = f"{CONSISTENCY_NAMESPACE}:{dimension}"
    return base + DETECTION_VARIANT_SUFFIX if detection else base


def is_detection_rule_id(tool_id: str) -> bool:
    """True for the detection-grade ``-majority`` variants: they never
    promote alone, only aggregate across independent namespaces."""
    return tool_id.startswith(f"{CONSISTENCY_NAMESPACE}:") and \
        tool_id.endswith(DETECTION_VARIANT_SUFFIX)


@dataclass(frozen=True)
class PeerExhibit:
    """One peer call site / sibling, quotable in a receipt."""

    file: str
    line: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet[:200],
        }


@dataclass
class PeerEvidence:
    """Majority-vs-deviant receipt for one consistency claim (§4.1)."""

    dimension: str        # "return-check" | "cleanup" | "flag-mode" | ...
    formation: str        # peer_groups layer id (l0_co_callee..l6_paired)
                          #   | same_callee | same_callee_pair
                          #   | same_sink | same_field | clone
                          #   | branch | interface
    group_key: str        # callee / sink / table / clone-cluster id
    n: int = 0
    conforming: int = 0
    ratio: float = 0.0
    deviant: PeerExhibit | None = None
    exhibits: list[PeerExhibit] = field(default_factory=list)
    contract_source: str = "none"
    provenance: str = ""  # e.g. "iris_spec:xref_backed", "wur:harvested"
    #: Similarity-weighted membership (clone-family formation): the
    #: weighted family size / weighted conformer mass. OPTIONAL and
    #: unset today — no producer emits them yet; the fields exist so
    #: readers never misread the integer ``n``/``conforming`` as the
    #: basis of a weighted ratio once a weighting layer lands.
    #: Serialization is additive (emitted only when set) and readers
    #: must tolerate their absence.
    weighted_n: float | None = None
    weighted_conforming: float | None = None

    def __post_init__(self) -> None:
        if len(self.exhibits) > MAX_EXHIBITS:
            self.exhibits = self.exhibits[:MAX_EXHIBITS]

    @property
    def registry_grade(self) -> bool:
        return self.contract_source in REGISTRY_CONTRACT_SOURCES

    @property
    def rule_id(self) -> str:
        return rule_id(self.dimension, detection=not self.registry_grade)

    @property
    def score(self) -> float:
        """Lead-strength ranking score: the Wilson lower bound of
        ``conforming / n`` — a monotone shrinkage score for small-N
        ranking, NOT a confidence claim (family members are
        copy-paste-correlated and the census is exhaustive; see
        :mod:`core.audit.consistency_stats`). Computed from the
        integer fields even when the weighted fields are set —
        weighted scoring waits for a producer of the weights."""
        from .consistency_stats import lead_strength_score
        return lead_strength_score(self.conforming, self.n)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": "peer_evidence",
            "dimension": self.dimension,
            "formation": self.formation,
            "group_key": self.group_key,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "score": round(self.score, 4),
            "exhibits": [e.to_dict() for e in self.exhibits],
            "contract_source": self.contract_source,
            "provenance": self.provenance,
            "rule_id": self.rule_id,
        }
        if self.deviant is not None:
            d["deviant"] = self.deviant.to_dict()
        if self.weighted_n is not None:
            d["weighted_n"] = round(self.weighted_n, 3)
        if self.weighted_conforming is not None:
            d["weighted_conforming"] = round(self.weighted_conforming, 3)
        return d
