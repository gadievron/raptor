"""Three-layer failure mode handling for /audit.

When Joern (mechanical/CPG), LLM inference, and Frida (dynamic
observation) disagree about a finding, this module applies a
principled resolution policy and logs disagreements as high-value
review artefacts.

Three failure modes handled:

1. Disagreement resolution — mechanical outweighs LLM unless the
   LLM articulates a specific evasion mechanism (dynamic dispatch,
   computed goto, signal handler, longjmp, runtime codegen).

2. Observation window bias — Frida absence is NOT evidence of absence.
   Each finding carries an observation status.  Functions that remain
   unobserved after dynamic analysis have their evidence tier capped.

3. CPG completeness — per-language confidence weights for Joern results.
   A Joern "not reachable" in C is reliable; in Ruby it's suggestive.
"""

from __future__ import annotations

import enum
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .evidence_grade import Confidence

logger = logging.getLogger(__name__)

_VALID_EVASION_MECHANISMS = frozenset({
    "dynamic_dispatch",
    "vtable",
    "callback",
    "dlsym",
    "reflection",
    "computed_goto",
    "signal_handler",
    "longjmp",
    "runtime_codegen",
    "eval",
    "method_missing",
    "monkey_patching",
    "prototype_chain",
})


class ObservationStatus(str, enum.Enum):
    OBSERVED = "observed"
    UNOBSERVED = "unobserved"
    NOT_OBSERVABLE = "not_observable"


class LayerVerdict(str, enum.Enum):
    MECHANICAL = "mechanical"
    LLM = "llm"
    DYNAMIC = "dynamic"


class DisagreementKind(str, enum.Enum):
    MECHANICAL_VS_LLM = "mechanical_vs_llm"
    MECHANICAL_VS_DYNAMIC = "mechanical_vs_dynamic"
    LLM_VS_DYNAMIC = "llm_vs_dynamic"
    ALL_THREE = "all_three"


@dataclass
class LayerClaim:
    """A claim from one analysis layer about a function/finding."""

    layer: LayerVerdict
    reachable: Optional[bool] = None
    has_flow: Optional[bool] = None
    evasion_mechanism: Optional[str] = None
    detail: str = ""


@dataclass
class Disagreement:
    """A logged disagreement between analysis layers."""

    file: str
    function: str
    kind: DisagreementKind
    mechanical_claim: Optional[LayerClaim] = None
    llm_claim: Optional[LayerClaim] = None
    dynamic_claim: Optional[LayerClaim] = None
    resolution: str = ""
    winner: Optional[LayerVerdict] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "file": self.file,
            "function": self.function,
            "kind": self.kind.value,
            "resolution": self.resolution,
        }
        if self.winner:
            d["winner"] = self.winner.value
        if self.mechanical_claim:
            d["mechanical"] = asdict(self.mechanical_claim)
        if self.llm_claim:
            d["llm"] = asdict(self.llm_claim)
        if self.dynamic_claim:
            d["dynamic"] = asdict(self.dynamic_claim)
        return d


@dataclass
class ObservationRecord:
    """Observation status for a function during dynamic analysis."""

    file: str
    function: str
    status: ObservationStatus
    coverage_pct: float = 0.0
    observation_runs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "status": self.status.value,
            "coverage_pct": self.coverage_pct,
            "observation_runs": self.observation_runs,
        }


# -- Per-language CPG confidence weights --

class CpgConfidence(str, enum.Enum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


@dataclass(frozen=True)
class LanguageCpgProfile:
    language: str
    cpg_confidence: CpgConfidence
    reachability_weight: float
    notes: str = ""


_LANGUAGE_PROFILES: Dict[str, LanguageCpgProfile] = {
    "c": LanguageCpgProfile("c", CpgConfidence.HIGH, 0.95,
                            "mature frontend, good pointer analysis"),
    "cpp": LanguageCpgProfile("cpp", CpgConfidence.HIGH, 0.90,
                              "templates and virtual dispatch partially resolved"),
    "c++": LanguageCpgProfile("cpp", CpgConfidence.HIGH, 0.90,
                              "templates and virtual dispatch partially resolved"),
    "java": LanguageCpgProfile("java", CpgConfidence.HIGH, 0.90,
                               "full type resolution, reflection partially handled"),
    "python": LanguageCpgProfile("python", CpgConfidence.MODERATE, 0.65,
                                 "duck typing, monkey-patching create soundness gaps"),
    "javascript": LanguageCpgProfile("javascript", CpgConfidence.MODERATE, 0.60,
                                     "prototype chains, dynamic this, eval()"),
    "js": LanguageCpgProfile("javascript", CpgConfidence.MODERATE, 0.60,
                             "prototype chains, dynamic this, eval()"),
    "typescript": LanguageCpgProfile("typescript", CpgConfidence.MODERATE, 0.65,
                                     "types help, but runtime duck typing remains"),
    "ts": LanguageCpgProfile("typescript", CpgConfidence.MODERATE, 0.65,
                             "types help, but runtime duck typing remains"),
    "go": LanguageCpgProfile("go", CpgConfidence.HIGH, 0.90,
                             "static typing + explicit interfaces"),
    "php": LanguageCpgProfile("php", CpgConfidence.MODERATE, 0.55,
                              "variable variables, dynamic includes"),
    "ruby": LanguageCpgProfile("ruby", CpgConfidence.LOW, 0.35,
                               "metaprogramming, method_missing, open classes"),
    "rust": LanguageCpgProfile("rust", CpgConfidence.HIGH, 0.90,
                               "strong type system, unsafe blocks clearly delineated"),
}

_DEFAULT_PROFILE = LanguageCpgProfile("unknown", CpgConfidence.MODERATE, 0.60)


def get_cpg_profile(language: str) -> LanguageCpgProfile:
    return _LANGUAGE_PROFILES.get(language.lower(), _DEFAULT_PROFILE)


def cpg_reachability_weight(language: str) -> float:
    return get_cpg_profile(language).reachability_weight


# -- Disagreement resolution --

def resolve_disagreement(
    file: str,
    function: str,
    mechanical: Optional[LayerClaim] = None,
    llm: Optional[LayerClaim] = None,
    dynamic: Optional[LayerClaim] = None,
    language: str = "",
) -> Optional[Disagreement]:
    """Apply the resolution policy when layers disagree.

    Returns a Disagreement record if layers disagree, None if they agree
    or there aren't enough claims to compare.
    """
    claims = [c for c in (mechanical, llm, dynamic) if c is not None]
    if len(claims) < 2:
        return None

    reachable_views = {
        c.layer.value: c.reachable for c in claims if c.reachable is not None
    }
    flow_views = {
        c.layer.value: c.has_flow for c in claims if c.has_flow is not None
    }

    has_reach_disagree = len(set(reachable_views.values())) > 1
    has_flow_disagree = len(set(flow_views.values())) > 1

    if not has_reach_disagree and not has_flow_disagree:
        return None

    kind = _classify_disagreement(mechanical, llm, dynamic)
    winner, resolution = _apply_policy(
        mechanical, llm, dynamic, language,
    )

    return Disagreement(
        file=file,
        function=function,
        kind=kind,
        mechanical_claim=mechanical,
        llm_claim=llm,
        dynamic_claim=dynamic,
        resolution=resolution,
        winner=winner,
    )


def _classify_disagreement(
    mechanical: Optional[LayerClaim],
    llm: Optional[LayerClaim],
    dynamic: Optional[LayerClaim],
) -> DisagreementKind:
    has_m = mechanical is not None
    has_l = llm is not None
    has_d = dynamic is not None

    if has_m and has_l and has_d:
        return DisagreementKind.ALL_THREE
    if has_m and has_l:
        return DisagreementKind.MECHANICAL_VS_LLM
    if has_m and has_d:
        return DisagreementKind.MECHANICAL_VS_DYNAMIC
    return DisagreementKind.LLM_VS_DYNAMIC


def _coalesce_bool(*values: Optional[bool]) -> Optional[bool]:
    """Return the first non-None boolean, or None if all are None."""
    for v in values:
        if v is not None:
            return v
    return None


def _apply_policy(
    mechanical: Optional[LayerClaim],
    llm: Optional[LayerClaim],
    dynamic: Optional[LayerClaim],
    language: str,
) -> tuple:
    """Return (winner, resolution_description)."""
    if mechanical and llm:
        m_reach = _coalesce_bool(mechanical.reachable, mechanical.has_flow)
        l_reach = _coalesce_bool(llm.reachable, llm.has_flow)

        if m_reach is not None and l_reach is not None and m_reach != l_reach:
            evasion = llm.evasion_mechanism or ""
            if evasion.lower() in _VALID_EVASION_MECHANISMS:
                weight = cpg_reachability_weight(language) if language else 0.8
                if weight < 0.7:
                    return (
                        LayerVerdict.LLM,
                        f"LLM claim accepted: valid evasion mechanism "
                        f"({evasion}) in low-CPG-confidence language "
                        f"({language}, weight={weight:.2f})",
                    )
                return (
                    LayerVerdict.LLM,
                    f"LLM claim plausible: valid evasion mechanism "
                    f"({evasion}), but CPG is reliable for {language} "
                    f"(weight={weight:.2f}) — investigate further",
                )
            return (
                LayerVerdict.MECHANICAL,
                "mechanical evidence outweighs LLM: no valid evasion "
                "mechanism articulated" + (
                    f" (rejected: {evasion})" if evasion else ""
                ),
            )

    if dynamic and (mechanical or llm):
        if dynamic.reachable or dynamic.has_flow:
            return (
                LayerVerdict.DYNAMIC,
                "dynamic observation confirms reachability "
                "(positive signal from Frida)",
            )
        other = mechanical or llm
        if other and (other.reachable or other.has_flow):
            return (
                other.layer,
                "Frida non-observation is not evidence of absence "
                "(asymmetric: positive-only signal)",
            )

    return (None, "inconclusive — manual review recommended")


# -- Observation status tracking --

def assign_observation_status(
    file: str,
    function: str,
    frida_available: bool,
    observed_functions: Optional[frozenset] = None,
    observation_runs: int = 0,
) -> ObservationRecord:
    if not frida_available:
        return ObservationRecord(
            file=file, function=function,
            status=ObservationStatus.NOT_OBSERVABLE,
        )

    key = f"{file}:{function}"
    obs = observed_functions or frozenset()

    if key in obs:
        return ObservationRecord(
            file=file, function=function,
            status=ObservationStatus.OBSERVED,
            observation_runs=observation_runs,
        )

    return ObservationRecord(
        file=file, function=function,
        status=ObservationStatus.UNOBSERVED,
        observation_runs=observation_runs,
    )


def cap_confidence_for_unobserved(
    confidence: Confidence,
    observation: ObservationRecord,
) -> Confidence:
    """Cap evidence confidence for unobserved functions.

    Unobserved functions after 2+ observation runs can't exceed MEDIUM.
    This prevents over-confidence in findings that were never dynamically
    exercised.
    """
    if observation.status == ObservationStatus.UNOBSERVED:
        if observation.observation_runs >= 2:
            if confidence == Confidence.HIGH:
                return Confidence.MEDIUM
    return confidence


# -- Triage weight adjustment --

def adjust_triage_for_cpg_confidence(
    joern_not_reachable: bool,
    language: str,
) -> bool:
    """Decide whether a Joern "not reachable" verdict should suppress a function.

    Returns True if the Joern verdict is reliable enough to skip the function.
    For low-confidence languages, Joern "not reachable" is suggestive,
    not authoritative — the function should still be reviewed.
    """
    if not joern_not_reachable:
        return False
    profile = get_cpg_profile(language)
    return profile.reachability_weight >= 0.8


# -- Persistence --

def write_disagreements(
    disagreements: List[Disagreement],
    output_dir: Path,
) -> Optional[Path]:
    if not disagreements:
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "disagreements.json"
    data = [d.to_dict() for d in disagreements]

    fd, tmp = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    logger.info("wrote %d disagreements to %s", len(disagreements), path)
    return path


def write_observation_records(
    records: List[ObservationRecord],
    output_dir: Path,
) -> Optional[Path]:
    if not records:
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "observation-status.json"
    data = [r.to_dict() for r in records]

    fd, tmp = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return path


def format_disagreement_summary(disagreements: List[Disagreement]) -> str:
    if not disagreements:
        return "Layer resolution: no disagreements"
    kinds: Dict[str, int] = {}
    for d in disagreements:
        kinds[d.kind.value] = kinds.get(d.kind.value, 0) + 1
    parts = [f"{k}={v}" for k, v in sorted(kinds.items())]
    return (
        f"Layer resolution: {len(disagreements)} disagreements "
        f"({', '.join(parts)})"
    )
