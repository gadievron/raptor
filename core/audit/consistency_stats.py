"""Statistical discipline for the consistency engine: the lead-strength
score and the per-dimension floors registry.

Lead-strength score
-------------------
:func:`lead_strength_score` is the Wilson LOWER bound on a family's
majority proportion (``conforming / n``, the receipt's own integers),
computed with the canonical :func:`core.dataflow.sanitizer_cut_parity.
wilson_interval` — this module deliberately contains no Wilson
arithmetic of its own (the repo already carries two implementations;
a third would drift).

The score is a **monotone shrinkage score for small-N ranking, NOT a
confidence or significance claim**. Family members are correlated by
copy-paste provenance (not i.i.d. draws), and the census is exhaustive
over the tree rather than sampled from a population, so binomial
coverage guarantees do not apply to these families. The score's whole
contract is monotonicity: at equal ratio a larger family scores
higher, and a small family's optimistic ratio is pulled down — exactly
the property a ranking needs so a 3/3 group does not outrank a 27/30
group. Verdict gates never read it; they keep the per-dimension floor
constants below.

Stratified ranking
------------------
:func:`stratified_lead_sort_key` preserves the established lead-
ranking chain — contract strength → security relevance → ratio — and
uses the score only WITHIN a ``(dimension × formation)`` stratum,
where it replaces what was previously an arbitrary file/line tie
order. Strata are never interleaved by score: cross-stratum ties on
the chain order by stratum id (per-stratum precision is unmeasured,
so a flag-mode 0.9 and a return-check 0.9 have no comparable score
scale yet).

Floors registry
---------------
:func:`floors_registry` is the single enumerable table of every
per-dimension census threshold (min sites, majority ratios, promote
ratios). The constants themselves stay inline in their owning modules
next to the checks they gate (with their trade-off rationale); the
registry references them, so the table can never drift from the live
values without the registry tests noticing. Per-run overrides come
through the audit run-config only (``consistency_floors`` in
``audit-run-config.json``) — never ``tuning.json`` (a hardware-
resource allowlist) and never any file read from the scanned repo.
Defaults reproduce current behaviour exactly.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from core.dataflow.sanitizer_cut_parity import wilson_interval

# The run-config key under which per-run floor overrides live.
RUN_CONFIG_FLOORS_KEY = "consistency_floors"

# Threshold kinds (validation contract per kind).
KIND_MIN_SITES = "min_sites"   # int >= 1
KIND_RATIO = "ratio"           # float in (0, 1]
KIND_MIN_TOKENS = "min_tokens"  # int >= 1

_VALID_KINDS = frozenset({KIND_MIN_SITES, KIND_RATIO, KIND_MIN_TOKENS})


def lead_strength_score(conforming: int, n: int) -> float:
    """Wilson lower bound of ``conforming / n`` — the lead-strength
    ranking score (monotone shrinkage; see the module docstring for
    what it is NOT). ``n <= 0`` scores 0.0; *conforming* is clamped
    into ``[0, n]`` so a malformed receipt can never score above a
    well-formed one."""
    if n <= 0:
        return 0.0
    return wilson_interval(min(max(conforming, 0), n), n)[0]


def lead_stratum(lead: Mapping[str, Any]) -> tuple[str, str]:
    """The ``(dimension, formation)`` stratum of one lead dict."""
    return (
        str(lead.get("dimension") or ""),
        str(lead.get("formation") or ""),
    )


def stratified_lead_sort_key(lead: Mapping[str, Any]) -> tuple[Any, ...]:
    """Sort key for lead ranking: the established chain (contract
    strength → security relevance → ratio), then the stratum id, then
    the lead-strength score WITHIN the stratum, then file/line for
    determinism. The stratum id sits ahead of the score so two leads
    from different strata are never ordered against each other by
    score (strata do not interleave by score)."""
    return (
        lead.get("contract_source", "none") == "majority",
        not lead.get("security_relevant", False),
        -float(lead.get("ratio") or 0.0),
        *lead_stratum(lead),
        -float(lead.get("score") or 0.0),
        lead.get("file", ""),
        lead.get("line", 0),
    )


# ── floors registry ──────────────────────────────────────────────────


@dataclass(frozen=True)
class FloorSpec:
    """One registered per-dimension threshold.

    ``overridable`` marks whether the audit run-config may override it
    this run: True only where the prepass/verdict layer threads the
    value through an existing parameter. Non-overridable entries are
    still enumerated (the eval-sweep surface reads the whole table);
    an override naming one is refused loudly, never ignored.
    """

    key: str          # "<dimension>.<name>"
    dimension: str
    name: str
    default: int | float
    kind: str         # KIND_MIN_SITES | KIND_RATIO | KIND_MIN_TOKENS
    overridable: bool
    consumer: str     # where the value gates, for the operator table


@lru_cache(maxsize=1)
def floors_registry() -> tuple[FloorSpec, ...]:
    """Every per-dimension census threshold, defaults referencing the
    live inline constants (lazy imports: the owning modules import
    this one for scoring, so the reference direction must resolve at
    call time, not import time)."""
    from . import callsite_consistency as cc
    from . import clone_drift as cd_clone
    from . import consistency_dimensions as cd
    from . import consistency_verify as cv

    def spec(dimension: str, name: str, default: int | float, kind: str,
             overridable: bool, consumer: str) -> FloorSpec:
        return FloorSpec(
            key=f"{dimension}.{name}", dimension=dimension, name=name,
            default=default, kind=kind, overridable=overridable,
            consumer=consumer,
        )

    return (
        # return-check: census lead arithmetic + verdict gates.
        spec("return-check", "lead_min_sites", cc.MIN_CALL_SITES,
             KIND_MIN_SITES, False,
             "callsite_consistency._deviations_from_census (legacy "
             "deviation-lead path; parameterised at its call sites, "
             "outside the prepass floors flow)"),
        spec("return-check", "lead_majority_threshold",
             cc.MAJORITY_THRESHOLD, KIND_RATIO, False,
             "callsite_consistency._deviations_from_census"),
        spec("return-check", "contract_min_sites",
             cc.MAJORITY_CONTRACT_MIN_SITES, KIND_MIN_SITES, True,
             "CalleeCensus.majority_says_check / "
             "majority_says_discard_ok"),
        spec("return-check", "contract_ratio",
             cc.MAJORITY_CONTRACT_RATIO, KIND_RATIO, True,
             "CalleeCensus.majority_says_check / "
             "majority_says_discard_ok"),
        spec("return-check", "verdict_min_sites", cv.VERDICT_MIN_SITES,
             KIND_MIN_SITES, True,
             "consistency_verify.census_verdict majority leg"),
        spec("return-check", "verdict_majority_ratio",
             cv.VERDICT_MAJORITY_RATIO, KIND_RATIO, True,
             "consistency_verify.census_verdict majority leg"),
        # flag-mode.
        spec("flag-mode", "min_sites", cd.MIN_GROUP_SITES,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_flag_mode_deviations"),
        spec("flag-mode", "ratio", cd.CONSISTENCY_RATIO, KIND_RATIO,
             True, "consistency_dimensions.detect_flag_mode_deviations"),
        # cleanup.
        spec("cleanup", "min_group", cd.MIN_GROUP_SITES,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_cleanup_deviations"),
        spec("cleanup", "ratio", cd.CONSISTENCY_RATIO, KIND_RATIO,
             True, "consistency_dimensions.detect_cleanup_deviations"),
        # argument-shape.
        spec("argument-shape", "min_sites", cd.ARGSHAPE_MIN_SITES,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_argument_shape_deviations"),
        spec("argument-shape", "ratio", cd.ARGSHAPE_RATIO, KIND_RATIO,
             True,
             "consistency_dimensions.detect_argument_shape_deviations"),
        # interface.
        spec("interface", "min_group", cd.INTERFACE_MIN_GROUP,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_interface_deviations"),
        spec("interface", "ratio", cd.CONSISTENCY_RATIO, KIND_RATIO,
             True, "consistency_dimensions.detect_interface_deviations"),
        # ordering.
        spec("ordering", "min_group", cd.ORDERING_MIN_GROUP,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_ordering_deviations"),
        spec("ordering", "ratio", cd.CONSISTENCY_RATIO, KIND_RATIO,
             True, "consistency_dimensions.detect_ordering_deviations"),
        # sanitize-sink.
        spec("sanitize-sink", "min_sites", cd.MIN_GROUP_SITES,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_sanitize_sink_deviations"),
        spec("sanitize-sink", "ratio", cd.CONSISTENCY_RATIO, KIND_RATIO,
             True,
             "consistency_dimensions.detect_sanitize_sink_deviations"),
        spec("sanitize-sink", "promote_ratio", cd.RATIO_PROMOTE,
             KIND_RATIO, False,
             "SanitizeSinkDeviation.registry_grade (evaluated inside "
             "the detector, not threadable per run)"),
        # guard-presence.
        spec("guard-presence", "min_sites", cd.MIN_GROUP_SITES,
             KIND_MIN_SITES, True,
             "consistency_dimensions.detect_guard_presence_deviations"),
        spec("guard-presence", "ratio", cd.CONSISTENCY_RATIO,
             KIND_RATIO, True,
             "consistency_dimensions.detect_guard_presence_deviations"),
        spec("guard-presence", "promote_ratio", cd.RATIO_PROMOTE,
             KIND_RATIO, True,
             "consistency_verify.guard_presence_verdict SMT-witness "
             "promote gate"),
        # clone-drift (similarity floors, enumerated for the sweep
        # surface; consumed inside clone_drift's winnowing, not
        # threadable per run).
        spec("clone-drift", "similarity", cd_clone.CLONE_SIMILARITY,
             KIND_RATIO, False, "clone_drift.detect_clone_drift"),
        spec("clone-drift", "fix_anchor_similarity",
             cd_clone.FIX_ANCHOR_SIMILARITY, KIND_RATIO, False,
             "clone_drift.fix_anchored_drift"),
        spec("clone-drift", "min_clone_tokens",
             cd_clone.MIN_CLONE_TOKENS, KIND_MIN_TOKENS, False,
             "clone_drift token floor"),
    )


def floors_table() -> list[dict[str, Any]]:
    """The registry as plain rows — the config surface and the eval
    sweep read this one enumeration."""
    return [
        {
            "key": s.key,
            "dimension": s.dimension,
            "name": s.name,
            "default": s.default,
            "kind": s.kind,
            "overridable": s.overridable,
            "consumer": s.consumer,
        }
        for s in floors_registry()
    ]


class Floors:
    """Effective floor values: registry defaults plus validated
    overrides. Construct via :func:`resolve_floors`."""

    __slots__ = ("_values", "_applied")

    def __init__(self, values: dict[str, int | float],
                 applied: dict[str, int | float]) -> None:
        self._values = values
        self._applied = applied

    def value(self, key: str) -> int | float:
        """The effective value for a registered key (KeyError on an
        unregistered key — consumers name real thresholds only)."""
        return self._values[key]

    def overridden(self) -> dict[str, int | float]:
        """The validated overrides that were applied (empty = pure
        defaults, i.e. current behaviour)."""
        return dict(self._applied)


def _validate_override(spec: FloorSpec, raw: Any) -> int | float:
    if spec.kind in (KIND_MIN_SITES, KIND_MIN_TOKENS):
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValueError(
                f"consistency floor {spec.key!r} takes an int, "
                f"got {type(raw).__name__}",
            )
        if raw < 1:
            raise ValueError(
                f"consistency floor {spec.key!r} must be >= 1, "
                f"got {raw}",
            )
        return raw
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(
            f"consistency floor {spec.key!r} takes a number, "
            f"got {type(raw).__name__}",
        )
    value = float(raw)
    if not 0.0 < value <= 1.0:
        raise ValueError(
            f"consistency floor {spec.key!r} must be in (0, 1], "
            f"got {value}",
        )
    return value


def resolve_floors(
    overrides: Mapping[str, Any] | None = None,
) -> Floors:
    """Registry defaults with *overrides* applied.

    Strict: an unknown key, a non-overridable key, or an out-of-
    contract value raises ``ValueError`` — an override the run cannot
    honour must fail loudly, never be silently dropped (the caller
    decides whether to abort or fall back to defaults, and says so).
    """
    specs = {s.key: s for s in floors_registry()}
    values: dict[str, int | float] = {
        k: s.default for k, s in specs.items()
    }
    applied: dict[str, int | float] = {}
    for key, raw in (overrides or {}).items():
        spec = specs.get(str(key))
        if spec is None:
            raise ValueError(
                f"unknown consistency floor {key!r} — known keys: "
                f"{', '.join(sorted(specs))}",
            )
        if not spec.overridable:
            raise ValueError(
                f"consistency floor {key!r} is not run-overridable "
                f"(consumed at {spec.consumer})",
            )
        value = _validate_override(spec, raw)
        values[spec.key] = value
        applied[spec.key] = value
    return Floors(values, applied)


@lru_cache(maxsize=1)
def default_floors() -> Floors:
    """The pure-defaults view (shared instance; ``Floors`` is
    read-only after construction)."""
    return resolve_floors(None)


def floor_overrides_from_run_config(out_dir: Path) -> dict[str, Any]:
    """Per-run floor overrides from ``audit-run-config.json`` in the
    run directory — the ONLY override surface. The run config is the
    same operator-authored artifact that already controls scope, pins
    and budget (bounded load via :func:`core.audit.resume.
    load_run_config`); values are still validated by
    :func:`resolve_floors` before use. Absent file / absent key /
    non-dict value all mean no overrides."""
    from .resume import load_run_config

    cfg = load_run_config(Path(out_dir))
    raw = (cfg or {}).get(RUN_CONFIG_FLOORS_KEY)
    return dict(raw) if isinstance(raw, dict) else {}
