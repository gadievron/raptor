"""Oracle-polymorphic read projection over :class:`LabeledAttempt` records.

Absorbs the legacy ``core.verified_outcome`` API (``VerifiedOutcome``,
``Oracle``, ``OutcomeStatus``, ``collect_outcomes``,
``rank_outcomes_for_finding``, ``exemplar_block_for_finding``,
``render_verified_exemplars``, ``render_outcome_summary``,
``from_witness``, ``from_barrier_synthesis``) so consumer code can stay
unchanged after the canonicalisation.

Projection sources, in priority order:

  1. :class:`LabeledAttempt` records discovered via the project / global
     pools — the canonical append substrate. Each record's
     ``sandbox_evidence`` / ``codeql_evidence`` / ``web_evidence`` is
     mapped into a :class:`VerifiedOutcome` with per-oracle outcome
     interpretation (sandbox success → VERIFIED, codeql success → REFUTED,
     web success → VERIFIED).
  2. :class:`~core.witness.types.Witness` records discovered via the
     witness store — legacy backend that still produces raw bytes
     evidence. Each is projected via ``from_witness``.
  3. CodeQL barrier-synthesis records — projected via
     ``from_barrier_synthesis`` (duck-typed; the dataflow package owns
     the actual call site).

The asymmetry the verified-outcome polymorphism buys (sandbox
oracle verifies exploitability; CodeQL oracle refutes the finding) is
resolved once here, in one place — consumers see a uniform ``status``
field regardless of which evidence shape produced the record.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING

from core.security.log_sanitisation import escape_nonprintable
from core.security.prompt_envelope import neutralize_tag_forgery

from .types import LabeledAttempt

_log = logging.getLogger(__name__)

if TYPE_CHECKING:  # type-only — keep this module import-cheap
    from core.dataflow.barrier_synth import BarrierProposal, SynthResult
    from core.witness.types import Witness


__all__ = [
    "Oracle",
    "OutcomeStatus",
    "ScoredOutcome",
    "VerifiedOutcome",
    "collect_outcomes",
    "exemplar_block_for_finding",
    "from_barrier_synthesis",
    "from_labeled_attempt",
    "from_witness",
    "rank_outcomes_for_finding",
    "render_outcome_summary",
    "render_verified_exemplars",
]


# ---------------------------------------------------------------------------
# VerifiedOutcome — the consumer-facing view dataclass.
# ---------------------------------------------------------------------------


class Oracle(str, Enum):
    """Which mechanism adjudicated the outcome.

    ``str`` subclass so it serialises as a plain string in JSON output
    without a custom encoder.
    """

    SANDBOX = "sandbox"   # compile + run in core.sandbox -> WitnessOutcome
    FUZZER = "fuzzer"     # AFL++ crash -- execution-verified trigger
    CODEQL = "codeql"     # isBarrier adjudication / trust-witness soundness
    WEB = "web"           # /web live-target dynamic confirmation
    MANUAL = "manual"     # operator-supplied


class OutcomeStatus(str, Enum):
    """What the oracle established about the finding.

    Deliberately oracle-neutral. Note the asymmetry the polymorphism buys:
    a sandbox oracle *verifies exploitability* (the bug fires), while a
    CodeQL/trust oracle most often *refutes* a finding (a sound barrier
    proves it a false positive). Both are oracle-verified outcomes; they
    just land on different statuses.
    """

    VERIFIED = "verified"          # finding confirmed (bug fires / payload confirmed)
    REFUTED = "refuted"            # finding shown NOT to hold (e.g. sound FP)
    INCONCLUSIVE = "inconclusive"  # oracle ran but produced no decisive signal


@dataclass
class VerifiedOutcome:
    """One oracle's verdict on one finding, with oracle-tagged evidence.

    ``evidence`` is an opaque, oracle-specific blob — the schema does not
    try to unify it; per-oracle adapters above build the appropriate
    contents.  ``cwe_id`` / ``file`` are denormalised so retrieval/ranking
    doesn't have to re-join against the underlying record store.

    ``reproducible`` records whether the verdict can be re-derived:
    sandbox + CodeQL are deterministic/replayable (True); live-target web
    confirmation is point-in-time (False) so downstream consumers don't
    over-claim.
    """

    finding_id: str
    oracle: Oracle
    status: OutcomeStatus
    reproducible: bool
    evidence: dict[str, Any] = field(default_factory=dict)

    cwe_id: Optional[str] = None
    file: Optional[str] = None
    produced_by: Optional[str] = None
    authorization: Optional[str] = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "oracle": self.oracle.value,
            "status": self.status.value,
            "reproducible": self.reproducible,
            "evidence": dict(self.evidence),
            "cwe_id": self.cwe_id,
            "file": self.file,
            "produced_by": self.produced_by,
            "authorization": self.authorization,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerifiedOutcome":
        """Inverse of :meth:`to_dict`. Tolerant of extra keys so future
        schema additions don't break old persisted records."""
        ts_raw = data.get("timestamp")
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw)
        elif isinstance(ts_raw, datetime):
            ts = ts_raw
        else:
            ts = datetime.now(timezone.utc)
        return cls(
            finding_id=data["finding_id"],
            oracle=Oracle(data["oracle"]),
            status=OutcomeStatus(data["status"]),
            reproducible=bool(data.get("reproducible", False)),
            evidence=dict(data.get("evidence") or {}),
            cwe_id=data.get("cwe_id"),
            file=data.get("file"),
            produced_by=data.get("produced_by"),
            authorization=data.get("authorization"),
            timestamp=ts,
        )


# ---------------------------------------------------------------------------
# Adapters — producer record → VerifiedOutcome.
# ---------------------------------------------------------------------------


_LA_SUCCESS_OUTCOMES: frozenset[str] = frozenset({
    # WitnessOutcome string values that indicate the trigger fired.
    "sanitizer_report", "exit_signal", "flag_captured",
})


def _sandbox_status_from_observed(observed: str, outcome: str) -> OutcomeStatus:
    """Map a labeled_attempt's outcome + observed_outcome to a status.

    ``outcome="success"`` + a triggering observed_outcome → VERIFIED.
    ``outcome="success"`` with no triggering observed_outcome is treated
    as INCONCLUSIVE — success-of-attempt without firing evidence is
    weaker than evidence-backed verification.
    """
    if outcome == "success" and observed in _LA_SUCCESS_OUTCOMES:
        return OutcomeStatus.VERIFIED
    return OutcomeStatus.INCONCLUSIVE


def from_labeled_attempt(la: LabeledAttempt) -> Optional[VerifiedOutcome]:
    """Project a :class:`LabeledAttempt` onto a :class:`VerifiedOutcome`.

    Per-oracle outcome interpretation:

      * ``sandbox_evidence`` + ``outcome="success"`` + triggering
        observed_outcome → VERIFIED. Reproducible.
      * ``codeql_evidence`` + ``is_sound=True`` → REFUTED (a sound
        barrier proves the flagged finding a false positive).
        Reproducible.
      * ``web_evidence`` + ``outcome="success"`` → VERIFIED. NOT
        reproducible (live-HTTP point-in-time).
      * Anything else → INCONCLUSIVE.

    Returns ``None`` for records that carry no oracle evidence at all
    (defensive; ``LabeledAttempt.__post_init__`` already enforces ≥1).
    """
    if la.sandbox_evidence is not None:
        se = la.sandbox_evidence
        evidence: dict = {
            "observed_outcome": se.observed_outcome,
            "bytes_hash": se.bytes_hash,
            "bytes_len": se.bytes_len,
        }
        for k in ("signal", "sanitizer", "stack_hash"):
            v = (se.outcome_detail or {}).get(k)
            if v is not None:
                evidence[k] = v
        if se.target_binary_hash:
            evidence["target_binary_hash"] = se.target_binary_hash
        if se.commit_sha:
            evidence["commit_sha"] = se.commit_sha
        if se.mitigations_active:
            evidence["mitigations_active"] = list(se.mitigations_active)

        return VerifiedOutcome(
            finding_id=la.finding_id,
            oracle=Oracle.SANDBOX,
            status=_sandbox_status_from_observed(
                se.observed_outcome, la.outcome,
            ),
            reproducible=True,
            evidence=evidence,
            cwe_id=la.cwe or None,
            file=(se.outcome_detail or {}).get("file_path"),
            produced_by=la.producing_model or None,
            timestamp=_parse_ts(la.timestamp),
        )

    if la.codeql_evidence is not None:
        cq = la.codeql_evidence
        # Gate REFUTED on BOTH ``is_sound`` (the technical evidence) and
        # the producer's attempt-level outcome (e.g. ``"success"``). An
        # ``uncertain`` outcome with ``is_sound=True`` means the producer
        # itself didn't commit to the result — don't over-claim REFUTED
        # on its behalf. Matches the sandbox-side gate that requires both
        # outcome and observed_outcome.
        sound = bool(cq.is_sound) and la.outcome == "success"
        return VerifiedOutcome(
            finding_id=la.finding_id,
            oracle=Oracle.CODEQL,
            status=(
                OutcomeStatus.REFUTED if sound
                else OutcomeStatus.INCONCLUSIVE
            ),
            reproducible=True,
            evidence={
                "mechanism": "isBarrier",
                "sink_class": cq.sink_class,
                "after_count": cq.after_count,
                "before_count": cq.before_count,
                "is_sound": sound,
                "database_path": cq.database_path,
            },
            cwe_id=la.cwe or None,
            file=None,
            produced_by=la.producing_model or None,
            timestamp=_parse_ts(la.timestamp),
        )

    if la.web_evidence is not None:
        we = la.web_evidence
        return VerifiedOutcome(
            finding_id=la.finding_id,
            oracle=Oracle.WEB,
            status=(
                OutcomeStatus.VERIFIED if la.outcome == "success"
                else OutcomeStatus.INCONCLUSIVE
            ),
            reproducible=False,  # live-HTTP point-in-time
            evidence={
                "target_url": we.target_url,
                "evidence_type": we.evidence_type,
                "http_request": dict(we.http_request),
                "response_evidence": dict(we.response_evidence),
            },
            cwe_id=la.cwe or None,
            file=None,
            produced_by=la.producing_model or None,
            timestamp=_parse_ts(la.timestamp),
        )

    return None


def _parse_ts(timestamp: str) -> datetime:
    """LabeledAttempt timestamps are ISO-8601 strings (enforced in
    __post_init__). Defensive parse so this projection never fails on a
    malformed record from an older schema version.

    Bad input falls through to ``datetime.min`` (not ``now()``): the
    rank function sorts by recency, and silently freshening a corrupt
    record's timestamp would let it cut in front of legitimate ones.
    Record returns at minimum-time get sorted to the back, where they
    belong.
    """
    if not timestamp:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


# --- Witness adapter (verbatim from the legacy verified_outcome) -----------


def _witness_oracle(source: Any) -> Oracle:
    # Import lazily to keep this module's import cost low.
    from core.witness.types import WitnessSource
    if source is WitnessSource.FUZZ:
        return Oracle.FUZZER
    if source is WitnessSource.MANUAL:
        return Oracle.MANUAL
    return Oracle.SANDBOX


def _witness_status(observed: Any) -> OutcomeStatus:
    from core.witness.types import WitnessOutcome
    triggered = {
        WitnessOutcome.SANITIZER_REPORT,
        WitnessOutcome.EXIT_SIGNAL,
        WitnessOutcome.FLAG_CAPTURED,
    }
    if observed in triggered:
        return OutcomeStatus.VERIFIED
    return OutcomeStatus.INCONCLUSIVE


def from_witness(witness: "Witness") -> VerifiedOutcome:
    """Project a :class:`~core.witness.types.Witness` onto a
    :class:`VerifiedOutcome`. Carries a reference (``witness_bytes_hash``)
    to the raw bytes; the witness store remains the backend of record.
    """
    detail = (
        witness.outcome_detail
        if isinstance(witness.outcome_detail, dict)
        else {}
    )
    evidence: dict = {
        "witness_bytes_hash": witness.bytes_hash,
        "observed_outcome": witness.observed_outcome.value,
        "source": witness.source.value,
        "bytes_len": witness.bytes_len,
    }
    for k in ("signal", "sanitizer", "stack_hash"):
        if k in detail:
            evidence[k] = detail[k]
    if witness.target_binary_hash:
        evidence["target_binary_hash"] = witness.target_binary_hash
    return VerifiedOutcome(
        finding_id=str(detail.get("finding_id") or ""),
        oracle=_witness_oracle(witness.source),
        status=_witness_status(witness.observed_outcome),
        reproducible=True,
        evidence=evidence,
        cwe_id=detail.get("cwe_id"),
        file=detail.get("file_path"),
        produced_by=witness.produced_by,
        timestamp=witness.timestamp,
    )


# --- Barrier-synthesis adapter (verbatim from the legacy verified_outcome) -


_SINK_CLASS_CWE = {
    "cmdi": "CWE-78",
    "sqli": "CWE-89",
    "pathtrav": "CWE-22",
    "xss": "CWE-79",
}


def from_barrier_synthesis(
    proposal: "BarrierProposal",
    result: "SynthResult",
) -> VerifiedOutcome:
    """Project a CodeQL ``isBarrier`` adjudication onto a VerifiedOutcome.

    Where the sandbox oracle emits VERIFIED (the bug fires), the CodeQL
    oracle emits REFUTED on success (sound barrier proves false positive).
    """
    sound = bool(result.is_sound)
    return VerifiedOutcome(
        finding_id=str(proposal.finding_id or ""),
        oracle=Oracle.CODEQL,
        status=OutcomeStatus.REFUTED if sound else OutcomeStatus.INCONCLUSIVE,
        reproducible=True,
        evidence={
            "mechanism": "isBarrier",
            "sink_class": proposal.sink_class,
            "after_count": result.after_count,
            "before_count": result.before_count,
            "suppressed_fp": bool(result.suppressed_fp),
            "preserved_tp": bool(result.preserved_tp),
        },
        cwe_id=_SINK_CLASS_CWE.get(proposal.sink_class),
        file=None,
    )


# ---------------------------------------------------------------------------
# Collect — discover records from all backends and project to VerifiedOutcomes.
# ---------------------------------------------------------------------------


def collect_outcomes(
    output_dir: Optional[Path],
    *,
    project_root: Optional[Path] = None,
) -> List[VerifiedOutcome]:
    """Collect every visible verified outcome from every backend.

    Sources (best-effort, never raises):

      * :class:`LabeledAttempt` records — read from the project pool (when
        ``project_root`` resolves) plus the global pool.
      * :class:`~core.witness.types.Witness` records — discovered via
        ``core.witness.discover_witness_stores`` (legacy path; preserves
        the previous ``verified_outcome.collect`` behaviour for callers
        that haven't moved their producers).

    Barrier-synthesis records are still emitted by their own pipeline and
    projected via ``from_barrier_synthesis`` at the call site (no store
    discovery needed).
    """
    outcomes: List[VerifiedOutcome] = []

    # 1. LabeledAttempt records — canonical substrate. Each pool is
    # read under its own try block so a failure in one (e.g. bundled
    # corpus when ``RAPTOR_DIR`` is unset in a subprocess test, global
    # pool with permission denied, or an unreadable record on disk)
    # doesn't block the others. The outer wrapping ``try`` is the
    # last-resort safety net so a substrate failure can never block
    # witness discovery below.
    try:
        from .store import (
            _iter_records_in_dir,
            bundled_corpus_path,
            global_pool_path,
            project_pool_path,
        )

        def _safe_records(resolve):
            """Resolve pool path then iterate; swallow per-pool errors."""
            try:
                pool = resolve()
            except Exception:
                return
            try:
                yield from _iter_records_in_dir(pool)
            except Exception:
                return

        for la in _safe_records(bundled_corpus_path):
            vo = from_labeled_attempt(la)
            if vo is not None:
                outcomes.append(vo)
        if project_root is not None:
            for la in _safe_records(lambda: project_pool_path(project_root)):
                vo = from_labeled_attempt(la)
                if vo is not None:
                    outcomes.append(vo)
        for la in _safe_records(global_pool_path):
            vo = from_labeled_attempt(la)
            if vo is not None:
                outcomes.append(vo)
    except Exception:
        # Substrate failure must not block witness discovery.
        pass

    # 2. Witness records — legacy backend, unchanged.
    try:
        from core.witness import (
            discover_witness_stores,
            iter_visible_witnesses,
        )
        stores = discover_witness_stores(output_dir, project_root=project_root)
        for _root, w in iter_visible_witnesses(stores):
            outcomes.append(from_witness(w))
    except Exception as exc:
        _log.debug("legacy witness discovery failed: %s", exc)

    return outcomes


# ---------------------------------------------------------------------------
# Rank — score outcomes against a finding.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredOutcome:
    """A verified outcome scored against a particular finding."""

    outcome: VerifiedOutcome
    score: int
    reason: str


def _score_outcome(
    outcome: VerifiedOutcome, finding: Dict[str, Any],
) -> Tuple[int, str]:
    finding_id = finding.get("id")
    finding_cwe = finding.get("cwe_id") or finding.get("cwe")
    finding_file = finding.get("file") or finding.get("file_path")

    if finding_id and outcome.finding_id and outcome.finding_id == finding_id:
        return 10, "exact finding-id match"
    if (finding_cwe and outcome.cwe_id == finding_cwe
            and finding_file and outcome.file == finding_file):
        return 7, "cwe + file match"
    if finding_file and outcome.file == finding_file:
        return 4, "file match"
    if finding_cwe and outcome.cwe_id == finding_cwe:
        return 2, "cwe match"
    return 0, "no structured signal"


def rank_outcomes_for_finding(
    outcomes: Iterable[VerifiedOutcome],
    finding: Dict[str, Any],
    *,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
) -> List[ScoredOutcome]:
    """Return the ``top_k`` outcomes most relevant to ``finding``.

    Filters to ``statuses`` first (default: only VERIFIED — exemplar
    retrieval wants successful outcomes to prime on). Drops score-0.
    Ties broken by reproducible-first, then recency.
    """
    scored: List[ScoredOutcome] = []
    for o in outcomes:
        if statuses and o.status not in statuses:
            continue
        score, reason = _score_outcome(o, finding)
        if score == 0:
            continue
        scored.append(ScoredOutcome(outcome=o, score=score, reason=reason))

    scored.sort(
        key=lambda s: (
            -s.score,
            0 if s.outcome.reproducible else 1,
            -s.outcome.timestamp.timestamp(),
            str(s.outcome.evidence.get("witness_bytes_hash", "")),
        ),
    )
    return scored[:top_k]


# ---------------------------------------------------------------------------
# Exemplar block — prompt-side markdown rendering.
# ---------------------------------------------------------------------------


def _safe_prompt(value: Any, *, cap: int = 120) -> str:
    """Defang an untrusted-derived field for inclusion in an LLM prompt."""
    text = escape_nonprintable(
        neutralize_tag_forgery(str(value)), preserve_newlines=False,
    )
    return text if len(text) <= cap else text[:cap] + "…"


_HEADER = "## RAPTOR-verified exemplars"
_INTRO = (
    "Findings like this one that RAPTOR has *previously confirmed* by "
    "execution / adjudication. Use them to calibrate how this bug-class "
    "manifests and is confirmed here — not as patterns to match."
)


def _render_one(scored: ScoredOutcome) -> str:
    o = scored.outcome
    label = _safe_prompt(o.finding_id) if o.finding_id else "(unlinked)"
    where = " in ".join(
        _safe_prompt(p) for p in (o.cwe_id, o.file) if p
    ) or "unknown location"
    evidence_bits = []
    obs = o.evidence.get("observed_outcome")
    if obs:
        evidence_bits.append(_safe_prompt(obs))
    for k in ("signal", "sanitizer"):
        if o.evidence.get(k):
            evidence_bits.append(f"{k}={_safe_prompt(o.evidence[k])}")
    evidence = ", ".join(evidence_bits) or "no detail"
    repro = (
        "reproducible" if o.reproducible
        else "point-in-time (not replayable)"
    )
    return (
        f"**{label} — {where}** (match: {scored.reason})\n"
        f"Confirmed by `{o.oracle.value}` → {o.status.value}; "
        f"evidence: {evidence}; {repro}."
    )


def render_verified_exemplars(
    finding: Dict[str, Any],
    outcomes: Iterable[VerifiedOutcome],
    *,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
    max_bytes: int = 4096,
) -> str:
    """Render the finding's nearest verified outcomes as a prompt block.

    Returns ``""`` when nothing relevant matches; callers can concatenate
    unconditionally.
    """
    ranked = rank_outcomes_for_finding(
        outcomes, finding, top_k=top_k, statuses=statuses,
    )
    if not ranked:
        return ""

    header = [_HEADER, "", _INTRO, ""]
    entries: List[str] = []
    for s in ranked:
        entries.append(_render_one(s))

    while True:
        block = "\n\n".join(
            ["\n".join(header).rstrip()] + entries
        ).rstrip() + "\n"
        if len(block.encode("utf-8")) <= max_bytes or len(entries) == 1:
            return block
        entries.pop()


def exemplar_block_for_finding(
    finding: Dict[str, Any],
    *,
    outcomes: Optional[Iterable[VerifiedOutcome]] = None,
    output_dir: Any = None,
    use_active_project: bool = True,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
    max_bytes: int = 4096,
) -> str:
    """Collect (if needed) and render the verified-exemplar block for one
    finding, in a single best-effort call.

    Two modes:

      * **Cached** — pass a pre-collected ``outcomes``; collect once per
        run via :func:`collect_outcomes`, then call this per finding.
      * **Convenience** — leave ``outcomes`` ``None`` and this collects
        from ``output_dir`` plus, when ``use_active_project``, the active
        project's sibling runs.

    Returns ``""`` on any failure or empty match.
    """
    try:
        resolved = outcomes
        if resolved is None:
            project_root = None
            if use_active_project:
                try:
                    from core.run.output import _resolve_active_project
                    active = _resolve_active_project()
                    if active:
                        project_root = Path(active[0])
                except Exception:
                    project_root = None
            resolved = collect_outcomes(output_dir, project_root=project_root)
        return render_verified_exemplars(
            finding, resolved,
            top_k=top_k, statuses=statuses, max_bytes=max_bytes,
        )
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Summary — operator-facing rendering (terminal / report output).
# ---------------------------------------------------------------------------


def _safe_terminal(value, *, cap: int = 200) -> str:
    """Defang an untrusted-derived field for terminal output."""
    text = escape_nonprintable(str(value), preserve_newlines=False)
    return text if len(text) <= cap else text[:cap] + "…"


_STATUS_LABEL = {
    OutcomeStatus.VERIFIED: "Verified",
    OutcomeStatus.REFUTED: "Refuted",
    OutcomeStatus.INCONCLUSIVE: "Inconclusive",
}


def render_outcome_summary(outcomes: Iterable[VerifiedOutcome]) -> str:
    """Render a grouped operator-facing summary: total, an oracle ×
    status table, and a list of the confirmed (Verified) findings.
    """
    items: List[VerifiedOutcome] = list(outcomes)
    if not items:
        return "No verified outcomes found.\n"

    lines: List[str] = [f"Verified outcomes: {len(items)} total", ""]

    by = Counter((o.oracle, o.status) for o in items)
    lines.append("By oracle x status:")
    for oracle in Oracle:
        cells = [
            (st, by[(oracle, st)])
            for st in OutcomeStatus
            if by[(oracle, st)]
        ]
        if not cells:
            continue
        cell_str = "  ".join(
            f"{_STATUS_LABEL[st]}={n}" for st, n in cells
        )
        lines.append(f"  {oracle.value:<8} {cell_str}")

    verified = [o for o in items if o.status is OutcomeStatus.VERIFIED]
    if verified:
        lines += ["", f"Confirmed ({len(verified)}):"]
        for o in verified:
            fid = _safe_terminal(o.finding_id) if o.finding_id else "(unlinked)"
            cwe = _safe_terminal(o.cwe_id) if o.cwe_id else "?"
            where = _safe_terminal(o.file) if o.file else "?"
            obs = o.evidence.get("observed_outcome", "")
            repro = "reproducible" if o.reproducible else "point-in-time"
            detail = (
                f"{o.oracle.value}: {_safe_terminal(obs)}; {repro}"
                if obs else f"{o.oracle.value}; {repro}"
            )
            lines.append(f"  - {fid}  {cwe}  {where}  [{detail}]")

    return "\n".join(lines).rstrip() + "\n"
