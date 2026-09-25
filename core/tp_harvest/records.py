"""Harvest records — one per confirmed true-positive finding.

A harvest record captures the defect MECHANISM (rule id, CWE, the
validated flow), the source span + function identity (the repo-wide
``core.staleness`` span-hash convention, so a record is directly
comparable with annotation hashes and corpus-label pins), and
pointers to the validation evidence. It deliberately captures no
verdict-forming logic of its own: the run's tool/oracle output IS the
verdict, and this module only projects it (verdict-integrity
doctrine — same reason ``core.project.correlate.get_finding_status``
is reused rather than re-derived).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.cve.cwe import canonicalize_cwe
from core.labeled_attempts.types import compute_finding_signature
from core.paths import confine
from core.project.correlate import get_finding_status, normalize_verdict
from core.project.findings_utils import finding_file
from core.security.log_sanitisation import escape_nonprintable
from core.staleness import hash_span

SCHEMA_VERSION = 1

# Statuses that make a finding harvestable: hard confirmations only.
# Deliberately NARROWER than correlate's POSITIVE_VERDICTS — the
# flywheel's inputs seed detection rules and corpus labels, where
# over-inclusion is a precision regression, so verdict tiers below
# hard confirmation are excluded by default and enumerated as skips
# (never silently dropped). Both directions matter: widening this set
# poisons the downstream stores; narrowing it starves the flywheel —
# see the two-direction tests in tests/test_records.py.
HARVEST_STATUSES = frozenset({
    "exploitable",
    "confirmed",
    "confirmed_constrained",
    "confirmed_blocked",
    "validated",
})

# Enumerated skip reasons (manifest vocabulary — never silent).
SKIP_STATUS_NEGATIVE = "status_negative"
SKIP_STATUS_UNVERIFIED = "status_unverified"
SKIP_STATUS_INTERMEDIATE = "status_intermediate"
SKIP_STATUS_INCONCLUSIVE = "status_inconclusive"
SKIP_STATUS_NOT_CONFIRMED = "status_not_confirmed"
SKIP_MISSING_LOCATION = "missing_location"
SKIP_DUPLICATE_IN_RUN = "duplicate_in_run"
SKIP_ALREADY_HARVESTED = "already_harvested"
# The finding's file path escapes the run's target tree (traversal
# segment, out-of-target absolute path, or symlink escape). A record
# pinned outside the target is meaningless for the flywheel and the
# path would otherwise become an arbitrary-read primitive (seed-line
# content into the candidate pattern; span_sha as a content oracle).
SKIP_PATH_ESCAPES_TARGET = "path_escapes_target"
# The finding row's shape defeated projection (non-dict row, or a
# field crash outside the coercion net) — the row is skipped, the
# harvest continues.
SKIP_FINDING_MALFORMED = "finding_malformed"

ALL_SKIP_REASONS = frozenset({
    SKIP_STATUS_NEGATIVE,
    SKIP_STATUS_UNVERIFIED,
    SKIP_STATUS_INTERMEDIATE,
    SKIP_STATUS_INCONCLUSIVE,
    SKIP_STATUS_NOT_CONFIRMED,
    SKIP_MISSING_LOCATION,
    SKIP_DUPLICATE_IN_RUN,
    SKIP_ALREADY_HARVESTED,
    SKIP_PATH_ESCAPES_TARGET,
    SKIP_FINDING_MALFORMED,
})

# Display caps for target-derived free text carried in a record.
_MESSAGE_CAP = 500
_FLOW_STEP_CAP = 200
_FLOW_STEPS_MAX = 20
_ELISION = " …[elided]"


@dataclass(frozen=True)
class HarvestRecord:
    """One confirmed finding, projected for the flywheel.

    ``harvest_id`` is the durable identity key — the same
    ``finding_signature`` convention the labeled-attempts substrate
    keys its on-disk pools by (``sha256(cwe|file|function|line|
    vuln_type)[:32]``) — so re-running the harvest on the same run
    is a keyed no-op and cross-run consumers can join on it.
    """

    harvest_id: str
    finding_id: str
    status: str
    rule_id: str
    cwe: str
    vuln_type: str
    message: str
    file: str
    function: str
    line: int
    span_sha: str
    flow: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    # POSITIVE oracle-verification marker: True only when at least one
    # VERIFIED oracle outcome matched this finding (the pointers in
    # evidence.verified_outcomes). Status-boolean-only confirmations
    # carry False — human promotion must not have to infer the
    # evidence tier from the ABSENCE of a key.
    oracle_verified: bool = False
    run_dir: str = ""
    target_path: str = ""
    command: str = ""
    harvested_at: str = ""
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bounded(text: Any, cap: int) -> str:
    """Escape non-printables and bound target-derived free text."""
    s = escape_nonprintable(str(text), preserve_newlines=False)
    if len(s) > cap:
        return s[:cap] + _ELISION
    return s


def effective_status(finding: dict[str, Any]) -> str:
    """The finding's effective status, via the project-layer resolver.

    Coerced: finding rows are LLM-authored and import-restored — a
    hostile row carrying a dict/list ``status`` must skip by name
    downstream, not AttributeError the whole harvest.
    """
    raw = get_finding_status(finding)
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def _coerce_line(value: Any) -> int:
    """Line component as int-or-0 (same hostile-row rationale as
    ``core.project.findings_utils._key_line`` — a bool or non-numeric
    string must degrade, not ValueError the harvest)."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def classify_finding(finding: dict[str, Any]) -> tuple[bool, str]:
    """Decide whether *finding* is harvestable.

    Returns ``(True, "")`` for harvestable findings, else
    ``(False, <skip_reason>)`` with an enumerated reason. Pure
    projection of the run's recorded verdict — never re-adjudicates.
    """
    status = effective_status(finding)
    if status not in HARVEST_STATUSES:
        if status == "confirmed_unverified":
            # Confirmed on paper but explicitly unverified — the
            # flywheel wants oracle/tool-backed confirmations.
            return False, SKIP_STATUS_UNVERIFIED
        if status == "poc_success":
            return False, SKIP_STATUS_INTERMEDIATE
        bucket = normalize_verdict(status)
        if bucket == "negative":
            return False, SKIP_STATUS_NEGATIVE
        if bucket == "inconclusive":
            return False, SKIP_STATUS_INCONCLUSIVE
        return False, SKIP_STATUS_NOT_CONFIRMED
    file_path = finding_file(finding)
    if not file_path or _coerce_line(finding.get("line")) <= 0:
        # No stable span identity — a rule candidate or label pin
        # would point at nothing verifiable.
        return False, SKIP_MISSING_LOCATION
    return True, ""


def harvest_identity(finding: dict[str, Any]) -> str:
    """Durable identity for idempotence keying (finding_signature)."""
    cwe = canonicalize_cwe(str(finding.get("cwe_id") or finding.get("cwe") or "")) or ""
    return compute_finding_signature(
        cwe=cwe,
        file_path=finding_file(finding),
        function=str(finding.get("function") or ""),
        line=_coerce_line(finding.get("line")),
        vuln_type=str(finding.get("vuln_type") or ""),
    )


def path_in_target(target_path: str, file_path: str) -> Path | None:
    """The finding's file path confined to the target tree, or None.

    ``core.paths.confine`` semantics: traversal segments, absolute
    paths outside the target, and symlink escapes all return None. An
    absolute path RESOLVING under the target is accepted. Every read
    the harvest performs against the target goes through this — a
    finding path is attacker-influenced data, and an unconfined join
    is an arbitrary-read primitive (candidate patterns embed seed-line
    call anchors concretely; span_sha is a content oracle).
    """
    if not target_path or not file_path:
        return None
    return confine(target_path, file_path)


def _span_sha_for(target_path: str, file_path: str, line: int) -> str:
    """Span hash of the finding line against the run's target tree.

    Single-line span (``line..line``) in the repo-wide SHA-256[:12]
    convention. ``""`` when the target tree (or the file/line) is not
    available — staleness detection degrades, identity does not.
    CONTAINED: only paths confined to the target tree are ever
    hashed (see :func:`path_in_target` — a 12-hex hash of an
    arbitrary host file is a content oracle).
    """
    if line <= 0:
        return ""
    candidate = path_in_target(target_path, file_path)
    if candidate is None:
        return ""
    return hash_span(candidate, line, line)


def _flow_steps(finding: dict[str, Any]) -> list[str]:
    """The validated flow, as bounded display strings."""
    proof = finding.get("proof")
    flow = proof.get("flow") if isinstance(proof, dict) else None
    if not isinstance(flow, list):
        return []
    steps = [_bounded(step, _FLOW_STEP_CAP) for step in flow[:_FLOW_STEPS_MAX]]
    if len(flow) > _FLOW_STEPS_MAX:
        steps.append(_ELISION.strip())
    return steps


# Evidence-blob keys worth carrying as pointers (content-addressed /
# small). The bulky per-oracle payloads (exploit code, query text)
# stay in their stores; the record points, never copies.
_OUTCOME_EVIDENCE_KEYS = ("bytes_hash", "witness_bytes_hash", "stack_hash",
                          "evidence_type")


def _outcome_pointer(outcome: Any) -> dict[str, Any]:
    """Small pointer projection of a ``VerifiedOutcome``."""
    d = outcome.to_dict()
    pointer = {
        "finding_id": d.get("finding_id"),
        "oracle": d.get("oracle"),
        "status": d.get("status"),
        "reproducible": d.get("reproducible"),
        "produced_by": d.get("produced_by"),
        "timestamp": d.get("timestamp"),
    }
    ev = d.get("evidence") or {}
    kept = {k: ev[k] for k in _OUTCOME_EVIDENCE_KEYS if k in ev}
    if kept:
        pointer["evidence"] = kept
    return pointer


def build_record(
    finding: dict[str, Any],
    *,
    run_dir: Path,
    target_path: str = "",
    command: str = "",
    outcomes: list[Any] | None = None,
    harvested_at: str = "",
) -> HarvestRecord:
    """Project one harvestable finding into a :class:`HarvestRecord`.

    ``outcomes`` — pre-collected ``VerifiedOutcome`` records for the
    run; the top-ranked verified matches become evidence pointers.
    """
    file_path = finding_file(finding)
    line = _coerce_line(finding.get("line"))
    cwe = canonicalize_cwe(str(finding.get("cwe_id") or finding.get("cwe") or "")) or ""

    evidence: dict[str, Any] = {}
    ruling = finding.get("ruling")
    if isinstance(ruling, dict):
        evidence["ruling"] = {
            "status": _bounded(ruling.get("status", ""), 64),
            "reason": _bounded(ruling.get("reason", ""), _MESSAGE_CAP),
        }
    if isinstance(finding.get("poc"), dict):
        evidence["has_poc"] = True
    refs = finding.get("provenance_refs")
    if isinstance(refs, list) and refs:
        evidence["provenance_refs"] = refs

    oracle_verified = False
    if outcomes:
        from core.labeled_attempts.view import rank_outcomes_for_finding
        ranked = rank_outcomes_for_finding(outcomes, finding)
        if ranked:
            evidence["verified_outcomes"] = [
                _outcome_pointer(s.outcome) for s in ranked
            ]
            oracle_verified = True

    return HarvestRecord(
        harvest_id=harvest_identity(finding),
        finding_id=str(finding.get("id") or finding.get("finding_id") or ""),
        status=effective_status(finding),
        rule_id=_bounded(finding.get("rule_id", ""), 200),
        cwe=cwe,
        vuln_type=_bounded(finding.get("vuln_type", ""), 100),
        message=_bounded(finding.get("message", ""), _MESSAGE_CAP),
        file=file_path,
        function=_bounded(finding.get("function", ""), 200),
        line=line,
        span_sha=_span_sha_for(target_path, file_path, line),
        flow=_flow_steps(finding),
        evidence=evidence,
        oracle_verified=oracle_verified,
        run_dir=str(run_dir),
        target_path=target_path,
        command=command,
        harvested_at=harvested_at,
    )
