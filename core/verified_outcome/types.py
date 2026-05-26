"""Oracle-polymorphic record for "this finding was verified by some oracle."

A :class:`VerifiedOutcome` is the shared, Finding-keyed spine that unifies
the verification signals different RAPTOR oracles produce:

  * the sandbox (compile + run an exploit -> ``WitnessOutcome``),
  * the fuzzer (AFL++ execution-verified crash),
  * CodeQL adjudication (``isBarrier`` synthesis -> sound FP suppression),
  * the ``/web`` dynamic scanner (live-target exploitation evidence),
  * an operator (manual import).

The design point is to *not* shape this record around any one oracle's
evidence format. The three evidence shapes do not unify: a sandbox witness
is ``(bytes-hash, trigger-bytes, outcome)``; a CodeQL adjudication is
``(query, before/after diff, is_sound)``; a web confirmation is
``(URL, HTTP payload, response-evidence)``. So the stable contract is
``Finding + verifying-oracle + status + oracle-tagged evidence blob``, with
each producer's own store (e.g. ``WitnessStore``) remaining the *backend*
that holds the raw evidence. This record is the queryable index over them.

Consumers: a unified verified-status view (``/project``), exemplar retrieval
(rank a finding's nearest verified outcomes), and measurement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


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

    VERIFIED = "verified"          # finding confirmed to hold (bug fires / payload confirmed)
    REFUTED = "refuted"            # finding shown NOT to hold (e.g. sound FP)
    INCONCLUSIVE = "inconclusive"  # oracle ran but produced no decisive signal


@dataclass
class VerifiedOutcome:
    """One oracle's verdict on one finding, with oracle-tagged evidence.

    ``evidence`` is an opaque, oracle-specific blob (the schema does not try
    to unify it -- see module docstring). ``cwe_id`` / ``file`` are
    denormalised from the finding so retrieval/ranking and the verified-
    status view don't have to re-join against the finding store.

    ``reproducible`` records whether the verdict can be re-derived: sandbox
    witnesses and CodeQL adjudication are deterministic/replayable (True);
    live-target web confirmation is point-in-time (False), so downstream
    consumers (e.g. ZKPoX eligibility, "reproduces N x") don't over-claim.
    """

    finding_id: str
    oracle: Oracle
    status: OutcomeStatus
    reproducible: bool
    evidence: dict[str, Any] = field(default_factory=dict)

    cwe_id: Optional[str] = None
    file: Optional[str] = None
    produced_by: Optional[str] = None
    # Provenance/consent tag for live-target oracles (/web): such records
    # assert "payloads were sent at target X". None for offline oracles.
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
        """Inverse of :meth:`to_dict`. Tolerant of extra keys so a future
        schema addition doesn't break old persisted records."""
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
