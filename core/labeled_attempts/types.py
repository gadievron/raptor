"""LabeledAttempt schema — the finding-keyed corpus spine.

A finding-keyed record of one producer's attempt to act on a
finding, plus oracle-verified evidence (sandbox / CodeQL / web)
and the resulting outcome.

The spine is **Finding + oracle-verified outcome**, keyed by the
finding's stable signature (CWE + file + function + line + vuln_type
hash) so renames and moves don't break cross-run linking.

``SandboxEvidence`` retains the full witness surface
(target_binary_hash, trigger bytes, mitigations_active, commit_sha)
so downstream proof-bundle producers can build on records without
retroactive schema changes.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

# Finding signature is a hex hash (compute_finding_signature returns 32
# chars). Tolerate the SHA-256 full width too. NO path-traversal chars
# allowed — this is the directory name on disk and must be safe.
_VALID_SIGNATURE = re.compile(r"^[0-9a-fA-F]{8,64}$")

# Bytes payload soft cap — exploits in practice are << 16 MB; producers
# emitting larger blobs are almost certainly buggy (e.g. logging a whole
# memory dump). Records cap out here so a runaway producer can't fill
# the disk one record at a time.
_MAX_BYTES_LEN = 16 * 1024 * 1024
_MAX_EXPLOIT_CODE_LEN = 1024 * 1024     # 1 MB of source is generous
_SHA256_HEX_LEN = 64

__all__ = [
    "FailureMode",
    "LabeledAttempt",
    "SandboxEvidence",
    "CodeQLEvidence",
    "WebEvidence",
    "Outcome",
]


# Outcome of the attempt — three values per the design doc.
Outcome = Literal["success", "reasoned_failure", "uncertain"]


class FailureMode(str, Enum):
    """Why a non-successful attempt didn't succeed.

    Distinct from :class:`core.witness.WitnessOutcome` (which names
    the *shape* of what was observed — sanitizer report, exit signal,
    etc.) — this names the *reason* a run that DIDN'T succeed didn't.
    Failure-mode
    taxonomy.

    Populated by:
      * Heuristics on the trajectory + observation (the engine-side
        populator in ``packages/llm_analysis/exploit_engine/
        labeled_attempt_bridge.py``)
      * Operator annotation (after-the-fact triage; future)

    Consumers:
      * L3 retrieval — can prefer exemplars sharing a CWE that DON'T
        share this failure mode (don't teach the model what just
        failed for the same reason).
      * Corpus-growth signal — N clusters of MODEL_REASONING_CEILING
        for one CWE is a candidate for a new mechanical primitive.
    """

    # Heap-shaping went wrong — chunks didn't land where expected.
    SIZE_MISMATCH = "size_mismatch"

    # Network / IPC: the model guessed a protocol or command shape
    # that doesn't match the target.
    PROTOCOL_GUESS = "protocol_guess"

    # Target's init() / setup runs after the attack and clears state
    # the exploit depended on.
    MISSING_INIT = "missing_init"

    # Model couldn't reason through the chain — repeated attempts
    # converged on dead-ends, no candidate produced or candidate
    # didn't compile usefully.
    MODEL_REASONING_CEILING = "model_ceiling"

    # Substrate flake (network race, container race, etc.) —
    # rerun-might-fix territory, not a real failure of the exploit.
    NETWORK_RACE = "network_race"

    # Run hit iteration / cost cap before the model converged.
    BUDGET_EXHAUSTED = "budget_exhausted"

    # Candidate failed to compile.
    COMPILE_FAILED = "compile_failed"

    # Model produced an input that fires the bug (sanitizer report,
    # crashing exit signal) but didn't achieve the run's controlled-
    # effect goal (no flag captured, no marker in stdout). The bug
    # is reachable; weaponization is the next step. Distinguishes
    # "fuzz-class success" from "real exploit success" so retries
    # can target the gap instead of re-deriving the trigger.
    TRIGGER_FIRED_NO_CONTROLLED_EFFECT = "trigger_fired_no_controlled_effect"

    # Candidate tried to side-channel the harness — modify the target
    # wrapper, plant the marker via FS write to work_dir, etc. — instead
    # of driving the bug to corrupt program state. Almost always a
    # sandbox-blocked attempt; recording it as its own class means the
    # retrieval layer won't surface "modify the wrapper" candidates as
    # exemplars for the next run.
    HARNESS_SIDE_CHANNEL = "harness_side_channel"

    # Catch-all for "the run failed but we can't classify why."
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SandboxEvidence:
    """Evidence from a sandbox-run oracle.

    Produced by /exploit (LLM-emitted exploit run in sandbox),
    /fuzz (AFL++ crash + replay), /validate (Stage A/B PoC), and
    /crash-analysis (replayed crash under gdb/rr).

    Reproducible: True. Same target binary + bytes → same outcome.
    """

    # Trigger bytes
    bytes_hash: str                       # SHA-256 of the trigger bytes
    bytes_len: int                        # for quick filtering without re-hashing
    bytes_path: Optional[str] = None      # absolute or project-relative file path

    # Outcome — string value of :class:`core.witness.types.WitnessOutcome`.
    # Keeping the wire format as a string (rather than an Enum field)
    # preserves JSON round-trip simplicity; ``__post_init__`` enforces
    # the closed-vocabulary contract so this substrate and the witness
    # substrate share one outcome taxonomy.
    observed_outcome: str = "unknown"
    outcome_detail: dict[str, Any] = field(default_factory=dict)

    # Target binding
    target_binary_hash: Optional[str] = None
    target_source_hash: Optional[str] = None
    commit_sha: Optional[str] = None      # source-tree commit (ZKPoX-forward)

    # Environment
    mitigations_active: list[str] = field(default_factory=list)
    arch: Optional[str] = None            # "x86_64" / "aarch64" / ...
    libc_version: Optional[str] = None

    # The exploit source (when applicable — /exploit's LLM-emitted code)
    exploit_code: Optional[str] = None
    exploit_language: Optional[str] = None  # "c" / "cpp" / "py" / ...

    def __post_init__(self) -> None:
        # observed_outcome must come from the WitnessOutcome closed
        # vocabulary so labeled_attempts and core.witness share one
        # outcome taxonomy in practice. Imported inline to keep this
        # module import-cheap (a producer that never constructs a
        # SandboxEvidence shouldn't pay the witness-import cost).
        #
        # Empty string is an explicit "producer didn't classify yet"
        # sentinel — downstream projection (view.from_labeled_attempt)
        # treats it as INCONCLUSIVE. Any other non-WitnessOutcome value
        # is a producer bug.
        if self.observed_outcome != "":
            from core.witness.types import WitnessOutcome
            _valid = {wo.value for wo in WitnessOutcome}
            if self.observed_outcome not in _valid:
                raise ValueError(
                    f"observed_outcome must be empty (sentinel for "
                    f"'not classified') or one of {sorted(_valid)}; "
                    f"got {self.observed_outcome!r}"
                )
        if self.bytes_len < 0:
            raise ValueError(
                f"bytes_len must be >= 0; got {self.bytes_len}"
            )
        if self.bytes_len > _MAX_BYTES_LEN:
            raise ValueError(
                f"bytes_len {self.bytes_len} exceeds soft cap "
                f"{_MAX_BYTES_LEN}; producer is almost certainly buggy "
                f"(re-emitting a memory dump?)"
            )
        # bytes_hash must look like a SHA-256 hex digest. Empty string
        # is reserved for "no bytes recorded" — rare but allowed.
        if self.bytes_hash and (
            len(self.bytes_hash) != _SHA256_HEX_LEN
            or not all(c in "0123456789abcdefABCDEF" for c in self.bytes_hash)
        ):
            raise ValueError(
                f"bytes_hash must be 64-char hex (SHA-256); got "
                f"{self.bytes_hash!r}"
            )
        if (
            self.exploit_code is not None
            and len(self.exploit_code) > _MAX_EXPLOIT_CODE_LEN
        ):
            raise ValueError(
                f"exploit_code length {len(self.exploit_code)} exceeds "
                f"soft cap {_MAX_EXPLOIT_CODE_LEN}"
            )
        # outcome_detail must round-trip through JSON — if it can't,
        # we'd fail on write() later with a confusing trace. Catch it
        # here where the producer can fix the offending value.
        try:
            json.dumps(self.outcome_detail)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"outcome_detail must be JSON-serialisable; got "
                f"{type(self.outcome_detail).__name__}: {e}"
            ) from None


@dataclass(frozen=True)
class CodeQLEvidence:
    """Evidence from a CodeQL-adjudication oracle.

    Produced by audit's barrier_synth and the wider trust-witness arc:
    an LLM proposes a CodeQL barrier predicate; CodeQL adjudicates
    by running before/after queries to confirm the barrier suppresses
    the FP while preserving the TP.

    Reproducible: True. Same DB + query → same counts.
    """

    query_ql: str                         # the runnable CodeQL query
    before_count: int                     # findings on pre-fix DB (want >= 1)
    after_count: int                      # findings on post-fix DB (want 0)
    is_sound: bool                        # before_count >= 1 AND after_count == 0

    sink_class: Optional[str] = None      # "SQL" / "CommandInjection" / ...
    database_path: Optional[str] = None   # for reproducibility


@dataclass(frozen=True)
class WebEvidence:
    """Evidence from a live-HTTP confirmation oracle.

    Produced by /web scanner v2 (issue #289): fires only on actual
    exploitation evidence — ``{{7*7}}`` → ``49`` for SSTI, real DB
    error strings for SQLi, payload reflected unescaped for XSS,
    ``/etc/passwd`` content for path traversal, etc.

    Reproducible: False — point-in-time confirmation against a live
    target. Records are confirmed-once; full teaching value as
    exemplars but NO REPRODUCES state.
    """

    target_url: str
    http_request: dict[str, Any]          # method, path, headers, body
    response_evidence: dict[str, Any]     # status, body excerpt, evidence marker
    evidence_type: str                    # "ssti" / "sqli_error" / "path_traversal" / ...
    timestamp_iso: str                    # when the evidence was observed


@dataclass(frozen=True)
class LabeledAttempt:
    """The labeled-attempt record.

    Spine: ``finding_id`` + ``finding_signature`` + ``cwe`` + ``outcome``.
    Exactly one of ``sandbox_evidence`` / ``codeql_evidence`` /
    ``web_evidence`` is set.

    See ``view.py`` for the read-projection used by prompt assembly.
    """

    # === Spine ===
    finding_id: str                       # operational id (may change)
    finding_signature: str                # stable hash across renames/moves
    cwe: str                              # e.g. "CWE-416"
    outcome: Outcome

    # === Oracle evidence (exactly one set) ===
    sandbox_evidence: Optional[SandboxEvidence] = None
    codeql_evidence: Optional[CodeQLEvidence] = None
    web_evidence: Optional[WebEvidence] = None

    # === Provenance ===
    producing_model: str = ""             # "claude-haiku-4-5" / "claude-opus-4-7" / ...
    prompt_version: str = ""              # for A/B across prompt iterations
    tools_used: tuple[str, ...] = ()      # immutable
    iterations: int = 0
    cost_usd: float = 0.0

    # exemplar_ids of the RetrievedExemplars that were in the model's
    # prompt at the time of this attempt (Phase B unit #4). Empty for
    # runs that didn't go through L3 retrieval. Used downstream for
    # A/B: did the exemplar help or did the model ignore it?
    exemplars_used: tuple[str, ...] = ()

    # Why a non-successful attempt failed. None
    # for outcome="success" runs (no failure to classify) and for
    # records produced before unit #11 (schema-evolution safe via
    # from_dict defaulting).
    failure_mode: Optional[FailureMode] = None

    # === Reproducibility ===
    # Sandbox + CodeQL: deterministic replay → True.
    # Web: live-HTTP point-in-time → False.
    reproducible: bool = True

    # === Audit ===
    timestamp: str = ""                   # ISO-8601 UTC

    def __post_init__(self) -> None:
        oracle_count = sum(
            1 for e in (
                self.sandbox_evidence,
                self.codeql_evidence,
                self.web_evidence,
            ) if e is not None
        )
        if oracle_count != 1:
            raise ValueError(
                f"LabeledAttempt must have exactly one oracle evidence, "
                f"got {oracle_count}: "
                f"sandbox={self.sandbox_evidence is not None}, "
                f"codeql={self.codeql_evidence is not None}, "
                f"web={self.web_evidence is not None}"
            )
        if self.outcome not in ("success", "reasoned_failure", "uncertain"):
            raise ValueError(f"unknown outcome: {self.outcome!r}")
        if not self.finding_id:
            raise ValueError("finding_id is required")
        if not self.finding_signature:
            raise ValueError("finding_signature is required")
        # The signature is used as a directory name on disk. Reject
        # anything that isn't hex — this blocks path traversal
        # (`../../etc/escape`) and filesystem-name-limit attacks
        # while accepting all legitimate signatures from
        # compute_finding_signature() (32 hex chars) or the wider
        # SHA-256 hex digest form (64 chars).
        if not _VALID_SIGNATURE.match(self.finding_signature):
            raise ValueError(
                f"finding_signature must be 8-64 hex chars; got "
                f"{self.finding_signature!r}"
            )
        if not self.cwe:
            raise ValueError("cwe is required")
        # Consistency: a success record cannot have a failure_mode.
        # The reverse direction (failure outcomes without a
        # failure_mode) is permitted — old records and producers that
        # don't classify still need to load.
        if self.outcome == "success" and self.failure_mode is not None:
            raise ValueError(
                f"outcome='success' is incompatible with "
                f"failure_mode={self.failure_mode!r}. A successful "
                f"attempt has no failure to classify."
            )
        # Normalise timestamp at construction so it is always ISO-8601
        # parseable. Producers that pass garbage get rejected here,
        # not silently mismatched with the filename later. Empty
        # string → use now().
        if not self.timestamp:
            object.__setattr__(
                self, "timestamp", datetime.now(timezone.utc).isoformat()
            )
        else:
            try:
                datetime.fromisoformat(self.timestamp)
            except ValueError as e:
                raise ValueError(
                    f"timestamp must be ISO-8601 parseable; got "
                    f"{self.timestamp!r}: {e}"
                ) from None

    # -- Serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe dict. Tuples → lists, dataclasses → dicts.

        Round-trips with :meth:`from_dict` over the canonical field set;
        unknown keys are ignored on load so future schema additions
        don't break old persisted records.
        """
        d = asdict(self)
        # Tuples serialise as lists naturally via asdict, but be explicit:
        d["tools_used"] = list(self.tools_used)
        d["exemplars_used"] = list(self.exemplars_used)
        # FailureMode → its string value, or None.
        d["failure_mode"] = (
            self.failure_mode.value if self.failure_mode is not None else None
        )
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LabeledAttempt":
        """Inverse of :meth:`to_dict`. Tolerant of extra keys.

        Each evidence sub-construction and the final dataclass init are
        wrapped so a malformed on-disk blob yields a single line that
        names the offending sub-record, not a bare TypeError on a
        deeply-nested call.
        """
        def _build(name: str, evidence_cls, raw):
            if raw is None:
                return None
            try:
                return evidence_cls(**raw)
            except (TypeError, ValueError) as e:
                raise ValueError(
                    f"failed to build {evidence_cls.__name__} from "
                    f"{name!r}: {e}"
                ) from None

        sandbox = _build(
            "sandbox_evidence", SandboxEvidence, data.get("sandbox_evidence"),
        )
        codeql = _build(
            "codeql_evidence", CodeQLEvidence, data.get("codeql_evidence"),
        )
        web = _build("web_evidence", WebEvidence, data.get("web_evidence"))

        # Whitelist the spine + provenance fields; ignore unknown keys
        # so schema additions in newer RAPTOR versions don't break old
        # persisted records.
        known = {f.name for f in fields(cls)} - {
            "sandbox_evidence", "codeql_evidence", "web_evidence",
        }
        kw = {k: data[k] for k in known if k in data}
        # Ensure tuple-typed fields land as tuples on the frozen
        # dataclass even when serialised as lists.
        for tuple_field in ("tools_used", "exemplars_used"):
            if tuple_field in kw and not isinstance(kw[tuple_field], tuple):
                kw[tuple_field] = tuple(kw[tuple_field])
        # FailureMode: accept string or None on load; unknown strings
        # fall back to FailureMode.UNKNOWN rather than failing the
        # whole record load (forward-compat for new enum values).
        if "failure_mode" in kw:
            raw_fm = kw["failure_mode"]
            if raw_fm is None:
                pass
            elif isinstance(raw_fm, FailureMode):
                pass
            else:
                try:
                    kw["failure_mode"] = FailureMode(raw_fm)
                except ValueError:
                    kw["failure_mode"] = FailureMode.UNKNOWN
        try:
            return cls(
                sandbox_evidence=sandbox,
                codeql_evidence=codeql,
                web_evidence=web,
                **kw,
            )
        except (TypeError, ValueError) as e:
            finding_id = data.get("finding_id", "<unknown>")
            raise ValueError(
                f"failed to build LabeledAttempt for finding_id="
                f"{finding_id!r}: {e}"
            ) from None

    # -- Convenience accessors -------------------------------------------

    @property
    def oracle(self) -> Literal["sandbox", "codeql", "web"]:
        """Which oracle produced this record."""
        if self.sandbox_evidence is not None:
            return "sandbox"
        if self.codeql_evidence is not None:
            return "codeql"
        return "web"  # __post_init__ guarantees exactly one is set


# --------------------------------------------------------------------------
# Helper for computing a stable finding signature when the producer
# doesn't have one. Most producers already carry one; the helper is for
# adapters that need to mint a signature from raw fields.
# --------------------------------------------------------------------------


def compute_finding_signature(
    *,
    cwe: str,
    file_path: str,
    function: str,
    line: int,
    vuln_type: str = "",
) -> str:
    """Stable hash over fields that don't change with refactors of
    surrounding code (function name + line is more durable than file
    name alone; CWE locks the bug class).

    NOT a security primitive — collision-resistance is sufficient for
    deduplication, not for cryptographic claims.
    """
    import hashlib
    blob = "|".join([
        cwe.strip().upper(),
        file_path.strip(),
        function.strip(),
        str(line),
        vuln_type.strip().lower(),
    ]).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]
