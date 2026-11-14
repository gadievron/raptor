"""Run-owned study lineage accounting, separate from paid budget admission.

The Runtime serialises every operation under its existing lock and owns unit
allowances, review reservations and source validation. Descriptors supplied here
must already come from pipeline-owned preparation. This ledger authenticates
neither a source descriptor nor an explanation.
"""

from dataclasses import dataclass, field
from uuid import uuid4


def _text(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _identities(values: object) -> bool:
    return (type(values) is tuple and bool(values)
            and all(_text(value) for value in values)
            and len(set(values)) == len(values))


@dataclass(frozen=True)
class StudyJobDescriptor:
    lineage: str
    generation: str

    def __post_init__(self) -> None:
        if not _text(self.lineage) or not _text(self.generation):
            raise ValueError("study lineage and material generation are required")


@dataclass(frozen=True)
class StudyDispatchLease:
    lease_id: str
    owner_id: str
    jobs: tuple[StudyJobDescriptor, ...]
    request_ids: tuple[str, ...]
    input_binding_ids: tuple[str, ...]


@dataclass
class _Job:
    generation: str
    spent: int = 0
    active_lease: str | None = None
    accounting_unknown: bool = False
    unknown_reasons: set[str] = field(default_factory=set)


@dataclass
class _Lease:
    token: StudyDispatchLease
    active: bool = True
    accounting_known: bool | None = None
    publication_closed: bool = False
    counted_admissions: int = 0
    unknown_reasons: set[str] = field(default_factory=set)


class SemanticStudyJobLedger:
    """One physical lease per lineage, with an explicit per-lineage allowance.

    Generation changes retain all spending and unknown-accounting tombstones.
    An identified sequential retry may debit the same live lease again. Closing
    its logical owner does not establish that its physical invocation retired.
    """

    def __init__(self, job_call_limit: int):
        if type(job_call_limit) is not int or job_call_limit < 1:
            raise ValueError("study job allowance must be an explicit positive integer")
        self._job_call_limit = job_call_limit
        self._jobs: dict[str, _Job] = {}
        self._leases: dict[str, _Lease] = {}
        self._closed = False

    @property
    def job_call_limit(self) -> int:
        return self._job_call_limit

    def begin(
        self, *, owner_id: str, jobs: tuple[StudyJobDescriptor, ...],
        request_ids: tuple[str, ...], input_binding_ids: tuple[str, ...],
        unit_caps: tuple[int, ...],
    ) -> tuple[StudyDispatchLease | None, str]:
        """Freeze one dispatch's supplied participants, without charging it."""
        if self._closed:
            return None, "study_jobs_closed"
        if (not _text(owner_id) or type(jobs) is not tuple or not jobs
                or not all(type(job) is StudyJobDescriptor for job in jobs)
                or not _identities(request_ids) or not _identities(input_binding_ids)
                or type(unit_caps) is not tuple or not unit_caps
                or not all(type(cap) is int and cap > 0 for cap in unit_caps)):
            return None, "study_job_inputs_unavailable"
        if self.job_call_limit > min(unit_caps):
            return None, "study_job_allowance_exceeds_unit_cap"
        by_lineage: dict[str, StudyJobDescriptor] = {}
        for descriptor in jobs:
            previous = by_lineage.setdefault(descriptor.lineage, descriptor)
            if previous != descriptor:
                return None, "study_job_generation_ambiguous"
        descriptors = tuple(by_lineage[key] for key in sorted(by_lineage))
        # Observing a different prepared generation invalidates old delivery,
        # even when its still-live physical lease prevents a replacement.
        for descriptor in descriptors:
            job = self._jobs.setdefault(descriptor.lineage, _Job(descriptor.generation))
            if job.generation != descriptor.generation:
                job.generation = descriptor.generation
                for lease in self._leases.values():
                    if any(old.lineage == descriptor.lineage for old in lease.token.jobs):
                        lease.publication_closed = True
        for descriptor in descriptors:
            job = self._jobs[descriptor.lineage]
            if job.accounting_unknown:
                return None, "study_job_accounting_unknown"
            if job.active_lease is not None:
                return None, "study_job_dispatch_live"
            if job.spent >= self.job_call_limit:
                return None, "study_job_call_limit"
        token = StudyDispatchLease(uuid4().hex, owner_id, descriptors,
                                   request_ids, input_binding_ids)
        self._leases[token.lease_id] = _Lease(token)
        for descriptor in descriptors:
            self._jobs[descriptor.lineage].active_lease = token.lease_id
        return token, ""

    def _owned(self, token: StudyDispatchLease) -> _Lease | None:
        if type(token) is not StudyDispatchLease:
            return None
        lease = self._leases.get(token.lease_id)
        return lease if lease is not None and lease.token is token else None

    def validity_rejection(self, token: StudyDispatchLease) -> str | None:
        """Check a live invocation without charging or reserving another call."""
        if self._closed:
            return "study_jobs_closed"
        lease = self._owned(token)
        if lease is None or not lease.active:
            return "study_job_lease_unavailable"
        if lease.publication_closed:
            return "study_job_owner_or_generation_closed"
        for descriptor in token.jobs:
            job = self._jobs[descriptor.lineage]
            if job.generation != descriptor.generation:
                return "study_job_generation_changed"
            if job.active_lease != token.lease_id:
                return "study_job_lease_unavailable"
            if job.accounting_unknown:
                return "study_job_accounting_unknown"
        return None

    def admission_rejection(self, token: StudyDispatchLease) -> str | None:
        reason = self.validity_rejection(token)
        if reason is not None:
            return reason
        if any(self._jobs[descriptor.lineage].spent >= self.job_call_limit
               for descriptor in token.jobs):
            return "study_job_call_limit"
        return None

    def debit(self, token: StudyDispatchLease) -> None:
        """Debit every distinct lineage after all job/unit preflights succeed."""
        reason = self.admission_rejection(token)
        if reason is not None:
            raise ValueError(reason)
        for descriptor in token.jobs:
            self._jobs[descriptor.lineage].spent += 1
        self._leases[token.lease_id].counted_admissions += 1

    def mark_unknown(self, token: StudyDispatchLease, reason: str) -> None:
        """Retain opaque accounting uncertainty; retirement cannot erase it."""
        lease = self._owned(token)
        if lease is None:
            return
        reason = reason if _text(reason) else "study_job_accounting_unknown"
        lease.unknown_reasons.add(reason)
        for descriptor in token.jobs:
            job = self._jobs[descriptor.lineage]
            job.accounting_unknown = True
            job.unknown_reasons.add(reason)

    def owner_finished(self, owner_id: str) -> None:
        """Close late publication, never pretend that a worker returned."""
        for lease in self._leases.values():
            if lease.active and lease.token.owner_id == owner_id:
                lease.publication_closed = True
                lease.unknown_reasons.add("study_owner_finished_while_dispatch_live")

    def retire(self, token: StudyDispatchLease, *, accounting_known: bool) -> None:
        """Called only by the actual invocation's completion owner, once."""
        lease = self._owned(token)
        if lease is None or not lease.active:
            return
        if type(accounting_known) is not bool:
            raise ValueError("physical retirement needs an explicit accounting status")
        if not accounting_known:
            self.mark_unknown(token, "study_dispatch_retired_with_unknown_accounting")
        lease.active = False
        lease.accounting_known = accounting_known and not any(
            self._jobs[descriptor.lineage].accounting_unknown for descriptor in token.jobs)
        for descriptor in token.jobs:
            job = self._jobs[descriptor.lineage]
            if job.active_lease == token.lease_id:
                job.active_lease = None

    def permits_answer(self, request_id: str, input_binding_ids: tuple[str, ...], *,
                       token: StudyDispatchLease | None = None) -> bool:
        """Check attempt custody only; the Runtime must still validate inputs."""
        if self._closed or not _text(request_id) or not _identities(input_binding_ids):
            return False
        owned = self._owned(token) if token is not None else None
        if token is not None and owned is None:
            return False
        leases = (owned,) if owned is not None else self._leases.values()
        for lease in leases:
            token = lease.token
            if (lease.active or lease.publication_closed or not lease.accounting_known
                    or lease.counted_admissions == 0 or request_id not in token.request_ids
                    or input_binding_ids != token.input_binding_ids):
                continue
            if all(self._jobs[descriptor.lineage].generation == descriptor.generation
                   and not self._jobs[descriptor.lineage].accounting_unknown
                   for descriptor in token.jobs):
                return True
        return False

    def close(self) -> None:
        self._closed = True
        for lease in self._leases.values():
            lease.publication_closed = True

    def snapshot(self) -> dict:
        """Return copied descriptive state, never a publication receipt."""
        return {
            "closed": self._closed,
            "job_call_limit": self.job_call_limit,
            "jobs": [{"lineage": lineage, "generation": job.generation,
                      "spent": job.spent, "active_lease": job.active_lease,
                      "accounting_unknown": job.accounting_unknown,
                      "unknown_reasons": sorted(job.unknown_reasons)}
                     for lineage, job in sorted(self._jobs.items())],
            "leases": [{"lease_id": lease_id, "owner_id": lease.token.owner_id,
                        "request_ids": list(lease.token.request_ids),
                        "input_binding_ids": list(lease.token.input_binding_ids),
                        "jobs": [{"lineage": job.lineage, "generation": job.generation}
                                 for job in lease.token.jobs],
                        "active": lease.active, "accounting_known": lease.accounting_known,
                        "publication_closed": lease.publication_closed,
                        "counted_admissions": lease.counted_admissions,
                        "unknown_reasons": sorted(lease.unknown_reasons)}
                       for lease_id, lease in self._leases.items()],
        }
