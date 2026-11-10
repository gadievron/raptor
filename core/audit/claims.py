"""Pipeline-issued claim lineage, separate from checker evidence scope."""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, init=False)
class ClaimRevision:
    """One fixed statement in an explicitly linked claim history.

    IDs are issued by the pipeline, never read from model dictionaries.
    Occurrence records intake context only: it establishes neither source
    freshness nor binary image/representation identity. VerificationScope
    remains the producer's separate evidence binding.
    """

    claim_id: str
    revision_id: str
    revision: int
    parent_revision: str | None
    pass_id: str
    file: str
    function: str
    line_start: int
    _hypothesis: dict[str, Any] = field(repr=False)

    def __init__(self, hypothesis: dict[str, Any], *, pass_id: str,
                 file: str, function: str, line_start: int):
        if not isinstance(pass_id, str) or not pass_id.strip():
            raise ValueError("a claim requires a pipeline pass identity")
        object.__setattr__(self, "claim_id", uuid4().hex)
        object.__setattr__(self, "revision_id", uuid4().hex)
        object.__setattr__(self, "revision", 1)
        object.__setattr__(self, "parent_revision", None)
        object.__setattr__(self, "pass_id", pass_id)
        object.__setattr__(self, "file", file)
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "line_start", line_start)
        object.__setattr__(self, "_hypothesis", deepcopy(dict(hypothesis)))

    @property
    def hypothesis(self) -> dict[str, Any]:
        return deepcopy(self._hypothesis)

    def revise(self, hypothesis: dict[str, Any], *, pass_id: str) -> "ClaimRevision":
        """Explicitly link a new statement; no receipt or scope is copied."""
        child = ClaimRevision(hypothesis, pass_id=pass_id, file=self.file,
                              function=self.function, line_start=self.line_start)
        object.__setattr__(child, "claim_id", self.claim_id)
        object.__setattr__(child, "revision", self.revision + 1)
        object.__setattr__(child, "parent_revision", self.revision_id)
        return child

    def reference(self) -> dict:
        """Data-only reference; the containing observation owns its statement."""
        return {"claim_id": self.claim_id, "revision_id": self.revision_id, "revision": self.revision,
                "parent_revision": self.parent_revision, "pass_id": self.pass_id,
                "file": self.file, "function": self.function, "line_start": self.line_start}
