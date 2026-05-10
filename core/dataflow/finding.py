"""Producer-neutral dataflow ``Finding`` and ``Step`` dataclasses.

A :class:`Finding` is one dataflow result: source location, sink
location, intermediate path steps, and the producer's raw blob for
round-tripping.

``finding_id`` must be stable across reruns of the same producer
against the same target — corpus replay matches labels by id. Callers
typically derive it from ``producer`` + ``rule_id`` + source/sink
locations.

:class:`Step` is fully frozen (all fields are immutable). :class:`Finding`
is not — its ``raw`` field is a producer-private mutable mapping —
but all its other invariants (non-empty required strings, tuple-typed
intermediate steps, strict JSON loading) are enforced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple


SCHEMA_VERSION = 1


_STEP_KEYS: FrozenSet[str] = frozenset(
    {"file_path", "line", "column", "snippet", "label"}
)
_FINDING_KEYS: FrozenSet[str] = frozenset(
    {
        "schema_version",
        "finding_id",
        "producer",
        "rule_id",
        "message",
        "source",
        "sink",
        "intermediate_steps",
        "raw",
    }
)


def _check_extra_fields(name: str, data: Mapping[str, Any], allowed: FrozenSet[str]) -> None:
    extras = set(data.keys()) - allowed
    if extras:
        raise ValueError(f"unknown fields in {name} JSON: {sorted(extras)}")


def _require_nonempty(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


@dataclass(frozen=True)
class Step:
    """One node on a dataflow path.

    ``label`` is one of ``"source"``, ``"step"``, ``"sink"``, or
    ``"sanitizer"`` when the producer attaches a role; ``None`` when
    the producer doesn't distinguish.
    """

    file_path: str
    line: int
    column: int
    snippet: str
    label: Optional[str] = None

    def __post_init__(self) -> None:
        _require_nonempty("Step.file_path", self.file_path)
        if self.line < 1:
            raise ValueError(f"Step.line must be >= 1, got {self.line}")
        if self.column < 0:
            raise ValueError(f"Step.column must be >= 0, got {self.column}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Step":
        _check_extra_fields("Step", data, _STEP_KEYS)
        return cls(
            file_path=data["file_path"],
            line=data["line"],
            column=data["column"],
            snippet=data["snippet"],
            label=data.get("label"),
        )


@dataclass
class Finding:
    """One producer-neutral dataflow finding.

    ``raw`` carries the producer's full original record so adapters
    are round-trippable without lossy reconstruction. Consumers must
    not depend on ``raw`` shape — that's producer-private.

    ``intermediate_steps`` is coerced to a tuple in :meth:`__post_init__`
    regardless of caller input — pass a list, get a tuple. The class
    itself is not frozen because :meth:`from_dict` constructs ``raw``
    as a mutable dict for round-trip fidelity, but no consumer should
    mutate it.
    """

    finding_id: str
    producer: str
    rule_id: str
    message: str
    source: Step
    sink: Step
    intermediate_steps: Tuple[Step, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_nonempty("Finding.finding_id", self.finding_id)
        _require_nonempty("Finding.producer", self.producer)
        _require_nonempty("Finding.rule_id", self.rule_id)
        _require_nonempty("Finding.message", self.message)
        if not isinstance(self.intermediate_steps, tuple):
            self.intermediate_steps = tuple(self.intermediate_steps)
        if not all(isinstance(s, Step) for s in self.intermediate_steps):
            raise TypeError("Finding.intermediate_steps must contain Step instances")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "producer": self.producer,
            "rule_id": self.rule_id,
            "message": self.message,
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "intermediate_steps": [s.to_dict() for s in self.intermediate_steps],
            "raw": dict(self.raw),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        _check_extra_fields("Finding", data, _FINDING_KEYS)
        version = data["schema_version"]
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"Finding schema_version {version!r} != expected "
                f"{SCHEMA_VERSION!r}; corpus upgrade required"
            )
        steps_raw: Iterable[Mapping[str, Any]] = data.get("intermediate_steps", [])
        return cls(
            finding_id=data["finding_id"],
            producer=data["producer"],
            rule_id=data["rule_id"],
            message=data["message"],
            source=Step.from_dict(data["source"]),
            sink=Step.from_dict(data["sink"]),
            intermediate_steps=tuple(Step.from_dict(s) for s in steps_raw),
            raw=dict(data.get("raw", {})),
        )

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls, text: str) -> "Finding":
        return cls.from_dict(json.loads(text))
