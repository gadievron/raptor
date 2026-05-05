"""Typed-plan layer — Pydantic models for hypotheses, locations, evidence.

These types are additive to the existing `hypothesis.py` / `result.py` /
`adapters/base.py` surface. The legacy dataclasses remain the API contract
for Phase A (single-shot) callers; the typed surface here is what the
deferred iteration loop and the AST-typed plan checker will consume.

Naming: the pre-existing dataclass `Hypothesis` stays in `hypothesis.py`
to keep backward compatibility for callers that already use it. The
typed equivalent lives here as `TypedHypothesis` and carries the richer
structure the design doc calls for (source/sink/flow/sanitizers/SMT
constraints).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    """Three-valued verdict ordered by the agreement lattice.

    Inheriting from `str` means `Verdict.CONFIRMED == "confirmed"` holds,
    so values pass through anywhere the legacy `Literal["confirmed",
    "refuted", "inconclusive"]` type is expected.

    INCONCLUSIVE is bottom: tool failure, no applicable adapter, or
    disagreement between adapters all collapse here.
    """

    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    CONFIRMED = "confirmed"


class SourceKind(str, Enum):
    NETWORK = "network"
    FILE = "file"
    ENV = "env"
    USER = "user"
    IPC = "ipc"
    UNKNOWN = "unknown"


class SinkKind(str, Enum):
    EXEC = "exec"
    SQL = "sql"
    DEREF = "deref"
    WRITE = "write"
    INDEX = "index"
    ALLOC = "alloc"
    UNKNOWN = "unknown"


class SourceLocation(BaseModel):
    """Where attacker-controlled data enters."""

    model_config = ConfigDict(frozen=True)

    kind: SourceKind = SourceKind.UNKNOWN
    file: str = ""
    function: str = ""
    line: int = 0


class SinkLocation(BaseModel):
    """Where the dangerous use happens."""

    model_config = ConfigDict(frozen=True)

    kind: SinkKind = SinkKind.UNKNOWN
    file: str = ""
    function: str = ""
    line: int = 0


class FlowStep(BaseModel):
    """One hop in the source → sink data-flow chain."""

    model_config = ConfigDict(frozen=True)

    file: str = ""
    function: str = ""
    line: int = 0
    description: str = ""


class TypedHypothesis(BaseModel):
    """Typed projection of a vulnerability hypothesis.

    Promoting the hypothesis from free-form text to a Pydantic model
    removes a class of failures where the natural-language phrasing
    under-specifies what an adapter should look for. `rationale` is the
    LLM's reasoning; it is **explicitly not a verdict** — verdicts come
    from the lattice in `verdict.py`.
    """

    model_config = ConfigDict(frozen=True)

    cwe: str
    source: SourceLocation
    sink: SinkLocation
    flow: List[FlowStep] = Field(default_factory=list)
    expected_sanitizers: List[str] = Field(default_factory=list)
    smt_constraints: List[str] = Field(default_factory=list)
    rationale: str = ""


class Match(BaseModel):
    """A typed match record.

    Adapters built before the typed layer return raw dicts; this model
    carries the same fields plus a `refers_to` provenance edge so the
    runner can refuse to combine evidence whose hypothesis hashes differ.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    file: str = ""
    line: int = 0
    message: str = ""
    refers_to: str = ""


class Effect(str, Enum):
    """Side-effect classes adapters declare up front."""

    NETWORK = "network"
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    SUBPROCESS = "subprocess"
    PURE = "pure"


class Cost(BaseModel):
    """Coarse cost annotation; finer scheduling can refine later."""

    model_config = ConfigDict(frozen=True)

    seconds: float = 0.0
    cpu_bound: bool = True


class AdapterQuery(BaseModel):
    """Projected hypothesis ready for a specific adapter to run.

    The `body` is the tool-native rule text (SmPL, Semgrep YAML, .ql,
    SMT constraint set). `tool` names the destination adapter; the
    runner uses it to dispatch.
    """

    model_config = ConfigDict(frozen=True)

    tool: str
    body: str
    refers_to: str = ""


class AdapterSpec(BaseModel):
    """Adapter declared as a typed morphism Hyp → Evidence.

    Splits the existing `ToolAdapter.run` into two pieces — `project`
    (turn a typed hypothesis into a tool-native query) and `run` (execute
    the query against a target) — plus declarative metadata
    (`applicable`, `effects`, `cost`) the runner uses for selection and
    scheduling. Compatible with existing `ToolAdapter` instances via
    `adapter_spec.from_tool_adapter`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    name: str
    applicable: Callable[[TypedHypothesis], bool]
    project: Callable[[TypedHypothesis], AdapterQuery]
    run: Callable[..., Any]
    effects: frozenset[Effect] = Field(default_factory=frozenset)
    cost: Cost = Field(default_factory=Cost)


__all__ = [
    "Verdict",
    "SourceKind",
    "SinkKind",
    "SourceLocation",
    "SinkLocation",
    "FlowStep",
    "TypedHypothesis",
    "Match",
    "Effect",
    "Cost",
    "AdapterQuery",
    "AdapterSpec",
]
