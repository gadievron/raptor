"""Versioned, JSON-safe evidence records; no domain-model confidence promotion."""
from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from typing import Any

from core.json import dumps_canonical

VERSION = 1


def digest(value: Any) -> str:
    return hashlib.sha256(dumps_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Limits:
    max_files: int = 200
    max_bytes: int = 8_000_000
    max_sites: int = 20_000
    max_functions: int = 10_000
    scan_seconds: float = 20.0
    max_slices: int = 40
    functions_per_slice: int = 12
    source_chars: int = 24_000
    input_tokens: int = 12_000
    graph_depth: int = 3
    graph_seconds: float = 10.0
    max_calls: int = 8
    output_tokens: int = 2500
    retrieval_rounds: int = 1
    study_seconds: float = 180.0
    index_batch_files: int = 200
    index_batch_bytes: int = 8_000_000
    index_batch_seconds: float = 20.0

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be nonnegative")

    def content_settings(self) -> dict[str, Any]:
        """Execution allowances do not invalidate unchanged semantic work."""
        execution = {"max_calls","max_slices","study_seconds","scan_seconds","graph_seconds",
                     "index_batch_files","index_batch_bytes","index_batch_seconds"}
        return {k:v for k,v in asdict(self).items() if k not in execution}


@dataclass
class Function:
    id: str
    file: str
    name: str
    start: int
    end: int
    start_byte: int
    end_byte: int
    source_hash: str
    source: str
    static: bool = False
    params: list[str] = field(default_factory=list)


@dataclass
class Access:
    id: str
    function: str
    file: str
    line: int
    start_byte: int
    end_byte: int
    type_id: str
    binding: str
    member_path: str
    operation: str
    expression: str
    rhs: str = ""
    provenance: str = "unknown"
    resolution: str = "unresolved"
    object_origin: str = ""


@dataclass
class Call:
    caller: str
    name: str
    arguments: list[str]
    line: int
    targets: list[str] = field(default_factory=list)
    start_byte: int = 0
    end_byte: int = 0
    dispatch_type: str = ""
    dispatch_slot: str = ""
    dispatch_candidates: list[str] = field(default_factory=list)
    argument_kinds: list[str] = field(default_factory=list)
    dispatch_bindings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Relation:
    source: str
    target: str
    kind: str
    evidence: str
    resolution: str = "candidate"


@dataclass
class AccessIndex:
    functions: dict[str, Function] = field(default_factory=dict)
    declarations: dict[str, dict[str, Any]] = field(default_factory=dict)
    accesses: list[Access] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    entries: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    callbacks: list[dict[str, Any]] = field(default_factory=list)
    source_hashes: dict[str, str] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=lambda: {
        "files_scanned": [], "skipped": [], "unresolved": [], "truncated": [],
        "limitations": ["Build conditions are not evaluated", "Object aliasing is candidate evidence"],
    })
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"version": VERSION, **asdict(self)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccessIndex:
        if data.get("version") != VERSION:
            raise ValueError("unsupported access-index version")
        return cls(functions={k:Function(**v) for k,v in data["functions"].items()},
                   declarations=data["declarations"],accesses=[Access(**v) for v in data["accesses"]],
                   calls=[Call(**v) for v in data["calls"]],relations=[Relation(**v) for v in data["relations"]],
                   entries=data["entries"],callbacks=data.get("callbacks",[]),source_hashes=data["source_hashes"],
                   coverage=data["coverage"],fingerprint=data["fingerprint"])


@dataclass
class StudySlice:
    id: str
    consumer: str
    functions: list[str]
    access_ids: list[str]
    entry_paths: list[list[str]]
    reasons: list[str]
    unresolved: list[str]
    truncated: list[str]
    score: int
    source: str
    fingerprint: str
    dispatch_candidates: list[dict[str, Any]] = field(default_factory=list)
    evidence_candidates: list[str] = field(default_factory=list)
    focus_functions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
