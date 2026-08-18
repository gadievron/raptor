"""Data models for Joern CPG results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set


def _coerce_int(value: object, default: int) -> int:
    """Best-effort int conversion for values parsed from Joern JSON.

    Real Joern emits numeric fields, but REPL output drifts across
    versions — a null or non-numeric string must not abort the whole
    flow parse.
    """
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default


@dataclass
class JoernCPG:
    """Handle to a built Code Property Graph on disk."""

    path: Path
    target: Path
    languages: Set[str] = field(default_factory=set)
    build_time_ms: int = 0

    def exists(self) -> bool:
        return self.path.exists()


@dataclass
class FlowStep:
    """One hop in a taint flow trace."""

    file: str
    function: str
    line: int
    code: str
    variable: str

    @classmethod
    def from_dict(cls, d: dict) -> FlowStep:
        return cls(
            file=d.get("file", ""),
            function=d.get("function", ""),
            line=_coerce_int(d.get("line", 0), 0),
            code=d.get("code", ""),
            variable=d.get("variable", ""),
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "code": self.code,
            "variable": self.variable,
        }


@dataclass
class TaintFlow:
    """A source-to-sink taint flow with intermediate steps."""

    source_method: str
    source_param: str
    sink_call: str
    sink_arg_idx: int
    steps: List[FlowStep] = field(default_factory=list)
    is_inter_procedural: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> TaintFlow:
        steps = [FlowStep.from_dict(s) for s in d.get("steps", [])]
        # Unattributed steps (empty function) must not count as a
        # distinct function — mirrors the runner's flow parser.
        funcs = {s.function for s in steps if s.function}
        return cls(
            source_method=d.get("source_method", ""),
            source_param=d.get("source_param", ""),
            sink_call=d.get("sink_call", ""),
            sink_arg_idx=_coerce_int(d.get("sink_arg_idx", -1), -1),
            steps=steps,
            is_inter_procedural=len(funcs) > 1,
        )

    def to_dict(self) -> dict:
        return {
            "source_method": self.source_method,
            "source_param": self.source_param,
            "sink_call": self.sink_call,
            "sink_arg_idx": self.sink_arg_idx,
            "steps": [s.to_dict() for s in self.steps],
            "is_inter_procedural": self.is_inter_procedural,
        }


@dataclass
class JoernMethodSummary:
    """Summary of taint rules, preconditions, and return properties for a method."""

    method: str
    taint_rules: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "taint_rules": self.taint_rules,
            "preconditions": self.preconditions,
            "returns": self.returns,
        }


@dataclass
class JoernResult:
    """Structured result from a Joern query execution."""

    query: str
    flows: List[TaintFlow] = field(default_factory=list)
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)
    elapsed_ms: int = 0
    dark_methods: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def flow_count(self) -> int:
        return len(self.flows)

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "flows": [f.to_dict() for f in self.flows],
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
            # Methods invisible to taint analysis (lost reaching-def
            # coverage) — the first thing to check when a sweep comes
            # back thin.
            "dark_methods": self.dark_methods,
        }
