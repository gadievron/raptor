"""Hypothesis dataclass — what the LLM thinks might be wrong.

The base shape (claim, target, target_function, cwe, suggested_tools,
context) is the contract Phase A callers depend on. The optional
structured fields (source, sink, flow_steps, sanitizers,
smt_constraints) are additive: adapters use them when set, ignore them
when unset. No breaking changes to existing callers.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class SourceLocation:
    """Where attacker-controlled data enters.

    All fields are optional so the LLM can populate as much or as little
    as it knows. `kind` is a free-form tag (e.g. "network", "file",
    "env") rather than an enum to keep this layer framework-free — the
    adapter layer is responsible for any kind-specific dispatch.
    """

    kind: str = ""
    file: str = ""
    function: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "file": self.file,
            "function": self.function,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "SourceLocation":
        if not d or not isinstance(d, dict):
            return cls()
        return cls(
            kind=d.get("kind", "") or "",
            file=d.get("file", "") or "",
            function=d.get("function", "") or "",
            line=int(d.get("line", 0) or 0),
        )


@dataclass
class SinkLocation:
    """Where the dangerous use happens. Same shape as SourceLocation."""

    kind: str = ""
    file: str = ""
    function: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "file": self.file,
            "function": self.function,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "SinkLocation":
        if not d or not isinstance(d, dict):
            return cls()
        return cls(
            kind=d.get("kind", "") or "",
            file=d.get("file", "") or "",
            function=d.get("function", "") or "",
            line=int(d.get("line", 0) or 0),
        )


@dataclass
class FlowStep:
    """One hop in the source → sink data-flow chain."""

    file: str = ""
    function: str = ""
    line: int = 0
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "FlowStep":
        if not d or not isinstance(d, dict):
            return cls()
        return cls(
            file=d.get("file", "") or "",
            function=d.get("function", "") or "",
            line=int(d.get("line", 0) or 0),
            description=d.get("description", "") or "",
        )


@dataclass
class Hypothesis:
    """A claim about a potential vulnerability that mechanical tools can test.

    The LLM produces hypotheses by reasoning about a function's assumptions
    ("this trusts X to be NULL-checked, what if it isn't?"). The runner
    then asks the LLM to translate the hypothesis into a tool invocation.

    Required attributes:
        claim: Free-text description of the suspected weakness. Should be
            specific enough that a tool rule can be generated from it.
        target: File or directory to test against.

    Optional metadata:
        target_function: Optional specific function within the target.
            Empty string when the hypothesis applies to the whole file.
        cwe: Optional CWE-NNN tag. Used for selecting exemplars and
            for routing the prompt template.
        suggested_tools: Optional ordered list of adapter names the LLM
            proposed for testing. The runner can override by selecting
            a different adapter from those available.
        context: Optional additional context to inject into the prompt
            (callers, callees, related annotations).

    Optional structured fields (used by adapters that know how to read
    them; ignored otherwise — additive, not breaking):
        source: Where attacker-controlled data enters.
        sink: Where the dangerous use happens.
        flow_steps: Ordered hops in the source → sink chain.
        sanitizers: Patterns the LLM expects to see (and which, if
            absent, support the hypothesis).
        smt_constraints: Constraint strings for the SMT adapter.
    """

    claim: str
    target: Path
    target_function: str = ""
    cwe: str = ""
    suggested_tools: List[str] = field(default_factory=list)
    context: str = ""
    source: Optional[SourceLocation] = None
    sink: Optional[SinkLocation] = None
    flow_steps: List[FlowStep] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    smt_constraints: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "claim": self.claim,
            "target": str(self.target),
            "target_function": self.target_function,
            "cwe": self.cwe,
            "suggested_tools": list(self.suggested_tools),
            "context": self.context,
        }
        # Only include structured fields when populated, so the existing
        # to_dict shape (and round-trip equality) is unchanged for callers
        # that don't use them.
        if self.source is not None:
            d["source"] = self.source.to_dict()
        if self.sink is not None:
            d["sink"] = self.sink.to_dict()
        if self.flow_steps:
            d["flow_steps"] = [s.to_dict() for s in self.flow_steps]
        if self.sanitizers:
            d["sanitizers"] = list(self.sanitizers)
        if self.smt_constraints:
            d["smt_constraints"] = list(self.smt_constraints)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Hypothesis":
        if not d or not isinstance(d, dict):
            return cls(claim="", target=Path("."))
        source = SourceLocation.from_dict(d.get("source")) if d.get("source") else None
        sink = SinkLocation.from_dict(d.get("sink")) if d.get("sink") else None
        flow_steps = [
            FlowStep.from_dict(s) for s in (d.get("flow_steps") or [])
            if isinstance(s, dict)
        ]
        return cls(
            claim=d.get("claim", ""),
            target=Path(d.get("target", ".")),
            target_function=d.get("target_function", ""),
            cwe=d.get("cwe", ""),
            suggested_tools=list(d.get("suggested_tools") or []),
            context=d.get("context", ""),
            source=source,
            sink=sink,
            flow_steps=flow_steps,
            sanitizers=list(d.get("sanitizers") or []),
            smt_constraints=list(d.get("smt_constraints") or []),
        )
