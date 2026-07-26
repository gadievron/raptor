"""Data model for lifecycle-precondition analysis.

A :class:`StateField` records every write site (with the conjunction of
guards dominating that write) and every security-relevant read site.
The checker (:mod:`core.analysis.lifecycle_checker`) compares the two sets to
find read sites whose reachable paths are not covered by any write-site
precondition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List


@dataclass(frozen=True)
class Guard:
    """One condition that dominates a code site."""

    condition: str
    file: str
    line: int
    polarity: bool = True
    smt_parseable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "condition": self.condition,
            "file": self.file,
            "line": self.line,
        }
        if not self.polarity:
            d["polarity"] = False
        if self.smt_parseable:
            d["smt_parseable"] = True
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Guard:
        return cls(
            condition=data["condition"],
            file=data["file"],
            line=data["line"],
            polarity=data.get("polarity", True),
            smt_parseable=data.get("smt_parseable", False),
        )


@dataclass(frozen=True)
class WriteSite:
    """One site where a state field is assigned a value."""

    file: str
    line: int
    function: str
    guards: FrozenSet[Guard]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "guards": [g.to_dict() for g in sorted(self.guards, key=lambda g: (g.file, g.line))],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WriteSite:
        return cls(
            file=data["file"],
            line=data["line"],
            function=data["function"],
            guards=frozenset(Guard.from_dict(g) for g in data.get("guards", [])),
        )


@dataclass(frozen=True)
class ReadSite:
    """One site where a state field is consumed in a security-relevant check."""

    file: str
    line: int
    function: str
    guards: FrozenSet[Guard]
    security_relevant: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "guards": [g.to_dict() for g in sorted(self.guards, key=lambda g: (g.file, g.line))],
        }
        if not self.security_relevant:
            d["security_relevant"] = False
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReadSite:
        return cls(
            file=data["file"],
            line=data["line"],
            function=data["function"],
            guards=frozenset(Guard.from_dict(g) for g in data.get("guards", [])),
            security_relevant=data.get("security_relevant", True),
        )


@dataclass
class StateField:
    """A struct/object field with lifecycle-sensitive semantics.

    The field carries a security-relevant invariant that depends on
    a precondition holding at read time.  If ANY write site's guard
    set is not covered at a read site, the invariant may not carry.
    """

    name: str
    struct_type: str
    invariant: str
    write_sites: List[WriteSite] = field(default_factory=list)
    read_sites: List[ReadSite] = field(default_factory=list)
    cwe: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "struct_type": self.struct_type,
            "invariant": self.invariant,
            "write_sites": [w.to_dict() for w in self.write_sites],
            "read_sites": [r.to_dict() for r in self.read_sites],
        }
        if self.cwe:
            d["cwe"] = self.cwe
        if self.notes:
            d["notes"] = self.notes
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StateField:
        return cls(
            name=data["name"],
            struct_type=data["struct_type"],
            invariant=data["invariant"],
            write_sites=[WriteSite.from_dict(w) for w in data.get("write_sites", [])],
            read_sites=[ReadSite.from_dict(r) for r in data.get("read_sites", [])],
            cwe=data.get("cwe", ""),
            notes=data.get("notes", ""),
        )

    @property
    def write_guard_conditions(self) -> FrozenSet[str]:
        """Union of all guard condition strings across write sites."""
        return frozenset(
            g.condition for ws in self.write_sites for g in ws.guards
        )


@dataclass
class LifecycleFinding:
    """A read site where a state field's invariant may not carry."""

    state_field: StateField
    read_site: ReadSite
    missing_guards: FrozenSet[str]
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.state_field.name,
            "struct_type": self.state_field.struct_type,
            "invariant": self.state_field.invariant,
            "read_site": self.read_site.to_dict(),
            "missing_guards": sorted(self.missing_guards),
            "confidence": self.confidence,
            "cwe": self.state_field.cwe,
        }
