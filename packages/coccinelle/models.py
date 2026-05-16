"""Data models for Coccinelle results."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class SpatchMatch:
    """A single match from a Coccinelle rule."""

    file: str
    line: int
    column: int = 0
    line_end: int = 0
    column_end: int = 0
    rule: str = ""
    message: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "SpatchMatch":
        if not d or not isinstance(d, dict):
            return cls(file="", line=0)
        return cls(
            file=d.get("file", ""),
            line=int(d.get("line", 0)),
            column=int(d.get("col", d.get("column", 0))),
            line_end=int(d.get("line_end", 0)),
            column_end=int(d.get("col_end", d.get("column_end", 0))),
            rule=d.get("rule", ""),
            message=d.get("message", ""),
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "line_end": self.line_end,
            "column_end": self.column_end,
            "rule": self.rule,
            "message": self.message,
        }


@dataclass
class SpatchResult:
    """Results from running a single Coccinelle rule."""

    rule: str
    rule_path: str = ""
    matches: List[SpatchMatch] = field(default_factory=list)
    files_examined: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_ms: int = 0
    returncode: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.errors

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "rule_path": self.rule_path,
            "matches": [m.to_dict() for m in self.matches],
            "files_examined": self.files_examined,
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
            "returncode": self.returncode,
        }
