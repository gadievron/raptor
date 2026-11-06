"""Data models for Coccinelle results."""

from dataclasses import dataclass, field
import math


def _coordinate(value) -> int:
    """Accept legacy integer strings, but never truncate or invent positions."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        return 0
    try:
        return max(0, int(value))
    except (ValueError, OverflowError):
        return 0


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
        def text(key: str) -> str:
            value = d.get(key)
            return value if isinstance(value, str) else ""

        file = text("file")
        return cls(
            file=file if "\x00" not in file else "",
            line=_coordinate(d.get("line")),
            column=_coordinate(d["col"] if d.get("col") is not None else d.get("column")),
            line_end=_coordinate(d.get("line_end")),
            column_end=_coordinate(d["col_end"] if d.get("col_end") is not None else d.get("column_end")),
            rule=text("rule"),
            message=text("message"),
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
    matches: list[SpatchMatch] = field(default_factory=list)
    files_examined: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    returncode: int = 0
    # COCCIRESULT-shaped output lines that did NOT carry the runner's
    # per-invocation nonce — rejected from ``matches`` and counted here
    # as an attack signal (hostile source planting forged evidence
    # lines that spatch's diff output re-emits).
    forged_markers: int = 0

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
            "forged_markers": self.forged_markers,
        }
