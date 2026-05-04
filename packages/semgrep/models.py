"""Data models for Semgrep results."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SemgrepFinding:
    """A single finding from a Semgrep rule, parsed from SARIF."""

    file: str
    line: int
    rule_id: str = ""
    message: str = ""
    column: int = 0
    line_end: int = 0
    column_end: int = 0
    level: str = "warning"

    @classmethod
    def from_sarif_result(cls, result: dict) -> "SemgrepFinding":
        """Build from a single SARIF runs[].results[] entry."""
        if not result or not isinstance(result, dict):
            return cls(file="", line=0)

        rule_id = result.get("ruleId", "")
        message = ""
        msg = result.get("message")
        if isinstance(msg, dict):
            message = msg.get("text", "")
        elif isinstance(msg, str):
            message = msg

        level = result.get("level", "warning")

        file = ""
        line = 0
        column = 0
        line_end = 0
        column_end = 0

        locations = result.get("locations") or []
        if locations and isinstance(locations[0], dict):
            phys = locations[0].get("physicalLocation") or {}
            artifact = phys.get("artifactLocation") or {}
            file = artifact.get("uri", "")
            region = phys.get("region") or {}
            line = int(region.get("startLine", 0))
            column = int(region.get("startColumn", 0))
            line_end = int(region.get("endLine", 0))
            column_end = int(region.get("endColumn", 0))

        return cls(
            file=file,
            line=line,
            column=column,
            line_end=line_end,
            column_end=column_end,
            rule_id=rule_id,
            message=message,
            level=level,
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "line_end": self.line_end,
            "column_end": self.column_end,
            "rule_id": self.rule_id,
            "message": self.message,
            "level": self.level,
        }


@dataclass
class SemgrepResult:
    """Results from running Semgrep with one config against a target.

    Fields are populated by the runner. SARIF and JSON outputs are kept as
    raw strings so callers can persist them in their own layout (e.g.
    scanner.py writes `semgrep_<name>.sarif`).
    """

    name: str = ""
    config: str = ""
    target: str = ""
    findings: List[SemgrepFinding] = field(default_factory=list)
    files_examined: List[str] = field(default_factory=list)
    files_failed: List[Dict[str, str]] = field(default_factory=list)
    semgrep_version: str = ""
    returncode: int = 0
    stderr: str = ""
    sarif: str = ""
    json_output: str = ""
    elapsed_ms: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        # Semgrep returns 0 on no findings, 1 when findings exist (with --error).
        # Anything outside {0,1} or recorded errors mean a real failure.
        return self.returncode in (0, 1) and not self.errors

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "config": self.config,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "files_examined": self.files_examined,
            "files_failed": self.files_failed,
            "semgrep_version": self.semgrep_version,
            "returncode": self.returncode,
            "elapsed_ms": self.elapsed_ms,
            "errors": self.errors,
        }


def parse_sarif(text: str) -> List[SemgrepFinding]:
    """Parse SARIF JSON text into SemgrepFinding objects.

    Returns an empty list on malformed input rather than raising — Semgrep
    sometimes emits empty output on rule errors.
    """
    import json

    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    findings: List[SemgrepFinding] = []
    runs = data.get("runs") or []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results") or []
        for result in results:
            findings.append(SemgrepFinding.from_sarif_result(result))
    return findings


def parse_json_output(text: str) -> Dict[str, Any]:
    """Parse Semgrep's --json-output content for paths.scanned, errors, version.

    Returns a dict with keys: files_examined, files_failed, semgrep_version.
    Empty/malformed input returns empty values rather than raising.
    """
    import json

    out: Dict[str, Any] = {
        "files_examined": [],
        "files_failed": [],
        "semgrep_version": "",
    }
    if not text or not text.strip():
        return out
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return out
    if not isinstance(data, dict):
        return out

    paths = data.get("paths") or {}
    scanned = paths.get("scanned") or []
    out["files_examined"] = sorted(str(p) for p in scanned if p)

    errors = data.get("errors") or []
    out["files_failed"] = [
        {"path": str(e.get("path", "")), "reason": str(e.get("message", "error"))}
        for e in errors
        if isinstance(e, dict) and e.get("path")
    ]

    out["semgrep_version"] = str(data.get("version", ""))
    return out
