"""Data models for Semgrep results."""

from dataclasses import dataclass, field
from typing import Any

from core.json.bounded import loads_bounded

# Byte ceiling for semgrep tool output (SARIF on stdout and the
# --json-output file). Both are produced over a scanned — possibly
# hostile — repository, which can inflate them arbitrarily through
# file paths, match snippets, and error messages. Large legitimate
# scans reach tens of MB; 128 MiB matches the cap used for SARIF
# artifacts elsewhere while refusing DoS-scale payloads.
_MAX_TOOL_OUTPUT_BYTES = 128 * 1024 * 1024


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
            try:
                line = int(region.get("startLine", 0))
                column = int(region.get("startColumn", 0))
                line_end = int(region.get("endLine", 0))
                column_end = int(region.get("endColumn", 0))
            except (ValueError, TypeError):
                pass

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
    findings: list[SemgrepFinding] = field(default_factory=list)
    files_examined: list[str] = field(default_factory=list)
    files_failed: list[dict[str, str]] = field(default_factory=list)
    semgrep_version: str = ""
    returncode: int = 0
    stderr: str = ""
    sarif: str = ""
    json_output: str = ""
    elapsed_ms: int = 0
    errors: list[str] = field(default_factory=list)

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


def parse_sarif(text: str) -> list[SemgrepFinding]:
    """Parse SARIF JSON text into SemgrepFinding objects.

    Returns an empty list on malformed input rather than raising — Semgrep
    sometimes emits empty output on rule errors. Over-budget input
    (> ``_MAX_TOOL_OUTPUT_BYTES``) is refused the same way, with the
    size logged by the bounded loader.
    """
    if not text:
        return []
    try:
        data = loads_bounded(text, max_bytes=_MAX_TOOL_OUTPUT_BYTES)
    except ValueError:
        # Malformed, whitespace-only, or over-budget output.
        return []
    if not isinstance(data, dict):
        return []

    findings: list[SemgrepFinding] = []
    runs = data.get("runs") or []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results") or []
        findings.extend(SemgrepFinding.from_sarif_result(result) for result in results)
    return findings


def parse_json_output(text: str) -> dict[str, Any]:
    """Parse Semgrep's --json-output content for paths.scanned, errors, version.

    Returns a dict with keys: files_examined, files_failed,
    semgrep_version, errors. Empty/malformed input returns empty values
    rather than raising.

    ``errors`` carries the rendered error-level entries of semgrep's
    real ``errors`` array (InvalidRuleSchemaError, SemgrepError, fatal
    per-file failures). Warn-level entries stay out of ``errors`` —
    they land in ``files_failed`` (when path-bearing) so a large scan
    with a few unparseable files is not reported as an engine failure.

    Over-budget input (> ``_MAX_TOOL_OUTPUT_BYTES``) returns the same
    empty values, with the size logged by the bounded loader.
    """
    out: dict[str, Any] = {
        "files_examined": [],
        "files_failed": [],
        "semgrep_version": "",
        "errors": [],
    }
    if not text:
        return out
    try:
        data = loads_bounded(text, max_bytes=_MAX_TOOL_OUTPUT_BYTES)
    except ValueError:
        # Malformed, whitespace-only, or over-budget output.
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
    out["errors"] = [
        _render_error(e)
        for e in errors
        if isinstance(e, dict)
        and str(e.get("level", "error")).lower() in ("error", "fatal")
    ]

    out["semgrep_version"] = str(data.get("version", ""))
    return out


def _render_error(entry: dict[str, Any]) -> str:
    """One-line rendering of a semgrep errors[] entry.

    Semgrep's error objects vary by type: rule-schema errors carry
    ``long_msg``/``short_msg``; runtime errors carry ``message``.
    """
    msg = (
        entry.get("message")
        or entry.get("long_msg")
        or entry.get("short_msg")
        or "semgrep error"
    )
    etype = entry.get("type") or "error"
    return f"{etype}: {msg}"[:500]
