"""Data models for Semgrep results."""

from dataclasses import dataclass, field
from typing import Any

from core.json.bounded import loads_bounded
from core.security.log_sanitisation import escape_nonprintable

# Byte ceiling for semgrep tool output (SARIF on stdout and the
# --json-output file). Both are produced over a scanned — possibly
# hostile — repository, which can inflate them arbitrarily through
# file paths, match snippets, and error messages. Large legitimate
# scans reach tens of MB; 128 MiB matches the cap used for SARIF
# artifacts elsewhere while refusing DoS-scale payloads.
_MAX_TOOL_OUTPUT_BYTES = 128 * 1024 * 1024

# Bounds for the skipped-path summary built from ``paths.skipped``.
# On a large monorepo that list can carry hundreds of thousands of
# entries (node_modules, build trees), and both the paths and the
# entry count are driven by the scanned — possibly hostile — tree,
# so the summary must stay bounded regardless of input. The caps cut
# both ways:
#   * higher = more of the excluded scope visible on the result, at
#     the cost of result-size / serialised-artifact bloat that the
#     target's file count and path lengths control;
#   * lower = cheaper results, but the operator loses the ability to
#     see WHICH subtree a skip reason is eating.
# 5 sample paths per reason is enough to recognise the affected
# subtree without retaining the whole list; 12 distinct reasons
# covers semgrep's skip-reason enum (~10 values on 1.172.0) with
# headroom while refusing an unbounded set of fabricated reason
# strings from a damaged payload.
_SKIPPED_SAMPLE_CAP = 5
_SKIPPED_REASON_CAP = 12
# Per-string caps for the same reason: a single entry must not carry
# an unbounded target-chosen payload into the retained summary.
_SKIPPED_PATH_MAXLEN = 300
_SKIPPED_REASON_MAXLEN = 100


def _coerce_int(value: Any) -> int:
    """Best-effort int coercion for SARIF region fields; 0 on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


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
    def from_sarif_result(
        cls,
        result: dict,
        rule_levels: dict[str, str] | None = None,
    ) -> "SemgrepFinding":
        """Build from a single SARIF runs[].results[] entry.

        ``rule_levels`` maps rule id → the rule's
        ``defaultConfiguration.level`` from the run's rules table.
        Semgrep's SARIF emitter never sets ``result.level`` (SARIF
        severity inheritance; verified against semgrep 1.172.0), so
        without the table every rule-declared severity — including
        error-severity rules — flattens to "warning".
        """
        if not result or not isinstance(result, dict):
            return cls(file="", line=0)

        rule_id = result.get("ruleId", "")
        message = ""
        msg = result.get("message")
        if isinstance(msg, dict):
            message = msg.get("text", "")
        elif isinstance(msg, str):
            message = msg

        level = result.get("level")
        if not isinstance(level, str) or not level:
            level = (rule_levels or {}).get(rule_id) or "warning"

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
            # Per-field coercion: a single try around all four meant
            # one bad value (e.g. startColumn: null) silently discarded
            # every later field even when it was parseable.
            line = _coerce_int(region.get("startLine", 0))
            column = _coerce_int(region.get("startColumn", 0))
            line_end = _coerce_int(region.get("endLine", 0))
            column_end = _coerce_int(region.get("endColumn", 0))

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
    # Bounded per-reason summary of the paths semgrep did NOT scan
    # (``paths.skipped`` — only populated at --verbose). Shape:
    # ``{"total": int, "reasons": {reason: {"count": int,
    # "sample": [path, ...]}}, "reasons_truncated": int}``; empty dict
    # when nothing was skipped. See ``_summarise_skipped``.
    skipped_summary: dict[str, Any] = field(default_factory=dict)
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
            "skipped_summary": self.skipped_summary,
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

    from core.sarif.parser import get_rules, rule_default_level

    findings: list[SemgrepFinding] = []
    runs = data.get("runs") or []
    for run in runs:
        if not isinstance(run, dict):
            continue
        # Rule-declared severities from the run's rules table — the
        # only place semgrep's SARIF carries them (results omit level).
        rule_levels = {
            rid: level
            for rid, rule in get_rules(run).items()
            if (level := rule_default_level(rule))
        }
        results = run.get("results") or []
        # Skip non-dict / empty entries outright: converting them
        # produced phantom SemgrepFinding(file='', line=0) records that
        # inflated finding_count downstream.
        findings.extend(
            SemgrepFinding.from_sarif_result(result, rule_levels)
            for result in results
            if result and isinstance(result, dict)
        )
    return findings


def _summarise_skipped(raw: Any) -> dict[str, Any]:
    """Bounded per-reason summary of semgrep's ``paths.skipped`` list.

    Returns ``{}`` when nothing usable was skipped, else::

        {"total": <all skipped entries>,
         "reasons": {reason: {"count": n, "sample": [path, ...]}},
         "reasons_truncated": <distinct reasons dropped by the cap>}

    Reasons are ordered by descending count (ties by name) and capped
    at ``_SKIPPED_REASON_CAP``; each keeps the first
    ``_SKIPPED_SAMPLE_CAP`` paths in semgrep's own output order.
    ``total`` always counts EVERY entry, so truncation never hides the
    magnitude of what went unscanned. Non-dict entries are ignored;
    a missing reason buckets as ``"unspecified"``.

    Path and reason strings are rendered inert at ingestion
    (``escape_nonprintable``) BEFORE the length caps — paths are
    target-chosen file names, and escaping after truncation would let
    hostile bytes ride inside the kept prefix while the cap hides the
    evidence.
    """
    if not isinstance(raw, list):
        return {}
    counts: dict[str, int] = {}
    samples: dict[str, list[str]] = {}
    total = 0
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        total += 1
        reason = escape_nonprintable(
            str(entry.get("reason") or "unspecified"),
        )[:_SKIPPED_REASON_MAXLEN]
        counts[reason] = counts.get(reason, 0) + 1
        bucket = samples.setdefault(reason, [])
        path = escape_nonprintable(str(entry.get("path") or ""))
        if path and len(bucket) < _SKIPPED_SAMPLE_CAP:
            bucket.append(path[:_SKIPPED_PATH_MAXLEN])
    if not total:
        return {}
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "total": total,
        "reasons": {
            reason: {"count": count, "sample": samples.get(reason, [])}
            for reason, count in ordered[:_SKIPPED_REASON_CAP]
        },
        "reasons_truncated": max(0, len(ordered) - _SKIPPED_REASON_CAP),
    }


def parse_json_output(text: str) -> dict[str, Any]:
    """Parse Semgrep's --json-output content for paths.scanned, errors, version.

    Returns a dict with keys: files_examined, files_failed,
    semgrep_version, errors, skipped_summary. Empty/malformed input
    returns empty values rather than raising.

    ``skipped_summary`` is the bounded per-reason digest of
    ``paths.skipped`` (see :func:`_summarise_skipped`) — the record of
    what the scan did NOT examine and why. Semgrep only populates the
    underlying list at --verbose; under quieter verbosity levels the
    summary is simply empty.

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
        "skipped_summary": {},
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
    out["skipped_summary"] = _summarise_skipped(paths.get("skipped"))

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
