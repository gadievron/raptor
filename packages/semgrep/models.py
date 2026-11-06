"""Data models for Semgrep results."""

from collections.abc import Callable
from dataclasses import dataclass, field
from heapq import nsmallest
from typing import Any

from core.json.bounded import loads_bounded
from core.run.toolprobe import reported_version
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
# headroom while bounding retained samples for fabricated reasons in
# a damaged payload. Exact counts still require one counter per distinct
# normalized reason.
_SKIPPED_SAMPLE_CAP = 5
_SKIPPED_REASON_CAP = 12
# Per-string caps for the same reason: a single entry must not carry
# an unbounded target-chosen payload into the retained summary.
_SKIPPED_PATH_MAXLEN = 300
_SKIPPED_REASON_MAXLEN = 100


def _coerce_int(value: Any) -> int:
    """Positive source coordinate; retain legacy integer-string compatibility."""
    from core.sarif.parser import _coerce_line

    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            return 0
    coordinate = _coerce_line(value)
    return coordinate if coordinate is not None and coordinate > 0 else 0


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
        *, resolved_rule: dict[str, Any] | None = None,
        resolve_uri: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> "SemgrepFinding":
        """Build from a single SARIF runs[].results[] entry.

        ``rule_levels`` maps rule id → the rule's
        ``defaultConfiguration.level`` from the run's rules table.
        Semgrep's SARIF emitter never sets ``result.level`` (SARIF
        severity inheritance; verified against semgrep 1.172.0), so
        without the table every rule-declared severity — including
        error-severity rules — flattens to "warning".

        Run-aware callers supply a validated descriptor and URI resolver;
        standalone callers retain inline-location and rule-level-map support.
        """
        if not result or not isinstance(result, dict):
            return cls(file="", line=0)

        from core.sarif.parser import _as_dict, _result_rule_id, rule_default_level, sarif_uri_path

        rule_id = _result_rule_id(result, resolved_rule or {}) or ""
        msg = result.get("message")
        message = msg.get("text", "") if isinstance(msg, dict) else msg
        if not isinstance(message, str):
            message = ""

        level = result.get("level")
        if not isinstance(level, str) or not level:
            level = (rule_default_level(resolved_rule) if resolved_rule is not None
                     else (rule_levels or {}).get(rule_id)) or "warning"

        locations = result.get("locations")
        location = locations[0] if isinstance(locations, list) and locations else None
        phys = _as_dict(_as_dict(location).get("physicalLocation"))
        artifact = _as_dict(phys.get("artifactLocation"))
        uri = resolve_uri(artifact) if resolve_uri is not None else artifact.get("uri")
        file = sarif_uri_path(uri) or ""
        # Native absolute drive paths are also emitted by Windows tool builds.
        # UNC/network authorities remain excluded from local source attribution.
        if not file and isinstance(uri, str):
            import ntpath
            from core.sarif.parser import _normalize_artifact_uri
            drive, tail = ntpath.splitdrive(uri)
            if (len(drive) == 2 and drive[0].isascii() and drive[0].isalpha()
                    and drive[1] == ":" and ntpath.isabs(uri)
                    and not tail.startswith(("//", "\\\\")) and _normalize_artifact_uri(uri) is not None):
                file = uri
        region = _as_dict(phys.get("region"))
        line = _coerce_int(region.get("startLine"))
        column = _coerce_int(region.get("startColumn"))
        line_end = _coerce_int(region.get("endLine"))
        column_end = _coerce_int(region.get("endColumn"))
        if line and line_end and line_end < line:
            line_end = column_end = 0
        if line_end in (0, line) and column and column_end and column_end < column:
            column_end = 0

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
    # Bounded per-reason summary of excluded or incompletely analysed paths
    # (``paths.skipped`` — only populated at --verbose). Shape:
    # ``{"total": int, "reasons": {reason: {"count": int,
    # "sample": [path, ...]}}, "reasons_truncated": int}``; empty dict
    # when nothing was skipped. See ``_summarise_skipped``.
    skipped_summary: dict[str, Any] = field(default_factory=dict)
    skipped_rules: list[str] = field(default_factory=list)
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
            "skipped_rules": self.skipped_rules,
            "semgrep_version": self.semgrep_version,
            "returncode": self.returncode,
            "elapsed_ms": self.elapsed_ms,
            "errors": self.errors,
        }


def parse_sarif(text: str, *, errors: list[str] | None = None) -> list[SemgrepFinding]:
    """Recover findings from bounded SARIF; optionally report incomplete output.

    Legacy callers still receive an empty list on malformed input. Execution
    callers pass ``errors`` so missing output cannot masquerade as no matches.
    """
    if not text:
        if errors is not None:
            errors.append("semgrep produced empty SARIF output")
        return []
    try:
        data = loads_bounded(text, max_bytes=_MAX_TOOL_OUTPUT_BYTES)
    except ValueError:
        if errors is not None:
            errors.append("semgrep produced invalid or over-budget SARIF output")
        return []
    return parse_sarif_data(data, errors=errors)


def parse_sarif_data(data: Any, *, errors: list[str] | None = None) -> list[SemgrepFinding]:
    """Interpret an already decoded document; callers bound its input read.

    Recover valid sibling results while recording bounded aggregate diagnostics.
    Missing optional fields remain compatible with older Semgrep versions.
    """
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        if errors is not None:
            errors.append("SARIF requires an object with a runs array")
        return []

    from core.sarif.parser import ArtifactUriResolver, ResultRuleResolver

    findings: list[SemgrepFinding] = []
    malformed = 0
    failed_invocations = 0
    for run in data["runs"]:
        if not isinstance(run, dict):
            malformed += 1
            continue
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            malformed += 1
        else:
            for invocation in invocations:
                if not isinstance(invocation, dict):
                    malformed += 1
                elif invocation.get("executionSuccessful") is False:
                    failed_invocations += 1
        rule_resolver = None
        uri_resolver = None
        results = run.get("results", [])
        if not isinstance(results, list):
            malformed += 1
            continue
        for result in results:
            if not isinstance(result, dict) or not result:
                malformed += 1
                continue
            try:
                if rule_resolver is None:
                    rule_resolver = ResultRuleResolver(run)
                    uri_resolver = ArtifactUriResolver(run)
                assert uri_resolver is not None
                rule = rule_resolver.resolve(result)
                finding = SemgrepFinding.from_sarif_result(
                    result, resolved_rule=rule, resolve_uri=uri_resolver.resolve,
                )
                if not rule and (("ruleIndex" in result and result["ruleIndex"] != -1)
                                 or result.get("rule")):
                    malformed += 1
                if not (finding.rule_id or finding.message or finding.file):
                    malformed += 1
                    continue
                locations = result.get("locations")
                if "locations" in result and not isinstance(locations, list):
                    malformed += 1
                elif isinstance(locations, list) and locations:
                    first = locations[0]
                    physical = first.get("physicalLocation") if isinstance(first, dict) else None
                    if not isinstance(first, dict) or ("physicalLocation" in first and not isinstance(physical, dict)):
                        malformed += 1
                    elif isinstance(physical, dict):
                        if "artifactLocation" in physical:
                            artifact = physical["artifactLocation"]
                            if not isinstance(artifact, dict) or (
                                any(key in artifact for key in ("uri", "index", "uriBaseId")) and not finding.file
                            ):
                                malformed += 1
                        region = physical.get("region")
                        if "region" in physical and not isinstance(region, dict):
                            malformed += 1
                        elif isinstance(region, dict) and "startLine" in region and not finding.line:
                            malformed += 1
            except (TypeError, ValueError, AttributeError, IndexError, OverflowError):
                malformed += 1
                continue
            findings.append(finding)
    if errors is not None:
        if malformed:
            errors.append(f"SARIF contains {malformed} malformed entry/entries")
        if failed_invocations:
            errors.append(f"SARIF reports {failed_invocations} unsuccessful invocation(s)")
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
    magnitude of the reported coverage limitations. Non-dict entries are ignored;
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
    total = 0
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        total += 1
        reason = escape_nonprintable(
            str(entry.get("reason") or "unspecified"),
        )[:_SKIPPED_REASON_MAXLEN]
        counts[reason] = counts.get(reason, 0) + 1
    if not total:
        return {}
    ordered = nsmallest(_SKIPPED_REASON_CAP, counts.items(), key=lambda kv: (-kv[1], kv[0]))
    # Count first, then sample only the retained reasons. Avoid both an
    # all-reasons sort and path copies for buckets that cannot be reported.
    samples: dict[str, list[str]] = {reason: [] for reason, _ in ordered}
    remaining = len(samples)
    for entry in raw:
        if not remaining:
            break
        if not isinstance(entry, dict):
            continue
        reason = escape_nonprintable(
            str(entry.get("reason") or "unspecified"),
        )[:_SKIPPED_REASON_MAXLEN]
        bucket = samples.get(reason)
        if bucket is None or len(bucket) >= _SKIPPED_SAMPLE_CAP:
            continue
        path = escape_nonprintable(str(entry.get("path") or ""))
        if path:
            bucket.append(path[:_SKIPPED_PATH_MAXLEN])
            if len(bucket) == _SKIPPED_SAMPLE_CAP:
                remaining -= 1
    return {
        "total": total,
        "reasons": {
            reason: {"count": count, "sample": samples.get(reason, [])}
            for reason, count in ordered
        },
        "reasons_truncated": max(0, len(counts) - _SKIPPED_REASON_CAP),
    }


def parse_json_output(text: str) -> dict[str, Any]:
    """Parse Semgrep's --json-output content for paths.scanned, errors, version.

    Returns a dict with keys: files_examined, files_failed,
    semgrep_version, errors, skipped_summary. Empty/malformed input
    returns empty values rather than raising; malformed nonempty input also
    records a metadata error. Missing optional fields remain compatible with
    older Semgrep versions.

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
    empty values and a metadata error, with the size logged by the bounded loader.
    """
    out: dict[str, Any] = {
        "files_examined": [],
        "files_failed": [],
        "semgrep_version": "",
        "errors": [],
        "skipped_summary": {},
        "skipped_rules": [],
    }
    if not text:
        return out
    try:
        data = loads_bounded(text, max_bytes=_MAX_TOOL_OUTPUT_BYTES)
    except ValueError:
        out["errors"].append("invalid or over-budget Semgrep JSON metadata")
        return out
    if not isinstance(data, dict):
        out["errors"].append("Semgrep JSON metadata must be an object")
        return out

    paths = data.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        out["errors"].append("Semgrep paths metadata must be an object")
        paths = {}
    scanned = paths.get("scanned", [])
    if not isinstance(scanned, list):
        out["errors"].append("Semgrep scanned paths must be an array")
        scanned = []
    examined: list[str] = []
    invalid_scanned = False
    for path in scanned:
        if isinstance(path, str) and path and "\x00" not in path:
            examined.append(path)
        else:
            invalid_scanned = True
    if invalid_scanned:
        out["errors"].append("Semgrep scanned paths contain invalid entries")
    out["files_examined"] = sorted(examined)
    skipped = paths.get("skipped", [])
    if not isinstance(skipped, list):
        out["errors"].append("Semgrep skipped paths must be an array")
        skipped = []
    if any(not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
           or not entry["path"] or "\x00" in entry["path"] for entry in skipped):
        out["errors"].append("Semgrep skipped paths contain invalid entries")
    out["skipped_summary"] = _summarise_skipped(skipped)

    errors = data.get("errors", [])
    if not isinstance(errors, list):
        out["errors"].append("Semgrep errors metadata must be an array")
        errors = []
    if any(not isinstance(entry, dict) for entry in errors):
        out["errors"].append("Semgrep errors metadata contains invalid entries")
    if any(isinstance(e, dict) and (
        (e.get("path") is not None and (
            not isinstance(e["path"], str) or "\x00" in e["path"]))
        or _diagnostic_level(e) is None
    ) for e in errors):
        out["errors"].append("Semgrep errors metadata contains invalid diagnostic fields")
    out["files_failed"] = [
        {"path": e["path"], "reason": _diagnostic_message(e)}
        for e in errors
        if isinstance(e, dict) and isinstance(e.get("path"), str)
        and e["path"] and "\x00" not in e["path"]
        and not _incompatible_rule(e)
    ]
    out["skipped_rules"] = [
        _render_error(e) for e in errors
        if isinstance(e, dict) and _incompatible_rule(e)
    ]
    out["errors"].extend(
        _render_error(e)
        for e in errors
        if isinstance(e, dict)
        and _diagnostic_level(e) in ("error", "fatal", None)
    )

    version = reported_version(data.get("version"))
    if version is None:
        out["errors"].append("Semgrep version metadata is invalid or overlong")
    else:
        out["semgrep_version"] = version
    return out


def _incompatible_rule(entry: dict[str, Any]) -> bool:
    kind = entry.get("type")
    if isinstance(kind, list) and kind:
        kind = kind[0]
    return kind == "IncompatibleRule"


def _diagnostic_level(entry: dict[str, Any]) -> str | None:
    """Unknown severities cannot establish an error-free scan."""
    level = entry.get("level", "error")
    if not isinstance(level, str):
        return None
    level = level.strip().lower()
    return level if level in ("debug", "info", "warn", "warning", "error", "fatal") else None


def _diagnostic_message(entry: dict[str, Any], default: str = "error") -> str:
    """Preserve supported diagnostic text without retaining oversized reasons."""
    for key in ("message", "long_msg", "short_msg"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value[:500]
    return default


def _render_error(entry: dict[str, Any]) -> str:
    """One-line rendering of a semgrep errors[] entry.

    Semgrep's error objects vary by type: rule-schema errors carry
    ``long_msg``/``short_msg``; runtime errors carry ``message``.
    """
    msg = _diagnostic_message(entry, default="semgrep error")
    etype = entry.get("type")
    if isinstance(etype, list):
        etype = etype[0] if etype else None
    if not isinstance(etype, str) or not etype:
        etype = "error"
    # Variant payloads can contain large snippets or rule metadata. Only the
    # type tag belongs in this bounded, single-line diagnostic summary.
    etype = escape_nonprintable(etype[:100])[:100]
    msg = escape_nonprintable(msg)
    return f"{etype}: {msg}"[:500]
