"""Coverage records — what each tool examined during a run.

Per-tool records written as coverage-<tool>.json in the run output directory.
Built from the reads manifest (populated by the PostToolUse hook),
Semgrep JSON output, CodeQL SARIF, and findings.json.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json, save_json

COVERAGE_RECORD_FILE = "coverage-record.json"  # legacy single-file name
READS_MANIFEST = ".reads-manifest"


def build_from_manifest(run_dir: Path, tool: str,
                        rules_applied: List[str] = None,
                        extra_files: List[str] = None) -> Optional[Dict[str, Any]]:
    """Build a coverage record from the reads manifest.

    The manifest is populated by the PostToolUse hook on Read.
    Deduplicates and normalises paths relative to the target.

    Args:
        run_dir: Run output directory containing .reads-manifest.
        tool: Tool identifier (e.g., "llm:validate", "understand").
        rules_applied: Optional list of rules/stages that ran.
        extra_files: Additional files to include (from other sources).

    Returns:
        Coverage record dict, or None if no manifest exists.
    """
    run_dir = Path(run_dir)
    manifest = run_dir / READS_MANIFEST

    files = set()

    # Read manifest. Use `rstrip("\r\n")` not `strip()` — the latter
    # also trims leading/trailing spaces, but POSIX permits filenames
    # that legitimately START or END with a space. `track_read`
    # already rejects NUL/CR/LF in the path itself (batch 207), so
    # a manifest line carrying a filename with a trailing space
    # made it in legitimately and was then silently mangled by
    # `strip()` here. Only newline-style line terminators need
    # removing.
    if manifest.exists():
        try:
            for line in manifest.read_text().splitlines():
                line = line.rstrip("\r\n")
                if line:
                    files.add(line)
        except OSError:
            pass

    # Add extra files from tool-specific sources
    if extra_files:
        files.update(extra_files)

    if not files:
        return None

    record = {
        "tool": tool,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if rules_applied:
        record["rules_applied"] = rules_applied

    return record


def build_from_semgrep(run_dir: Path, semgrep_json_path: Path,
                       rules_applied: List[str] = None) -> Optional[Dict[str, Any]]:
    """Build a coverage record from Semgrep JSON output.

    Reads paths.scanned from Semgrep's JSON output for authoritative
    file list, and errors for files_failed.
    """
    data = load_json(semgrep_json_path)
    if not data or not isinstance(data, dict):
        return None

    paths = data.get("paths", {})
    scanned = paths.get("scanned", [])
    if not scanned:
        return None

    errors = data.get("errors", [])
    version = data.get("version", "")

    record = {
        "tool": "semgrep",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(scanned),
    }
    if version:
        record["version"] = version
    if rules_applied:
        record["rules_applied"] = rules_applied
    if errors:
        record["files_failed"] = [
            {"path": e.get("path", ""), "reason": e.get("message", "error")}
            for e in errors if e.get("path")
        ]

    return record


def build_from_codeql(sarif_path: Path) -> Optional[Dict[str, Any]]:
    """Build a coverage record from CodeQL SARIF output.

    Extracts: files from artifacts, packs from tool.extensions,
    rules from tool.driver.rules, failures from invocations.
    """
    data = load_json(sarif_path)
    if not data or not isinstance(data, dict):
        return None

    files = []
    packs = []
    rules = []
    failures = []
    version = ""

    for run in data.get("runs", []):
        # Files extracted
        for artifact in run.get("artifacts", []):
            uri = artifact.get("location", {}).get("uri", "")
            if uri:
                files.append(uri)

        # Tool info
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        version = version or driver.get("version", "")
        rules.extend(r.get("id", "") for r in driver.get("rules", []))

        # Packs
        for ext in tool.get("extensions", []):
            name = ext.get("name", "")
            ver = ext.get("version", "")
            packs.append(f"{name}@{ver}" if ver else name)

        # Extraction failures
        for inv in run.get("invocations", []):
            for notif in inv.get("toolExecutionNotifications", []):
                if notif.get("level") in ("error", "warning"):
                    loc = notif.get("locations", [{}])[0] if notif.get("locations") else {}
                    path = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    failures.append({
                        "path": path,
                        "reason": notif.get("message", {}).get("text", "unknown"),
                    })

    if not files:
        return None

    record = {
        "tool": "codeql",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(set(files)),
    }
    if version:
        record["version"] = version
    if packs:
        record["packs"] = packs
    if rules:
        record["rules_applied"] = sorted(set(rules))
    if failures:
        record["files_failed"] = [f for f in failures if f["path"]]

    return record


def build_from_findings(findings_path: Path, reads_manifest_path: Path = None,
                        tool: str = "llm") -> Optional[Dict[str, Any]]:
    """Build a coverage record from findings.json + optional reads manifest.

    Combines two signals:
    - files_examined: files the LLM opened (from reads manifest)
    - functions_analysed: functions the LLM produced findings/rulings for
    """
    findings_data = load_json(findings_path)
    if not findings_data or not isinstance(findings_data, dict):
        return None

    findings = findings_data.get("findings", [])

    # Functions analysed (from findings with rulings)
    functions = []
    finding_files = set()
    for f in findings:
        file_path = f.get("file", "")
        func = f.get("function", "")
        if file_path and func:
            functions.append({"file": file_path, "function": func})
            finding_files.add(file_path)

    # Files examined (from reads manifest)
    read_files = set()
    if reads_manifest_path and reads_manifest_path.exists():
        try:
            # Same rstrip-only rationale as the helper above.
            for line in reads_manifest_path.read_text().splitlines():
                line = line.rstrip("\r\n")
                if line:
                    read_files.add(line)
        except OSError:
            pass

    all_files = sorted(read_files | finding_files)

    if not all_files and not functions:
        return None

    record = {
        "tool": tool,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if all_files:
        record["files_examined"] = all_files
    if functions:
        record["functions_analysed"] = functions

    return record


def write_record(run_dir: Path, record: Dict[str, Any],
                 tool_name: str = None) -> Path:
    """Write a coverage record to the run directory.

    Args:
        run_dir: Run output directory.
        record: Coverage record dict.
        tool_name: If provided, writes coverage-<tool_name>.json.
                   Otherwise writes the legacy coverage-record.json.
    """
    if tool_name:
        filename = f"coverage-{tool_name}.json"
    else:
        filename = COVERAGE_RECORD_FILE
    path = Path(run_dir) / filename
    save_json(path, record)
    return path


def load_records(run_dir: Path) -> List[Dict[str, Any]]:
    """Load all coverage records from a run directory.

    The per-tool glob `coverage-*.json` overlaps the legacy
    single-file name `coverage-record.json` (`record` matches
    `*`). Pre-fix the legacy file was picked up by the per-tool
    loop AS WELL as the legacy fallback below — and if the
    legacy file happened to have a `"tool"` key (e.g. an old
    single-file write that pre-dated the per-tool split but
    still recorded a tool name), the per-tool loop accepted it,
    `records` became non-empty, and the legacy fallback never
    fired. The same record then appeared twice in the loaded
    list, double-counting in downstream coverage stats.
    Explicitly exclude `COVERAGE_RECORD_FILE` from the glob so
    the legacy file only flows through its dedicated fallback
    path.
    """
    run_dir = Path(run_dir)
    records = []
    # Per-tool files (must be dicts with a "tool" key)
    for p in sorted(run_dir.glob("coverage-*.json")):
        if p.name == COVERAGE_RECORD_FILE:
            continue
        data = load_json(p)
        if isinstance(data, dict) and "tool" in data:
            records.append(data)
    # Legacy single file (if no per-tool files found)
    if not records:
        legacy = load_json(run_dir / COVERAGE_RECORD_FILE)
        if legacy:
            records.append(legacy)
    return records


def load_record(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Load a coverage record from a run directory. Legacy single-file API."""
    return load_json(Path(run_dir) / COVERAGE_RECORD_FILE)


def cleanup_manifest(run_dir: Path) -> None:
    """Remove the reads manifest after converting to a coverage record."""
    manifest = Path(run_dir) / READS_MANIFEST
    if manifest.exists():
        manifest.unlink(missing_ok=True)
