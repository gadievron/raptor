#!/usr/bin/env python3
"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.config import RaptorConfig
from core.json import load_json


def _path_from_locations(
    locations: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Build a {source, sink, steps, total_steps} dict from one
    SARIF threadFlow's locations array. Returns None if there are
    fewer than 2 locations (no source-to-sink path)."""
    if len(locations) < 2:
        return None
    path: Dict[str, Any] = {
        "source": None,
        "sink": None,
        "steps": [],
        "total_steps": len(locations),
    }
    for idx, loc_wrapper in enumerate(locations):
        location = loc_wrapper.get("location", {})
        physical_loc = location.get("physicalLocation", {})
        artifact = physical_loc.get("artifactLocation", {})
        region = physical_loc.get("region", {})
        message = location.get("message", {}).get("text", "")
        step_info = {
            "file": artifact.get("uri", ""),
            "line": region.get("startLine", 0),
            "column": region.get("startColumn", 0),
            "label": message,
            "snippet": region.get("snippet", {}).get("text", ""),
        }
        if idx == 0:
            path["source"] = step_info
        elif idx == len(locations) - 1:
            path["sink"] = step_info
        else:
            path["steps"].append(step_info)
    return path


def extract_dataflow_path(code_flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Extract dataflow path information from SARIF codeFlows.

    Pre-fix only `codeFlows[0].threadFlows[0]` was returned. SARIF
    results commonly carry multiple code flows (one per source-to-sink
    path the analyser identified) and multiple thread flows (one per
    relevant thread). Picking only the first hid genuinely-different
    paths from the operator — the second sink for the same source, the
    second source feeding the same sink, etc.

    Returns:
        Dict with `source`/`sink`/`steps`/`total_steps` for the first
        usable path (back-compat for existing callers), plus an
        `alternative_paths` list of the same dict-shape for every
        OTHER (codeFlow, threadFlow) combination that produced a
        valid 2+ location path. Empty list when the first is the
        only path.
    """
    if not code_flows:
        return None

    try:
        # `.get(k, default)` returns the value (None) when the key is
        # present-but-null. SARIF emitters legitimately produce
        # `"threadFlows": null` when no flow is available — guard with
        # `or []` so iteration doesn't TypeError on None.
        all_paths: List[Dict[str, Any]] = []
        for flow in code_flows:
            for tflow in (flow.get("threadFlows") or []):
                locations = tflow.get("locations") or []
                p = _path_from_locations(locations)
                if p is not None:
                    all_paths.append(p)

        if not all_paths:
            return None

        primary = all_paths[0]
        primary["alternative_paths"] = all_paths[1:]
        return primary

    except Exception as e:
        print(f"[SARIF Parser] Warning: Failed to extract dataflow path: {e}")
        return None


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate findings based on fingerprints.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of unique findings
    """
    seen: Set[Tuple] = set()
    unique: List[Dict[str, Any]] = []

    for finding in findings:
        # Create fingerprint from location + rule
        fp = (
            finding.get("file"),
            finding.get("startLine"),
            finding.get("endLine"),
            finding.get("rule_id"),
        )

        if fp not in seen:
            seen.add(fp)
            unique.append(finding)

    return unique


def _result_key(
    result: Dict[str, Any],
) -> Tuple[str, str, int, int, int, str]:
    """Dedup key for a SARIF result.

    Pre-fix the key was just (ruleId, uri, startLine). That collapsed
    distinct findings on the same line:

      * Two SQL-injection findings at the same line but different
        column offsets — the second arrival overwrote the first
        and the operator only saw one.
      * Two findings at different `endLine`s sharing a startLine
        (multi-line span vs single-line span on the same start) —
        same collapse.
      * Two scanner runs returning the same shape under different
        SARIF `partialFingerprints` — these are the tool's own
        identity for the finding and should disambiguate even when
        line/column match.

    Extended key: (ruleId, uri, startLine, endLine, startColumn,
    fingerprint). Missing fields default to 0 / "" so keys remain
    hashable and the (legacy) "no column / no fingerprint" case
    keeps deduping like before.
    """
    rule_id = result.get("ruleId", "")
    locs = result.get("locations") or [{}]
    phys = locs[0].get("physicalLocation", {}) if locs else {}
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {}) or {}
    line = region.get("startLine", 0)
    end_line = region.get("endLine", line)  # multi-line spans differ
    start_col = region.get("startColumn", 0)
    # `partialFingerprints` is a tool-supplied dict; serialise the
    # primary `primaryLocationLineHash` if present, else collapse the
    # whole dict to a stable string. SARIF spec recommends
    # `primaryLocationLineHash` as the dedup-quality fingerprint.
    fp = result.get("partialFingerprints") or {}
    fingerprint = fp.get("primaryLocationLineHash") or ""
    if not fingerprint and fp:
        # Fall back to a stable serialisation of the whole dict —
        # different fingerprint sets mean different findings.
        fingerprint = repr(sorted(fp.items()))
    return (rule_id, uri, line, end_line, start_col, fingerprint)


def merge_sarif(sarif_paths: List[str]) -> Dict[str, Any]:
    """
    Merge multiple SARIF files into a single SARIF dict.

    Groups runs by tool name, deduplicates results within each tool by
    (ruleId, uri, startLine). Latest occurrence wins on collision.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Merged SARIF dict with deduplicated results per tool
    """
    # Group runs by tool name so same-tool runs get their results merged
    tool_runs: Dict[str, Dict[str, Any]] = {}  # tool_name -> merged run

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue
        for run in (sarif_data.get("runs") or []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            if tool_name not in tool_runs:
                tool_runs[tool_name] = {
                    "tool": run.get("tool", {}),
                    # Track rules by id so we union the rule list across
                    # same-tool runs without duplicates. Pre-fix the
                    # `tool` block was set once (first run wins) and any
                    # rules emitted in subsequent runs' tool.driver.rules
                    # were silently dropped — downstream consumers
                    # looking up `result.ruleId` against the merged
                    # rule index missed those rules entirely (CWE
                    # lookup, severity inheritance, etc. all returned
                    # None for the dropped rules).
                    "rules_by_id": {},
                    "results": {},  # keyed by _result_key for dedup
                }
            # Union this run's rules into the per-tool index. Same-id
            # rules from later runs win on collision (matches the
            # latest-occurrence-wins semantic the result dedup uses).
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
                if isinstance(rule, dict):
                    rule_id = rule.get("id")
                    if rule_id:
                        tool_runs[tool_name]["rules_by_id"][rule_id] = rule
            for result in run.get("results", []):
                key = _result_key(result)
                tool_runs[tool_name]["results"][key] = result

    # Build final SARIF with one run per tool
    merged_runs = []
    for tool_name, run_data in tool_runs.items():
        # Re-inject the unioned rule list into tool.driver.rules.
        tool_block = dict(run_data["tool"]) if run_data["tool"] else {}
        driver = dict(tool_block.get("driver") or {})
        if run_data["rules_by_id"]:
            driver["rules"] = list(run_data["rules_by_id"].values())
        tool_block["driver"] = driver
        merged_runs.append({
            "tool": tool_block,
            "results": list(run_data["results"].values()),
        })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": merged_runs,
    }


def _extract_cwe_from_rule(rule: Dict[str, Any]) -> Optional[str]:
    """Extract CWE ID from a SARIF rule's properties/tags.

    SARIF rules carry CWE metadata in various places:
    - properties.tags: ["external/cwe/cwe-89", "security"]
    - properties.cwe: "CWE-89"
    - shortDescription or fullDescription text
    """
    # Check properties.cwe directly
    props = rule.get("properties", {})
    if props.get("cwe"):
        cwe = props["cwe"]
        if isinstance(cwe, str) and re.match(r"CWE-\d+", cwe):
            return cwe

    # Check tags for CWE patterns
    for tag in props.get("tags", []):
        if isinstance(tag, str) and "cwe" in tag.lower():
            m = re.search(r"cwe-(\d+)", tag, re.IGNORECASE)
            if m:
                return f"CWE-{m.group(1)}"

    return None


def load_sarif(sarif_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load a SARIF file with safety guards.

    Handles existence check, size guard (100 MiB), and JSON decode errors.
    All SARIF file I/O should go through this function.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        Parsed SARIF dict, or None on error
    """
    if not sarif_path.exists():
        print(f"[SARIF] ERROR: File does not exist: {sarif_path}")
        return None

    max_size = 100 * 1024 * 1024  # 100 MiB

    try:
        # Read then check size — avoids TOCTOU between stat() and read()
        content = sarif_path.read_text()
        if len(content) > max_size:
            print(f"[SARIF] ERROR: File too large ({len(content) / 1024 / 1024:.0f} MiB): {sarif_path}")
            return None
    except OSError as e:
        print(f"[SARIF] WARNING: Could not read {sarif_path}: {e}")
        return None

    try:
        data = json.loads(content or "{}")
    except json.JSONDecodeError as e:
        print(f"[SARIF] ERROR: Invalid JSON in {sarif_path}: {e}")
        return None
    except OSError as e:
        print(f"[SARIF] ERROR: Could not read {sarif_path}: {e}")
        return None

    if not isinstance(data, dict):
        print(f"[SARIF] ERROR: Root must be an object in {sarif_path}")
        return None

    return data


def get_tool_name(run: Dict[str, Any]) -> str:
    """Extract tool name from a SARIF run."""
    return run.get("tool", {}).get("driver", {}).get("name") or "unknown"


def get_rules(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract rules from a SARIF run, keyed by rule ID."""
    return {
        r.get("id", ""): r
        for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        if r.get("id")
    }


def parse_sarif_findings(sarif_path: Path) -> List[Dict[str, Any]]:
    """
    Parse findings from a SARIF file.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        List of finding dictionaries with normalized structure
    """
    data = load_sarif(sarif_path)
    if not data:
        return []

    findings: List[Dict[str, Any]] = []

    runs = data.get("runs") or []
    print(f"[SARIF Parser] Found {len(runs)} run(s) in SARIF file")
    
    for run_idx, run in enumerate(runs):
        results = run.get("results", [])
        print(f"[SARIF Parser] Run {run_idx + 1}: {len(results)} result(s)")

        tool_name = get_tool_name(run)

        # Build rule_id → CWE lookup
        rules_by_id = {}
        for rid, rule in get_rules(run).items():
            cwe_id = _extract_cwe_from_rule(rule)
            if rid:
                rules_by_id[rid] = {"cwe_id": cwe_id}

        for result in results:
            # finding_id resolution:
            #   1. SARIF tool-supplied fingerprint (best — survives
            #      reformatting / line-shifts that the tool tracked).
            #   2. ruleId (cheap, but collides across multiple findings
            #      of the same rule type — only useful when the run has
            #      one finding per rule).
            #   3. Deterministic hash of the canonicalised result.
            #
            # Pre-fix the fallback was `str(hash(json.dumps(result)))`.
            # Two problems:
            #   * Python's `hash()` is randomised per-process by default
            #     (PYTHONHASHSEED) for security against hash-flooding,
            #     so the SAME finding produced a DIFFERENT finding_id
            #     on every invocation. Downstream consumers tracking
            #     findings across runs (deduplication, regression
            #     detection, fix verification) couldn't correlate.
            #   * `json.dumps` without `sort_keys=True` is also non-
            #     deterministic across dict insertion orders.
            # `hashlib.sha256(json.dumps(..., sort_keys=True))` fixes
            # both: identical input always yields the same hex digest.
            try:
                canonical = json.dumps(result, sort_keys=True, default=str)
            except (TypeError, ValueError):
                canonical = repr(sorted(result.items()))
            sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            finding_id = (
                (result.get("fingerprints") or {}).get("matchBasedId/v1")
                or result.get("ruleId")
                or sha
            )

            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            snippet = region.get("snippet", {}).get("text", "")

            # Extract dataflow path if present
            code_flows = result.get("codeFlows") or []
            dataflow_path = extract_dataflow_path(code_flows) if code_flows else None

            rule_id = result.get("ruleId")
            rule_meta = rules_by_id.get(rule_id, {})

            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "message": result.get("message", {}).get("text"),
                    "file": artifact.get("uri"),
                    "startLine": region.get("startLine"),
                    "endLine": region.get("endLine"),
                    "snippet": snippet,
                    "level": result.get("level", "warning"),
                    "cwe_id": rule_meta.get("cwe_id"),
                    "tool": tool_name,
                    # Dataflow information
                    "has_dataflow": dataflow_path is not None,
                    "dataflow_path": dataflow_path,
                }
            )

    print(f"[SARIF Parser] Parsed {len(findings)} total findings")
    return findings


def validate_sarif(sarif_path: Path, schema_path: Optional[Path] = None) -> bool:
    """
    Validate SARIF file against schema.

    Args:
        sarif_path: Path to SARIF file
        schema_path: Optional path to SARIF schema (auto-detected if None)

    Returns:
        True if valid, False otherwise
    """
    sarif_data = load_sarif(sarif_path)
    if not sarif_data:
        return False

    if sarif_data.get("version") not in ["2.1.0", "2.0.0"]:
        print(f"[validation] Unsupported SARIF version: {sarif_data.get('version')}")
        return False

    if "runs" not in sarif_data:
        print("[validation] SARIF missing required 'runs' field")
        return False

    # Optional: Full schema validation if jsonschema is available
    try:
        import jsonschema

        if schema_path is None:
            schema_path = RaptorConfig.SCHEMAS_DIR / "sarif-2.1.0.json"

        if schema_path.exists():
            schema = load_json(schema_path)
            if schema is not None:
                jsonschema.validate(instance=sarif_data, schema=schema)
        else:
            # Skip full validation if schema not available
            pass
    except ImportError:
        # jsonschema not installed - skip full validation
        pass
    except jsonschema.ValidationError as e:
        print(f"[validation] SARIF schema validation failed: {e.message}")
        return False

    return True


def generate_scan_metrics(sarif_paths: List[str]) -> Dict[str, Any]:
    """
    Generate metrics from scan results.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Dictionary containing scan metrics
    """
    metrics: Dict[str, Any] = {
        "total_files_scanned": 0,
        "total_findings": 0,
        "findings_by_severity": {
            "error": 0,
            "warning": 0,
            "note": 0,
            "none": 0,
        },
        "findings_by_rule": {},
        "tools_used": [],
    }

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue

        for run in (sarif_data.get("runs") or []):
            tool_name = get_tool_name(run)
            if tool_name not in metrics["tools_used"]:
                metrics["tools_used"].append(tool_name)

            # Count artifacts (files)
            artifacts = run.get("artifacts", [])
            metrics["total_files_scanned"] += len(artifacts)

            # Count findings
            results = run.get("results", [])
            metrics["total_findings"] += len(results)

            for result in results:
                # Count by severity
                level = result.get("level", "warning")
                if level in metrics["findings_by_severity"]:
                    metrics["findings_by_severity"][level] += 1

                # Count by rule
                rule_id = result.get("ruleId", "unknown")
                metrics["findings_by_rule"][rule_id] = (
                    metrics["findings_by_rule"].get(rule_id, 0) + 1
                )

    return metrics


def sanitize_finding_for_display(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize a finding for safe display, truncating long fields.

    Args:
        finding: Finding dictionary

    Returns:
        Sanitized finding dictionary
    """
    sanitized = finding.copy()

    # Truncate long snippets
    if "snippet" in sanitized and len(sanitized["snippet"]) > 500:
        sanitized["snippet"] = sanitized["snippet"][:497] + "..."

    # Truncate long messages
    if "message" in sanitized and len(sanitized["message"]) > 200:
        sanitized["message"] = sanitized["message"][:197] + "..."

    return sanitized
