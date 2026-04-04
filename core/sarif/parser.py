#!/usr/bin/env python3
"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.config import RaptorConfig


def extract_dataflow_path(code_flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Extract dataflow path information from SARIF codeFlows.

    Args:
        code_flows: List of codeFlow objects from SARIF result

    Returns:
        Dictionary with source, sink, and intermediate steps, or None if no dataflow
    """
    if not code_flows:
        return None

    try:
        # Get the first code flow (typically the most relevant)
        flow = code_flows[0]
        thread_flows = flow.get("threadFlows", [])
        if not thread_flows:
            return None

        # Get all locations in the dataflow path
        locations = thread_flows[0].get("locations", [])
        if len(locations) < 2:  # Need at least source and sink
            return None

        dataflow_path = {
            "source": None,
            "sink": None,
            "steps": [],
            "total_steps": len(locations)
        }

        # Extract each location in the path
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
                "snippet": region.get("snippet", {}).get("text", "")
            }

            # First location is the source
            if idx == 0:
                dataflow_path["source"] = step_info
            # Last location is the sink
            elif idx == len(locations) - 1:
                dataflow_path["sink"] = step_info
            # Everything else is an intermediate step
            else:
                dataflow_path["steps"].append(step_info)

        return dataflow_path

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


def merge_sarif(sarif_paths: List[str]) -> Dict[str, Any]:
    """
    Merge multiple SARIF files into a single SARIF dict with combined runs.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Merged SARIF dict with all runs combined
    """
    merged: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [],
    }
    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if sarif_data:
            merged["runs"].extend(sarif_data.get("runs", []))
    return merged


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
        file_size = sarif_path.stat().st_size
        if file_size > max_size:
            print(f"[SARIF] ERROR: File too large ({file_size / 1024 / 1024:.0f} MiB): {sarif_path}")
            return None
    except OSError as e:
        print(f"[SARIF] WARNING: Could not stat {sarif_path}: {e}")

    try:
        data = json.loads(sarif_path.read_text() or "{}")
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

    runs = data.get("runs", [])
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
            finding_id = (
                result.get("fingerprints", {}).get("matchBasedId/v1")
                or result.get("ruleId")
                or str(hash(json.dumps(result)))
            )

            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            snippet = region.get("snippet", {}).get("text", "")

            # Extract dataflow path if present
            code_flows = result.get("codeFlows", [])
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
            schema = json.loads(schema_path.read_text())
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

        for run in sarif_data.get("runs", []):
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
