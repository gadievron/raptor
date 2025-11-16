#!/usr/bin/env python3
"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import json
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


def parse_sarif_findings(sarif_path: Path) -> List[Dict[str, Any]]:
    """
    Parse findings from a SARIF file.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        List of finding dictionaries with normalized structure
    """
    if not sarif_path.exists():
        print(f"[SARIF Parser] ERROR: File does not exist: {sarif_path}")
        return []

    try:
        data = json.loads(sarif_path.read_text() or "{}")
    except json.JSONDecodeError as e:
        print(f"[SARIF Parser] ERROR: Invalid JSON in {sarif_path}: {e}")
        return []

    findings: List[Dict[str, Any]] = []

    runs = data.get("runs", [])
    print(f"[SARIF Parser] Found {len(runs)} run(s) in SARIF file")
    
    for run_idx, run in enumerate(runs):
        results = run.get("results", [])
        print(f"[SARIF Parser] Run {run_idx + 1}: {len(results)} result(s)")
        
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

            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": result.get("ruleId"),
                    "message": result.get("message", {}).get("text"),
                    "file": artifact.get("uri"),
                    "startLine": region.get("startLine"),
                    "endLine": region.get("endLine"),
                    "snippet": snippet,
                    "level": result.get("level", "warning"),
                    # NEW: Dataflow information
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
    if not sarif_path.exists():
        return False

    # Load SARIF
    try:
        sarif_data = json.loads(sarif_path.read_text())
    except json.JSONDecodeError as e:
        print(f"[validation] Invalid JSON in SARIF file: {e}")
        return False

    # Basic validation - check required fields
    if not isinstance(sarif_data, dict):
        print("[validation] SARIF root must be an object")
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
        path = Path(sarif_path)
        if not path.exists():
            continue

        try:
            sarif_data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue

        for run in sarif_data.get("runs", []):
            # Track tool
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
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
