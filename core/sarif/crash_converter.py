#!/usr/bin/env python3
"""
SARIF Converter for Binary Crash Analysis

Converts CrashContext objects from binary fuzzing/analysis to SARIF 2.1.0 format.
This enables unified reporting across static analysis (Semgrep/CodeQL) and
dynamic analysis (fuzzing/crash analysis).

SARIF 2.1.0 supports binary analysis via:
- physicalLocation.address (binary addresses)
- threadFlowLocation (execution traces/stack traces)
- region.byteOffset (binary byte ranges)

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


def crash_context_to_sarif(
    crash_contexts: List[Any],  # List[CrashContext]
    tool_name: str = "RAPTOR-Fuzzer",
    tool_version: str = "3.0.0",
    binary_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Convert CrashContext objects to SARIF 2.1.0 format.

    Args:
        crash_contexts: List of CrashContext objects from crash analysis
        tool_name: Name of the analysis tool (default: "RAPTOR-Fuzzer")
        tool_version: Version of the tool
        binary_path: Path to analyzed binary (for artifact location)

    Returns:
        SARIF 2.1.0 document as dictionary

    Example:
        from packages.binary_analysis.crash_analyser import CrashAnalyser
        from core.sarif.crash_converter import crash_context_to_sarif

        analyser = CrashAnalyser("/path/to/binary")
        crashes = [analyser.analyse_crash(crash_id, input_file, signal)]

        sarif_doc = crash_context_to_sarif(crashes, binary_path=Path("/path/to/binary"))

        with open("crashes.sarif", "w") as f:
            json.dump(sarif_doc, f, indent=2)
    """

    # SARIF 2.1.0 document structure
    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/gadievron/raptor",
                        "rules": _generate_crash_rules()
                    }
                },
                "artifacts": [],
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                    }
                ]
            }
        ]
    }

    run = sarif_doc["runs"][0]

    # Add binary artifact if provided
    if binary_path:
        run["artifacts"].append({
            "location": {
                "uri": str(binary_path)
            },
            "roles": ["analysisTarget"],
            "mimeType": "application/x-executable"
        })

    # Convert each crash to SARIF result
    for crash in crash_contexts:
        result = _crash_to_sarif_result(crash, binary_path)
        if result:
            run["results"].append(result)

    return sarif_doc


def _generate_crash_rules() -> List[Dict[str, Any]]:
    """
    Generate SARIF rule definitions for crash types.

    These correspond to crash_type values in CrashContext:
    - heap_overflow, stack_overflow, null_deref, use_after_free, etc.
    """
    rules = [
        {
            "id": "crash/segfault",
            "name": "Segmentation Fault",
            "shortDescription": {"text": "Segmentation fault detected"},
            "fullDescription": {"text": "A segmentation fault (SIGSEGV) occurred, indicating memory access violation."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "memory-safety", "crash"],
                "precision": "high"
            }
        },
        {
            "id": "crash/stack-overflow",
            "name": "Stack Overflow",
            "shortDescription": {"text": "Stack overflow detected"},
            "fullDescription": {"text": "A stack overflow was detected, potentially exploitable for code execution."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "memory-safety", "crash", "exploitable"],
                "precision": "high"
            }
        },
        {
            "id": "crash/heap-overflow",
            "name": "Heap Overflow",
            "shortDescription": {"text": "Heap overflow detected"},
            "fullDescription": {"text": "A heap overflow was detected, potentially exploitable for arbitrary code execution."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "memory-safety", "crash", "exploitable"],
                "precision": "high"
            }
        },
        {
            "id": "crash/null-deref",
            "name": "Null Pointer Dereference",
            "shortDescription": {"text": "Null pointer dereference"},
            "fullDescription": {"text": "A null pointer dereference was detected, causing a crash."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": ["security", "memory-safety", "crash"],
                "precision": "high"
            }
        },
        {
            "id": "crash/use-after-free",
            "name": "Use After Free",
            "shortDescription": {"text": "Use-after-free detected"},
            "fullDescription": {"text": "A use-after-free condition was detected, highly exploitable for arbitrary code execution."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "memory-safety", "crash", "exploitable"],
                "precision": "high"
            }
        },
        {
            "id": "crash/double-free",
            "name": "Double Free",
            "shortDescription": {"text": "Double free detected"},
            "fullDescription": {"text": "A double free condition was detected, potentially exploitable."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "memory-safety", "crash", "exploitable"],
                "precision": "high"
            }
        },
        {
            "id": "crash/abort",
            "name": "Abnormal Termination",
            "shortDescription": {"text": "Abnormal program termination"},
            "fullDescription": {"text": "The program terminated abnormally (SIGABRT), possibly due to assertion failure or explicit abort."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": ["reliability", "crash"],
                "precision": "medium"
            }
        },
        {
            "id": "crash/unknown",
            "name": "Unknown Crash Type",
            "shortDescription": {"text": "Crash with unknown type"},
            "fullDescription": {"text": "A crash occurred but the specific type could not be determined."},
            "defaultConfiguration": {"level": "note"},
            "properties": {
                "tags": ["crash"],
                "precision": "medium"
            }
        }
    ]

    return rules


def _crash_to_sarif_result(crash: Any, binary_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """
    Convert a single CrashContext to SARIF result.

    Args:
        crash: CrashContext object
        binary_path: Path to binary (for artifact reference)

    Returns:
        SARIF result dictionary or None if conversion fails
    """
    try:
        # Determine rule ID from crash type
        crash_type = getattr(crash, "crash_type", "unknown")
        rule_id = f"crash/{crash_type}" if crash_type != "unknown" else "crash/segfault"

        # Determine severity level from exploitability
        exploitability = getattr(crash, "exploitability", "unknown")
        level = _exploitability_to_level(exploitability)

        # Build result
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": _generate_crash_message(crash)
            },
            "locations": [
                {
                    "physicalLocation": _build_physical_location(crash, binary_path)
                }
            ],
            "properties": {
                "crash_id": getattr(crash, "crash_id", "unknown"),
                "signal": getattr(crash, "signal", "unknown"),
                "exploitability": exploitability,
                "crash_type": crash_type,
                "cvss_estimate": getattr(crash, "cvss_estimate", 0.0),
                "function_name": getattr(crash, "function_name", "unknown"),
                "input_file": str(getattr(crash, "input_file", "")),
            }
        }

        # Add stack trace as code flow (execution trace)
        stack_trace = getattr(crash, "stack_trace", "")
        if stack_trace:
            result["codeFlows"] = [_build_code_flow_from_stack(stack_trace, binary_path)]

        # Add disassembly as region snippet
        disassembly = getattr(crash, "disassembly", "")
        if disassembly:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": disassembly
            }

        # Add registers as related locations
        registers = getattr(crash, "registers", {})
        if registers:
            result["relatedLocations"] = _build_register_locations(registers)

        # Add analysis results if available
        analysis = getattr(crash, "analysis", {})
        if analysis:
            result["properties"]["analysis"] = analysis

        return result

    except Exception as e:
        print(f"[SARIF Converter] Warning: Failed to convert crash {getattr(crash, 'crash_id', 'unknown')}: {e}")
        return None


def _build_physical_location(crash: Any, binary_path: Optional[Path]) -> Dict[str, Any]:
    """
    Build SARIF physicalLocation for crash address.

    Uses SARIF's address-based location for binaries.
    """
    crash_address = getattr(crash, "crash_address", "")

    location = {
        "artifactLocation": {
            "uri": str(binary_path) if binary_path else str(getattr(crash, "binary_path", "unknown"))
        }
    }

    # Add address if available
    if crash_address and crash_address not in ("unknown", ""):
        # Convert hex string to integer for SARIF
        try:
            address_int = int(crash_address, 16) if crash_address.startswith("0x") else int(crash_address)
            location["address"] = {
                "absoluteAddress": address_int,
                "relativeAddress": address_int,  # Same as absolute for now
                "kind": "instruction"
            }
        except ValueError:
            pass

    # Add region for disassembly context
    location["region"] = {
        "startLine": 1,  # Not applicable for binary
        "startColumn": 1
    }

    # Add source location if available (from addr2line)
    source_location = getattr(crash, "source_location", "")
    if source_location and ":" in source_location:
        try:
            file_part, line_part = source_location.rsplit(":", 1)
            location["region"]["startLine"] = int(line_part)
            location["artifactLocation"]["uri"] = file_part
        except:
            pass

    return location


def _build_code_flow_from_stack(stack_trace: str, binary_path: Optional[Path]) -> Dict[str, Any]:
    """
    Build SARIF codeFlow from stack trace.

    SARIF codeFlows represent execution traces, perfect for stack traces.
    """
    thread_flow_locations = []

    # Parse stack trace (format varies by debugger)
    lines = stack_trace.split("\n")
    for idx, line in enumerate(lines):
        if not line.strip():
            continue

        # Extract frame information (best effort parsing)
        location_obj = {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(binary_path) if binary_path else "unknown"
                    },
                    "region": {
                        "snippet": {
                            "text": line.strip()
                        }
                    }
                },
                "message": {
                    "text": f"Stack frame {idx}"
                }
            }
        }

        thread_flow_locations.append(location_obj)

    return {
        "threadFlows": [
            {
                "id": "stack-trace",
                "message": {
                    "text": "Stack trace at crash"
                },
                "locations": thread_flow_locations
            }
        ]
    }


def _build_register_locations(registers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Build SARIF relatedLocations for register values.

    Registers are metadata, not code locations, but SARIF allows this for context.
    """
    related_locs = []

    for reg_name, reg_value in registers.items():
        related_locs.append({
            "id": reg_name,
            "message": {
                "text": f"{reg_name} = {reg_value}"
            },
            "properties": {
                "register": reg_name,
                "value": reg_value
            }
        })

    return related_locs


def _exploitability_to_level(exploitability: str) -> str:
    """
    Map exploitability to SARIF level.

    Args:
        exploitability: "exploitable", "likely", "unlikely", "not_exploitable", "unknown"

    Returns:
        SARIF level: "error", "warning", "note"
    """
    mapping = {
        "exploitable": "error",
        "likely": "error",
        "unlikely": "warning",
        "not_exploitable": "note",
        "unknown": "warning"
    }
    return mapping.get(exploitability, "warning")


def _generate_crash_message(crash: Any) -> str:
    """Generate human-readable message for crash."""
    crash_type = getattr(crash, "crash_type", "unknown")
    function_name = getattr(crash, "function_name", "unknown")
    crash_address = getattr(crash, "crash_address", "unknown")
    exploitability = getattr(crash, "exploitability", "unknown")

    msg = f"Crash detected: {crash_type}"

    if function_name != "unknown":
        msg += f" in function '{function_name}'"

    if crash_address != "unknown":
        msg += f" at address {crash_address}"

    msg += f" (exploitability: {exploitability})"

    return msg


def save_crashes_as_sarif(
    crash_contexts: List[Any],
    output_path: Path,
    tool_name: str = "RAPTOR-Fuzzer",
    tool_version: str = "3.0.0",
    binary_path: Optional[Path] = None
) -> None:
    """
    Convert crashes to SARIF and save to file.

    Args:
        crash_contexts: List of CrashContext objects
        output_path: Path to save SARIF file
        tool_name: Name of analysis tool
        tool_version: Version of tool
        binary_path: Path to analyzed binary

    Example:
        from packages.binary_analysis.crash_analyser import CrashAnalyser
        from core.sarif.crash_converter import save_crashes_as_sarif

        analyser = CrashAnalyser("/path/to/binary")
        crashes = [analyser.analyse_crash(crash_id, input_file, signal)]

        save_crashes_as_sarif(
            crashes,
            output_path=Path("crashes.sarif"),
            binary_path=Path("/path/to/binary")
        )
    """
    sarif_doc = crash_context_to_sarif(
        crash_contexts,
        tool_name=tool_name,
        tool_version=tool_version,
        binary_path=binary_path
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(sarif_doc, f, indent=2)

    print(f"[SARIF Converter] Saved {len(crash_contexts)} crashes to {output_path}")
