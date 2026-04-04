"""Shared schemas for LLM analysis prompts.

Used by both agent.py (sequential external LLM) and orchestrator.py (parallel dispatch).
Field names and types are aligned with the /validate pipeline — see
packages/schema_constants.py for the canonical field list.
"""

from packages.schema_constants import AGENTIC_RULING_VALUES, SEVERITY_LEVELS

# Schema for vulnerability analysis — used with generate_structured()
ANALYSIS_SCHEMA = {
    "is_true_positive": "boolean",
    "is_exploitable": "boolean",
    "exploitability_score": "float (0.0-1.0)",
    "confidence": "string (high/medium/low)",
    "severity_assessment": f"string ({'/'.join(SEVERITY_LEVELS)})",
    "ruling": f"string ({'/'.join(AGENTIC_RULING_VALUES)})",
    "reasoning": "string",
    "attack_scenario": "string",
    "prerequisites": "list of strings",
    "impact": "string",
    "cvss_vector": "string - CVSS v3.1 vector (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    "cvss_score_estimate": "float or null - computed from cvss_vector, do not estimate manually",
    "vuln_type": "string - vulnerability category (e.g. command_injection, xss, buffer_overflow)",
    "cwe_id": "string - CWE-NNN (e.g. CWE-120)",
    "dataflow_summary": "string - concise source->sanitizer->sink chain",
    "remediation": "string - what to fix and how",
    "false_positive_reason": "string or null - reason when ruling is false_positive",
}

# Additional fields when dataflow is available
DATAFLOW_SCHEMA_FIELDS = {
    "source_attacker_controlled": "boolean - is the dataflow source controlled by attacker?",
    "sanitizers_effective": "boolean - are sanitizers in the path effective?",
    "sanitizer_bypass_technique": "string - how to bypass sanitizers, or empty if effective",
    "dataflow_exploitable": "boolean - is the complete dataflow path exploitable?",
}

# JSON Schema for CC sub-agent structured output (claude -p --json-schema).
# This is a proper JSON Schema, unlike ANALYSIS_SCHEMA which uses descriptive strings.
FINDING_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "is_true_positive": {"type": "boolean"},
        "is_exploitable": {"type": "boolean"},
        "exploitability_score": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "confidence": {"type": ["string", "null"]},
        "severity_assessment": {"type": "string"},
        "ruling": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
        "attack_scenario": {"type": ["string", "null"]},
        "exploit_code": {"type": ["string", "null"]},
        "patch_code": {"type": ["string", "null"]},
        "cvss_vector": {"type": ["string", "null"]},
        "cvss_score_estimate": {"type": ["number", "null"]},
        "vuln_type": {"type": ["string", "null"]},
        "cwe_id": {"type": ["string", "null"]},
        "dataflow_summary": {"type": ["string", "null"]},
        "remediation": {"type": ["string", "null"]},
        "false_positive_reason": {"type": ["string", "null"]},
        "tool": {"type": ["string", "null"]},
        "rule_id": {"type": ["string", "null"]},
    },
    "required": ["finding_id", "is_true_positive", "is_exploitable", "reasoning"],
    "additionalProperties": False,
}
