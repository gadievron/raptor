"""Shared schemas for LLM analysis prompts.

Used by both agent.py (sequential external LLM) and orchestrator.py (parallel dispatch).
"""

# Schema for vulnerability analysis — used with generate_structured()
ANALYSIS_SCHEMA = {
    "is_true_positive": "boolean",
    "is_exploitable": "boolean",
    "exploitability_score": "float (0.0-1.0)",
    "severity_assessment": "string (critical/high/medium/low)",
    "ruling": "string (validated/false_positive/unreachable/test_code/dead_code/mitigated)",
    "reasoning": "string",
    "attack_scenario": "string",
    "prerequisites": "list of strings",
    "impact": "string",
    "cvss_score_estimate": "float (0.0-10.0)",
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
        "severity_assessment": {"type": "string"},
        "ruling": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "exploit_code": {"type": ["string", "null"]},
        "patch_code": {"type": ["string", "null"]},
    },
    "required": ["finding_id", "is_true_positive", "is_exploitable", "reasoning"],
    "additionalProperties": False,
}
