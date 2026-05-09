"""Shared schemas for LLM analysis prompts.

Used by both agent.py (sequential external LLM) and orchestrator.py (parallel dispatch).
Field names and types are aligned with the /validate pipeline — see
core/schema_constants.py for the canonical field list.
"""

from core.schema_constants import AGENTIC_RULING_VALUES, CONFIDENCE_LEVELS, SEVERITY_LEVELS

# Schema for vulnerability analysis — used with generate_structured()
ANALYSIS_SCHEMA = {
    "is_true_positive": "boolean",
    "is_exploitable": "boolean",
    "exploitability_score": "float (0.0-1.0)",
    "confidence": f"string ({'/'.join(CONFIDENCE_LEVELS)})",
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
    # SMT path-feasibility hooks (populated only for memory-corruption /
    # arithmetic / bounds CWEs: 190, 125, 787, 476, 191). When present
    # the orchestrator's Tier 4 gate uses Z3 to refute findings whose
    # path conditions are unsatisfiable and to attach a witness model
    # to confirmed findings (used downstream by /exploit as a PoC seed).
    # Empty / missing → Tier 4 no-ops; nothing requires these fields.
    "path_conditions": (
        "list of strings or null - SMT-checkable branch conditions on the "
        "dangerous path. Each entry is a single predicate the parser "
        "accepts: e.g. 'count > 0x10000000', 'alloc_size == count * 16', "
        "'index >= buffer_size', 'ptr == NULL'. Populate ONLY for memory-"
        "corruption / arithmetic / bounds / null-deref CWEs (190, 125, 787, "
        "476, 191); use null or empty list otherwise — the field is "
        "optional and absence does not dock response quality."
    ),
    "path_profile": (
        "string or null - bitvector profile for SMT encoding. One of: "
        "'uint64' (default — sizes/offsets/counts), 'uint32' (CWE-190 "
        "wraparound), 'int32' / 'int64' (signed integer paths). Only "
        "meaningful when path_conditions is non-empty; null otherwise."
    ),
}

# Schema for deep dataflow validation — used by agent.py's validate_dataflow
DATAFLOW_VALIDATION_SCHEMA = {
    "source_type": "string - type of source (user_input/config/hardcoded/etc)",
    "source_attacker_controlled": "boolean - can attacker control this source?",
    "source_reasoning": "string - explain why source is or isn't attacker-controlled",
    "sanitizers_found": "integer - number of sanitizers in the path",
    "sanitizers_effective": "boolean - do sanitizers prevent exploitation?",
    "sanitizer_details": "list of dicts with keys: name, purpose, bypass_possible, bypass_method",
    "path_reachable": "boolean - can this code path be reached by attacker?",
    "reachability_barriers": "list of strings - what blocks reaching this path?",
    "is_exploitable": "boolean - FINAL VERDICT: is this truly exploitable?",
    "exploitability_confidence": "float (0.0-1.0) - how confident in this assessment?",
    "exploitability_reasoning": "string - detailed explanation of verdict",
    "attack_complexity": "string - low/medium/high - difficulty of exploitation",
    "attack_prerequisites": "list of strings - what attacker needs to succeed",
    "attack_payload_concept": "string - describe what payload would work, or empty if not exploitable",
    "impact_if_exploited": "string - what attacker can achieve",
    "cvss_estimate": "float (0.0-10.0) - severity score",
    "false_positive": "boolean - is this a false positive?",
    "false_positive_reason": "string - why it's false positive, or empty",
    # SMT path-feasibility hooks — see DATAFLOW_SCHEMA_FIELDS for the
    # full description. Same semantics; carried in the deep-validation
    # output too so the Tier 4 gate sees them whichever LLM call
    # produced them.
    "path_conditions": (
        "list of strings or null - SMT-checkable branch conditions on the "
        "dangerous path. Populate for memory-corruption / arithmetic / "
        "bounds / null-deref CWEs (190, 125, 787, 476, 191); null or "
        "empty list otherwise — optional, absence does not dock quality."
    ),
    "path_profile": (
        "string or null - bitvector profile: uint64 (default), uint32 "
        "(wraparound), int32, int64. Only meaningful with non-empty "
        "path_conditions; null otherwise."
    ),
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
        "confidence": {"type": ["string", "null"], "enum": [*CONFIDENCE_LEVELS, None]},
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
