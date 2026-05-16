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
    # SMT path-feasibility hooks. Lives in ANALYSIS_SCHEMA (not
    # DATAFLOW_SCHEMA_FIELDS) because the conditions are LOCAL to
    # the dangerous statement for memory-corruption CWEs — the LLM
    # can extract them from a `count * sizeof(record)` expression
    # without needing CodeQL dataflow context. Pre-fix these were
    # gated behind has_dataflow=True, which created a circular
    # bootstrap: the auto-deep-validate gate needs path_conditions,
    # but path_conditions only got asked for when CodeQL had
    # already given a dataflow. Now always in scope; null is the
    # correct value for non-applicable CWEs.
    "path_conditions": (
        "list of strings or null - SMT-checkable branch conditions on the "
        "dangerous path. Each entry is a single predicate the parser "
        "accepts: e.g. 'count > 0x10000000', 'alloc_size == count * 16', "
        "'index >= buffer_size', 'ptr == NULL'. "
        "REQUIRED for memory-corruption CWEs (their analysis is not "
        "complete without it): CWE-119/120/121/122 (buffer overflow — "
        "supply the size-vs-bound predicate), CWE-125/787 (out-of-bounds "
        "read/write — supply the index-vs-bound predicate, e.g. 'idx >= "
        "buffer_size'), CWE-190 (integer overflow — supply the wraparound "
        "predicate, e.g. 'count * size > UINT32_MAX'), CWE-191 (integer "
        "underflow), CWE-476 (null deref — supply 'ptr == NULL'). For ANY "
        "OTHER CWE (XSS, SQLi, command injection, auth bypass, etc.), the "
        "correct value is null. Downstream Z3 refutes findings whose "
        "conditions are unsatisfiable and seeds /exploit PoCs from witness "
        "models — populating this field on the listed CWEs measurably "
        "improves verdict precision."
    ),
    "path_profile": (
        "string or null - bitvector profile for SMT encoding. One of: "
        "'uint64' (default — sizes/offsets/counts), 'uint32' (CWE-190 "
        "wraparound), 'int32' / 'int64' (signed integer paths). REQUIRED "
        "when path_conditions is non-empty; null otherwise."
    ),
}

# Additional fields when dataflow is available
DATAFLOW_SCHEMA_FIELDS = {
    "source_attacker_controlled": "boolean - is the dataflow source controlled by attacker?",
    "sanitizers_effective": "boolean - are sanitizers in the path effective?",
    "sanitizer_bypass_technique": "string - how to bypass sanitizers, or empty if effective",
    "dataflow_exploitable": "boolean - is the complete dataflow path exploitable?",
    # path_conditions / path_profile moved to ANALYSIS_SCHEMA above
    # so they're always in scope (not gated on has_dataflow=True).
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
        "dangerous path. REQUIRED for CWE-190 (integer overflow — supply "
        "wraparound predicate), CWE-125/787 (out-of-bounds — supply index-"
        "vs-bound predicate), CWE-476 (null deref — supply 'ptr == NULL'), "
        "CWE-191 (underflow). For ANY OTHER CWE, the correct value is null. "
        "Examples: 'count > 0x10000000', 'alloc_size == count * 16', "
        "'idx >= buffer_size', 'ptr == NULL'. Z3 uses these to refute "
        "infeasible findings and to seed /exploit PoCs from witness models."
    ),
    "path_profile": (
        "string or null - bitvector profile: 'uint64' (default — sizes/"
        "offsets/counts), 'uint32' (CWE-190 wraparound), 'int32' / 'int64' "
        "(signed paths). REQUIRED when path_conditions is non-empty; null "
        "otherwise."
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
