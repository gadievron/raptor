"""
Shared schema constants for vulnerability findings.

Single source of truth for field values used by both /validate and /agentic
pipelines. Import from here — don't duplicate enum lists in individual schemas.

Field alignment between pipelines:

| Concept              | /validate            | /agentic              | Shared? |
|----------------------|----------------------|-----------------------|---------|
| ID                   | id                   | finding_id            | No      |
| Vuln type            | vuln_type            | vuln_type             | Yes     |
| CWE                  | cwe_id               | cwe_id                | Yes     |
| True positive        | is_true_positive     | is_true_positive      | Yes     |
| Exploitable          | is_exploitable       | is_exploitable        | Yes     |
| Exploitability score | exploitability_score | exploitability_score  | Yes     |
| Proximity            | proximity (0-10)     | n/a                   | No      |
| Severity             | severity_assessment  | severity_assessment   | Yes     |
| CVSS score           | cvss_score_estimate  | cvss_score_estimate   | Yes     |
| CVSS vector          | cvss_vector          | cvss_vector           | Yes     |
| Ruling               | ruling.status        | ruling                | No *    |
| FP reason            | false_positive_reason| false_positive_reason | Yes     |
| Reasoning            | description + proof  | reasoning + attack_scenario | No |
| Attack scenario      | attack_scenario      | attack_scenario       | Yes     |
| Confidence           | confidence           | confidence            | Yes     |
| Dataflow             | dataflow_summary     | dataflow_summary      | Yes     |
| Remediation          | remediation          | remediation           | Yes     |
| Exploit code         | poc.payload          | exploit_code          | No      |
| Patch code           | n/a                  | patch_code            | No      |
| Tool                 | tool                 | tool                  | Yes     |
| Rule ID              | rule_id              | rule_id               | Yes     |

* Ruling uses different enums intentionally. Validate: confirmed/ruled_out/exploitable
  (pipeline outcome). Agentic: validated/false_positive/unreachable/test_code/dead_code/mitigated
  (categorised verdict). The false_positive_reason field bridges the gap.

Fields intentionally NOT shared:

| Field        | Why different                                                    |
|--------------|------------------------------------------------------------------|
| ID           | Different origins (validate creates, agentic converts from SARIF)|
|              | Renaming validate's `id` → `finding_id` would touch 50+ places. |
| Proximity    | Multi-stage progress metric. No meaning in single-pass agentic.  |
| Ruling enums | Validate = pipeline outcome (confirmed/ruled_out/exploitable).   |
|              | Agentic = categorised verdict (false_positive/unreachable/...).  |
|              | false_positive_reason bridges the gap.                           |
| Reasoning    | Validate needs structured proof for Stage C sanity checking.     |
|              | Agentic needs narrative text for human review.                   |
| Exploit code | Validate: nested poc with safety metadata. Agentic: flat string. |
| Patch code   | Agentic-only. Validate doesn't generate patches.                 |
"""

# Vulnerability type enum — from SARIF rule mappings and manual analysis.
VULN_TYPES = [
    "command_injection", "sql_injection", "xss", "path_traversal",
    "ssrf", "deserialization", "buffer_overflow", "heap_overflow",
    "stack_overflow", "format_string", "use_after_free", "double_free",
    "integer_overflow", "out_of_bounds_read", "out_of_bounds_write",
    "null_deref", "type_confusion", "memory_leak", "privilege_confusion",
    "race_condition", "uninitialized_memory",
    "hardcoded_secret", "weak_crypto", "other",
]

# Severity assessment levels.
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]

# Agentic ruling values (single-pass categorised verdict).
# "validated" = confirmed real vulnerability.
# The rest are categories of dismissal, each with a specific reason.
AGENTIC_RULING_VALUES = [
    "validated", "false_positive", "unreachable",
    "test_code", "dead_code", "mitigated",
]

# Validate ruling values (multi-stage pipeline outcome).
VALIDATE_RULING_VALUES = ["confirmed", "ruled_out", "exploitable"]

# Confidence levels for LLM self-assessment.
CONFIDENCE_LEVELS = ["high", "medium", "low"]

# False-positive reason categories — why a finding was ruled out.
FP_REASONS = [
    "sanitized_input", "dead_code", "test_only",
    "unreachable_path", "safe_api_usage", "compiler_optimized",
    "defense_in_depth", "other",
]

# CWE ↔ vuln_type bidirectional mapping.
# Superset of all CWE mappings used across the codebase.
# CWE → vuln_type: used by orchestrator.py to classify SARIF findings.
# vuln_type → CWE: used by raptor_agentic.py to infer CWE when LLM omits it.
CWE_TO_VULN_TYPE = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-89": "sql_injection",
    "CWE-90": "other",              # LDAP injection
    "CWE-91": "other",              # XML injection
    "CWE-94": "command_injection",   # Code injection
    "CWE-119": "buffer_overflow",    # Generic buffer issue
    "CWE-120": "buffer_overflow",
    "CWE-121": "stack_overflow",
    "CWE-122": "heap_overflow",
    "CWE-125": "out_of_bounds_read",
    "CWE-134": "format_string",
    "CWE-190": "integer_overflow",
    "CWE-200": "other",             # Information disclosure
    "CWE-327": "weak_crypto",
    "CWE-328": "weak_crypto",       # Weak hash
    "CWE-367": "race_condition",
    "CWE-415": "double_free",
    "CWE-416": "use_after_free",
    "CWE-476": "null_deref",
    "CWE-502": "deserialization",
    "CWE-611": "other",             # XXE
    "CWE-787": "out_of_bounds_write",
    "CWE-843": "type_confusion",
    "CWE-918": "ssrf",
}

# Reverse: vuln_type → preferred CWE. Explicit — not derived from the forward
# mapping, because multiple CWEs map to the same vuln_type and the most common
# one isn't always first or last.
VULN_TYPE_TO_CWE = {
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "sql_injection": "CWE-89",
    "buffer_overflow": "CWE-120",
    "stack_overflow": "CWE-121",
    "heap_overflow": "CWE-122",
    "out_of_bounds_read": "CWE-125",
    "format_string": "CWE-134",
    "integer_overflow": "CWE-190",
    "weak_crypto": "CWE-327",
    "race_condition": "CWE-367",
    "double_free": "CWE-415",
    "use_after_free": "CWE-416",
    "null_deref": "CWE-476",
    "deserialization": "CWE-502",
    "out_of_bounds_write": "CWE-787",
    "type_confusion": "CWE-843",
    "ssrf": "CWE-918",
}
