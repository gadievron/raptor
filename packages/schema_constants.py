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
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

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
