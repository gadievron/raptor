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
    "integer_overflow", "integer_underflow",
    "out_of_bounds_read", "out_of_bounds_write",
    "null_deref", "type_confusion", "memory_leak", "privilege_confusion",
    "race_condition", "uninitialized_memory",
    "hardcoded_secret", "weak_crypto", "other",
]

# Memory corruption vuln_types — Stage E feasibility analysis applies to these.
# Non-memory-corruption types (command_injection, sql_injection, xss, etc.) skip Stage E.
MEMORY_CORRUPTION_TYPES = frozenset({
    "buffer_overflow", "heap_overflow", "stack_overflow",
    "format_string", "use_after_free", "double_free",
    "integer_overflow", "integer_underflow",
    "out_of_bounds_read", "out_of_bounds_write",
    "null_deref", "type_confusion", "uninitialized_memory",
})

# Module-level invariant: every memory-corruption type must be a
# canonical vuln_type. Pre-fix (and historically): the two lists
# could drift apart silently. A vuln_type added to
# MEMORY_CORRUPTION_TYPES but not VULN_TYPES would be silently
# untracked by validators that whitelist against VULN_TYPES; a
# typo like "double_freee" would survive code review and only
# manifest as a missed Stage-E-skipped finding months later.
# Assert on import so any drift fails the test suite immediately.
_VULN_TYPES_SET = frozenset(VULN_TYPES)
_drift = MEMORY_CORRUPTION_TYPES - _VULN_TYPES_SET
if _drift:
    raise AssertionError(
        f"MEMORY_CORRUPTION_TYPES drifted from VULN_TYPES: "
        f"{sorted(_drift)} not in VULN_TYPES. "
        f"Add to VULN_TYPES list or remove from MEMORY_CORRUPTION_TYPES."
    )

def needs_feasibility_analysis(vuln_type: str) -> bool:
    """Check if a vuln_type requires Stage E binary feasibility analysis."""
    return normalise_vuln_type(vuln_type) in MEMORY_CORRUPTION_TYPES


# ---------------------------------------------------------------------------
# LLM alias → canonical vuln_type mapping
# ---------------------------------------------------------------------------
# LLMs produce varied names for the same vuln type. This maps common
# alternatives to the canonical VULN_TYPES enum values.

VULN_TYPE_ALIASES = {
    # Race condition / TOCTOU
    "toctou": "race_condition",
    "time_of_check_time_of_use": "race_condition",
    "time_of_check_to_time_of_use": "race_condition",
    "race": "race_condition",
    # Null dereference
    "null_pointer_dereference": "null_deref",
    "null_ptr_dereference": "null_deref",
    "null_dereference": "null_deref",
    "nullptr_deref": "null_deref",
    "null_pointer": "null_deref",
    "null_ptr_deref": "null_deref",
    "null_pointer_deref": "null_deref",
    # Buffer overflow
    "bof": "buffer_overflow",
    "stack_buffer_overflow": "buffer_overflow",
    "heap_buffer_overflow": "heap_overflow",
    "stack_bof": "stack_overflow",
    "heap_bof": "heap_overflow",
    # Use-after-free
    "uaf": "use_after_free",
    "use_after_free_read": "use_after_free",
    "use_after_free_write": "use_after_free",
    # Double free
    "double-free": "double_free",
    # Format string
    "fmt_string": "format_string",
    "format_string_bug": "format_string",
    "format_string_vulnerability": "format_string",
    "printf_vulnerability": "format_string",
    # XSS
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "dom_xss": "xss",
    # SQL injection
    "sqli": "sql_injection",
    "sql_injection_blind": "sql_injection",
    # Command injection
    "os_command_injection": "command_injection",
    "cmd_injection": "command_injection",
    "shell_injection": "command_injection",
    "code_injection": "command_injection",
    # RCE is a CONSEQUENCE classification, not a root cause. The
    # same outcome is reachable from deserialization, buffer
    # overflow → ROP, format-string overwrite of return address,
    # SSTI, etc. Mapping it to "command_injection" silently
    # misclassifies all the non-shell paths and confuses Stage E
    # feasibility analysis (which only runs on memory-corruption
    # types). Map to "other" so the LLM-supplied RCE label
    # signals "exploitable, but check the description for the
    # actual primitive" rather than asserting a specific class.
    "rce": "other",
    "remote_code_execution": "other",
    # Path traversal
    "directory_traversal": "path_traversal",
    "lfi": "path_traversal",
    "local_file_inclusion": "path_traversal",
    "file_inclusion": "path_traversal",
    # SSRF
    "server_side_request_forgery": "ssrf",
    # Integer overflow / underflow — distinct vuln_types because
    # CWE-190 (overflow) and CWE-191 (underflow) cover different
    # underlying bugs and different exploitation primitives
    # (overflow → too-small allocation; underflow → negative-
    # wrap-into-large-positive after subtraction). Pre-fix
    # collapsed both into "integer_overflow" which made
    # downstream consumers (CWE inference, Stage E analysis,
    # remediation suggestions) unable to distinguish them.
    "int_overflow": "integer_overflow",
    "int_underflow": "integer_underflow",
    # `integer_wrap` stays under overflow — wrap is the canonical
    # consequence of unchecked arithmetic exceeding bounds, not
    # of subtracting past zero.
    "integer_wrap": "integer_overflow",
    # Out of bounds
    "oob_read": "out_of_bounds_read",
    "oob_write": "out_of_bounds_write",
    "out_of_bounds": "out_of_bounds_read",
    "stack_overread": "out_of_bounds_read",
    "heap_overread": "out_of_bounds_read",
    "buffer_over_read": "out_of_bounds_read",
    "buffer_overread": "out_of_bounds_read",
    # Deserialization
    "insecure_deserialization": "deserialization",
    "unsafe_deserialization": "deserialization",
    # Memory leak
    "information_leak": "memory_leak",
    "info_leak": "memory_leak",
    # Crypto
    "weak_cryptography": "weak_crypto",
    "insecure_crypto": "weak_crypto",
    # Type confusion
    "type_confusion_vulnerability": "type_confusion",
    # Uninitialized memory
    "uninitialized_variable": "uninitialized_memory",
    "uninitialized_read": "uninitialized_memory",
    # Privilege
    "privilege_escalation": "privilege_confusion",
    # Hardcoded secrets
    "hardcoded_credentials": "hardcoded_secret",
    "hardcoded_password": "hardcoded_secret",
    "embedded_secret": "hardcoded_secret",
}


def normalise_vuln_type(vuln_type: str) -> str:
    """Normalize a vuln_type string to its canonical form.

    Accepts LLM-friendly aliases (toctou, null_pointer_dereference, etc.)
    and returns the canonical VULN_TYPES enum value. Returns the
    ORIGINAL string (preserving casing/whitespace) if no alias is
    known and the value isn't already canonical — pre-fix this
    silently lower-cased and stripped unknown values, mutating
    custom strings in places where the caller relied on
    `normalise_vuln_type(x) == x` to detect "this is a known type"
    (it always returned True because the lowered version of any
    string round-trips to itself).

    Lower-cased canonical match is also accepted: `"BUFFER_OVERFLOW"`
    -> `"buffer_overflow"` (canonical, case-insensitive).
    """
    if not vuln_type:
        return vuln_type
    lower = vuln_type.lower().strip()
    if lower in VULN_TYPE_ALIASES:
        return VULN_TYPE_ALIASES[lower]
    if lower in _VULN_TYPES_SET:
        return lower  # Already canonical (case-folded match).
    # Unknown — preserve the caller's original string so equality
    # checks against the input remain meaningful and downstream
    # logging shows what the caller actually supplied.
    return vuln_type

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
    # Note: keys must be unique — Python silently drops earlier dict
    # literals on collision, so a duplicate key looks like a no-op
    # but actually deletes the comment-documented intent. Keep one
    # entry per CWE; expand the comment when multiple intents apply.
    "CWE-20": "other",              # Improper input validation (parent of injection-class CWEs; mark generic so a more-specific child wins when both appear)
    "CWE-22": "path_traversal",
    "CWE-77": "command_injection",   # Command injection (parent of CWE-78 OS command injection — same vuln_type)
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-89": "sql_injection",
    "CWE-90": "other",              # LDAP injection
    "CWE-91": "other",              # XML injection
    "CWE-93": "other",              # CRLF injection (no closer-fitting vuln_type — typically header smuggling)
    "CWE-94": "command_injection",   # Code injection
    "CWE-119": "buffer_overflow",    # Generic buffer issue
    "CWE-120": "buffer_overflow",
    "CWE-121": "stack_overflow",
    "CWE-122": "heap_overflow",
    "CWE-125": "out_of_bounds_read",
    "CWE-129": "out_of_bounds_read", # Improper validation of array index
    "CWE-131": "buffer_overflow",   # Incorrect calculation of buffer size
    "CWE-134": "format_string",
    "CWE-170": "buffer_overflow",   # Improper null termination
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_underflow", # Distinct from overflow — see batch 324
    "CWE-193": "buffer_overflow",   # Off-by-one error
    "CWE-200": "other",             # Information disclosure
    "CWE-209": "other",             # Sensitive info in error message
    "CWE-269": "privilege_confusion", # Improper privilege management
    "CWE-285": "other",             # Improper authorization
    "CWE-287": "other",             # Improper authentication
    "CWE-295": "weak_crypto",       # Improper certificate validation
    "CWE-306": "other",             # Missing authentication
    "CWE-311": "weak_crypto",       # Missing encryption of sensitive data
    "CWE-319": "weak_crypto",       # Cleartext transmission
    "CWE-326": "weak_crypto",       # Inadequate encryption strength
    "CWE-327": "weak_crypto",
    "CWE-328": "weak_crypto",       # Weak hash
    "CWE-330": "weak_crypto",       # Insufficient randomness
    "CWE-352": "other",             # CSRF
    "CWE-362": "race_condition",   # General race condition
    "CWE-367": "race_condition",
    "CWE-369": "other",             # Divide by zero
    "CWE-400": "other",             # Resource exhaustion / DoS
    "CWE-401": "memory_leak",      # Missing release of memory
    "CWE-415": "double_free",
    "CWE-416": "use_after_free",
    "CWE-426": "path_traversal",   # Untrusted search path
    "CWE-434": "other",             # Unrestricted file upload
    "CWE-444": "other",             # HTTP request smuggling
    "CWE-457": "uninitialized_memory",
    "CWE-476": "null_deref",
    "CWE-489": "other",             # Active debug code
    "CWE-494": "other",             # Download of code without integrity check
    "CWE-502": "deserialization",
    "CWE-552": "path_traversal",   # Files accessible to external parties
    "CWE-601": "ssrf",              # URL redirect to untrusted site
    "CWE-611": "other",             # XXE
    "CWE-639": "other",             # Authorization bypass via user-controlled key
    "CWE-732": "other",             # Incorrect permission assignment
    "CWE-770": "other",             # Allocation of resources without limits
    "CWE-787": "out_of_bounds_write",
    "CWE-798": "hardcoded_secret",
    "CWE-805": "buffer_overflow",   # Buffer access with incorrect length
    "CWE-820": "race_condition",   # Missing synchronization
    "CWE-822": "out_of_bounds_read", # Untrusted pointer dereference
    "CWE-824": "uninitialized_memory", # Access of uninitialized pointer
    "CWE-843": "type_confusion",
    "CWE-862": "other",             # Missing authorization
    "CWE-863": "other",             # Incorrect authorization
    "CWE-908": "uninitialized_memory", # Use of uninitialized resource
    "CWE-918": "ssrf",
    "CWE-923": "weak_crypto",       # Improper restriction of comm. channel
    "CWE-1004": "other",            # Sensitive cookie missing HttpOnly
    "CWE-1188": "other",            # Insecure default initialization
    "CWE-1333": "other",            # Inefficient regex (ReDoS)
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
    "integer_underflow": "CWE-191",
    "weak_crypto": "CWE-327",
    "race_condition": "CWE-367",
    "double_free": "CWE-415",
    "use_after_free": "CWE-416",
    "null_deref": "CWE-476",
    "deserialization": "CWE-502",
    "out_of_bounds_write": "CWE-787",
    "type_confusion": "CWE-843",
    "ssrf": "CWE-918",
    # Round-trip closure: every vuln_type that appears as a value
    # in CWE_TO_VULN_TYPE above should also appear as a key here so
    # callers can convert in BOTH directions. Pre-fix five
    # categories were forward-only:
    "memory_leak": "CWE-401",
    "hardcoded_secret": "CWE-798",
    "uninitialized_memory": "CWE-908",  # Use of uninitialized resource (more general than 457 init-only)
    "privilege_confusion": "CWE-269",
}
