"""CWE-to-tool dispatch mapping for /audit.

Single source of truth for mapping CWE classes to tool-specific
dispatch rules (SMT verbs, Coccinelle rules, Joern taint, CodeQL
queries) and sink targets.

Consumed by:
  - Step 1e CWE fallback in _hypothesis_to_tool_chain
  - Step 1e' proactive tool validation
  - Any future CWE→tool consumer
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

CWE_TO_TOOL_DISPATCH: Dict[str, Dict[str, Any]] = {
    # Memory / bounds
    "CWE-120": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    "CWE-122": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    "CWE-125": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/out-of-bounds-read",
        "sinks": ["memcmp", "strlen", "strstr", "strcmp", "strncmp", "read", "fread"],
    },
    "CWE-787": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    # Integer
    "CWE-190": {
        "smt": "check-overflow",
        "cocci": "integer_overflow_alloc.cocci",
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
        "dark_verify": True,
    },
    "CWE-191": {
        "smt": "check-overflow",
        "cocci": None,
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
    },
    # Injection
    "CWE-78": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "cpp/command-line-injection",
        "sinks": ["os.system", "popen", "execve", "subprocess.Popen"],
    },
    "CWE-89": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/sql-injection",
        "sinks": ["sqlite3_exec", "cursor.execute", "mysql_query"],
    },
    "CWE-79": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "js/xss",
        "sinks": ["document.write", "innerHTML", "eval"],
    },
    "CWE-90": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": ["ldap_search", "ldap_search_s"],
    },
    "CWE-94": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": ["eval", "exec", "loadstring", "dofile"],
    },
    # Error handling
    "CWE-252": {
        "smt": None,
        "cocci": "unchecked_return.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-476": {
        "smt": "check-null-propagation",
        "cocci": "missing_null_check.cocci",
        "joern": False,
        "codeql": "cpp/null-dereference",
        "sinks": [],
    },
    # Format string
    "CWE-134": {
        "smt": None,
        "cocci": "format_string.cocci",
        "joern": True,
        "codeql": "cpp/non-constant-format",
        "sinks": ["printf", "fprintf", "sprintf", "syslog"],
        "dark_verify": True,
    },
    # Use-after-free / double-free
    "CWE-416": {
        "smt": "check-early-release",
        "cocci": "use_after_free.cocci",
        "joern": True,
        "codeql": "cpp/use-after-free",
        "sinks": ["kfree", "kfree_rcu", "free", "vfree", "kvfree",
                  "kfree_sensitive", "devm_kfree"],
        "dark_verify": True,
    },
    "CWE-415": {
        "smt": "check-early-release",
        "cocci": "double_free.cocci",
        "joern": True,
        "codeql": "cpp/use-after-free",
        "sinks": ["kfree", "kfree_rcu", "free", "vfree", "kvfree"],
    },
    # Concurrency
    "CWE-362": {
        "smt": "check-lock-domain",
        "cocci": "lock_imbalance.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-367": {
        "smt": "check-toctou",
        "cocci": "toctou_stat_open.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-667": {
        "smt": "check-lock-discipline",
        "cocci": "lock_imbalance.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Authentication / authorisation
    "CWE-287": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authenticate", "verify_password", "check_credentials",
            "login", "verify_token", "jwt.decode", "check_auth",
        ],
        "dark_verify": True,
    },
    "CWE-862": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authorize", "check_permission", "has_role", "is_admin",
            "check_access", "require_auth", "can_access",
        ],
        "dark_verify": True,
    },
    "CWE-863": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authorize", "check_permission", "has_role", "is_admin",
            "check_access", "require_auth", "can_access",
        ],
        "dark_verify": True,
    },
    # Resource management
    "CWE-401": {
        "smt": "check-resource-leak",
        "cocci": "resource_leak_err.cocci",
        "joern": False,
        "codeql": "cpp/resource-not-released-in-destructor",
        "sinks": [],
    },
    "CWE-775": {
        "smt": "check-resource-leak",
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Integer narrowing
    "CWE-681": {
        "smt": "check-integer-narrowing",
        "cocci": "sign_extension_widen.cocci",
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
    },
    # Uninitialised variable
    "CWE-457": {
        "smt": None,
        "cocci": "uninitialized_return.cocci",
        "joern": False,
        "codeql": "cpp/uninitialized-local",
        "sinks": [],
        "dark_verify": True,
    },
}


def lookup(cwe: str) -> Optional[Dict[str, Any]]:
    """Look up dispatch rules for a CWE identifier.

    Accepts "CWE-78", "cwe-78", "78", etc.
    """
    normalized = cwe.upper().strip()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_TO_TOOL_DISPATCH.get(normalized)


_HYPOTHESIS_CWE_MAP = [
    (r"race\s+condition|data\s+race|concurrent.*(?:write|access|modif)", "CWE-362"),
    (r"toctou|time.of.check.*time.of.use|check.*then.*use.*race", "CWE-367"),
    (r"deadlock|livelock|lock.*order|double.*lock", "CWE-667"),
    (r"use.after.free|dangling.*pointer|freed.*(?:object|memory|buffer)", "CWE-416"),
    (r"double.free|free.*twice", "CWE-415"),
    (r"(?:integer|arithmetic).*overflow|integer.*wrap", "CWE-190"),
    (r"(?:integer|arithmetic).*underflow", "CWE-191"),
    (r"null.*(?:pointer|deref)|nullptr.*deref|deref.*null", "CWE-476"),
    (r"(?:buffer|heap|stack).*overflow|out.of.bounds.*(?:write|access)", "CWE-787"),
    (r"out.of.bounds.*read|oob.*read", "CWE-125"),
    (r"format.*string.*(?:vuln|inject|attack)", "CWE-134"),
    (r"(?:command|os|shell).*inject", "CWE-78"),
    (r"sql.*inject", "CWE-89"),
    (r"(?:auth|permission|privilege).*bypass", "CWE-863"),
    (r"missing.*auth|no.*auth.*check", "CWE-862"),
    (r"resource.*leak|memory.*leak|missing.*free", "CWE-401"),
    (r"(?:integer|type).*(?:truncat|narrow)", "CWE-681"),
    (r"uninitiali[sz]ed", "CWE-457"),
]

_HYPOTHESIS_CWE_RE = None


def infer_cwe_from_hypothesis(hypothesis: str) -> Optional[str]:
    """Extract a CWE from hypothesis text via keyword matching.

    Returns the first matching CWE that has a dispatch entry, or None.
    Used as fallback when the LLM doesn't populate the CWE field.
    """
    global _HYPOTHESIS_CWE_RE
    if _HYPOTHESIS_CWE_RE is None:
        import re
        _HYPOTHESIS_CWE_RE = [
            (re.compile(pattern, re.IGNORECASE), cwe)
            for pattern, cwe in _HYPOTHESIS_CWE_MAP
        ]

    for regex, cwe in _HYPOTHESIS_CWE_RE:
        if regex.search(hypothesis or ""):
            if lookup(cwe) is not None:
                return cwe
    return None


def sinks_for_cwe(cwe: str) -> List[str]:
    """Return sink targets for a CWE, or empty list."""
    entry = lookup(cwe)
    if entry is None:
        return []
    return entry.get("sinks", [])


def smt_verb_for_cwe(cwe: str) -> Optional[str]:
    """Return the SMT verb for a CWE, or None."""
    entry = lookup(cwe)
    if entry is None:
        return None
    return entry.get("smt")


def cocci_rule_for_cwe(cwe: str) -> Optional[str]:
    """Return the Coccinelle rule filename for a CWE, or None."""
    entry = lookup(cwe)
    if entry is None:
        return None
    return entry.get("cocci")


def codeql_query_for_cwe(cwe: str) -> Optional[str]:
    """Return the CodeQL query ID for a CWE, or None."""
    entry = lookup(cwe)
    if entry is None:
        return None
    return entry.get("codeql")


def joern_applicable(cwe: str) -> bool:
    """Return whether Joern taint tracking is useful for a CWE."""
    entry = lookup(cwe)
    if entry is None:
        return False
    return bool(entry.get("joern")) and bool(entry.get("sinks"))


def dark_verify_applicable(cwe: str) -> bool:
    """Return whether dark-verify witness execution is the primary grounding for a CWE."""
    entry = lookup(cwe)
    if entry is None:
        return False
    return bool(entry.get("dark_verify"))
