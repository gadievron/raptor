"""Map hypotheses to mechanical tool actions.

Given a natural-language hypothesis string from the LLM's review,
select the appropriate Semgrep rule, SMT solver verb, or Coccinelle
consistency-check.  Pure functions — no orchestrator state.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Dict, Optional

_HYPOTHESIS_SEMGREP_PATTERNS: Dict[str, str] = {
    "buffer overflow": "strcpy|sprintf|gets\\s*\\(|strcat",
    "sql injection": "SELECT.*%|INSERT.*%|UPDATE.*%|DELETE.*%",
    "command injection": "system\\s*\\(|popen\\s*\\(|exec[lv]p?e?\\s*\\(",
    "path traversal": "os\\.path\\.join|open\\s*\\(",
    "format string": "%s.*printf|printf\\s*\\(\\s*[a-zA-Z_]",
    "use after free": "free\\s*\\(",
    "double free": "free\\s*\\(",
    "xss": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "reflected": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "cross-site": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
}


def hypothesis_to_semgrep_rule(hypothesis: str, file_path: str) -> Optional[str]:
    """Generate a Semgrep YAML rule from a hypothesis string.

    Returns a path to a temp YAML file, or None if no rule can be derived.
    """
    hyp_lower = hypothesis.lower()

    pattern = None
    rule_id = "hypothesis-check"
    for keyword, regex in _HYPOTHESIS_SEMGREP_PATTERNS.items():
        if keyword in hyp_lower:
            if keyword == "format string" and file_path.endswith(".go"):
                continue
            pattern = regex
            rule_id = keyword.replace(" ", "-")
            break

    if not pattern:
        return None

    lang = "c"
    if file_path.endswith(".py"):
        lang = "python"
    elif file_path.endswith((".js", ".ts")):
        lang = "javascript"
    elif file_path.endswith(".java"):
        lang = "java"
    elif file_path.endswith(".go"):
        lang = "go"
    elif file_path.endswith(".rs"):
        lang = "rust"

    rule_yaml = (
        f"rules:\n"
        f"  - id: audit-sweep-{rule_id}\n"
        f"    pattern-regex: '{pattern}'\n"
        f"    message: 'Hypothesis validation: {rule_id}'\n"
        f"    languages: [{lang}]\n"
        f"    severity: WARNING\n"
    )

    try:
        tmp = tempfile.NamedTemporaryFile(
            prefix="audit_sweep_", suffix=".yaml",
            mode="w", delete=False,
        )
        tmp.write(rule_yaml)
        tmp.close()
        return tmp.name
    except OSError:
        return None


_SMT_HYPOTHESIS_VERBS = [
    ("integer overflow leading to", "check-overflow-to-oob"),
    ("overflow to oob", "check-overflow-to-oob"),
    ("negative value", "check-negative-bypass"),
    ("bypass the size check", "check-negative-bypass"),
    ("bypass the resource limit", "check-negative-bypass"),
    ("out of bounds", "check-oob"),
    ("out-of-bounds", "check-oob"),
    ("buffer overflow", "check-oob"),
    ("integer underflow", "check-overflow"),
    ("integer overflow", "check-overflow"),
    ("arithmetic overflow", "check-overflow"),
    ("multiplication overflow", "check-overflow"),
    ("addition overflow", "check-overflow"),
    ("truncation overflow", "check-overflow"),
    ("arithmetic underflow", "check-overflow"),
    ("permission bypass", "check-auth-bypass"),
    ("capability bypass", "check-auth-bypass"),
    ("auth bypass", "check-auth-bypass"),
    ("access control bypass", "check-auth-bypass"),
    ("privilege escalation", "check-auth-bypass"),
    ("early return bypass", "check-auth-bypass"),
    ("capability check", "check-auth-bypass"),
    ("permission check bypass", "check-auth-bypass"),
    ("lock imbalance", "check-lock-discipline"),
    ("missing unlock", "check-lock-discipline"),
    ("lock not released", "check-lock-discipline"),
    ("lock held on return", "check-lock-discipline"),
    ("lock held on error", "check-lock-discipline"),
    ("spinlock held", "check-lock-discipline"),
    ("mutex held", "check-lock-discipline"),
    ("deadlock", "check-lock-discipline"),
    ("lock discipline", "check-lock-discipline"),
    ("without unlocking", "check-lock-discipline"),
    ("resource leak", "check-resource-leak"),
    ("memory leak", "check-resource-leak"),
    ("leak on error", "check-resource-leak"),
    ("not freed", "check-resource-leak"),
    ("missing free", "check-resource-leak"),
    ("missing kfree", "check-resource-leak"),
    ("leaked on error path", "check-resource-leak"),
    ("allocated but not freed", "check-resource-leak"),
    ("leak in error handling", "check-resource-leak"),
    ("null pointer dereference", "check-null-propagation"),
    ("null dereference", "check-null-propagation"),
    ("null propagation", "check-null-propagation"),
    ("unchecked null", "check-null-propagation"),
    ("missing null check", "check-null-propagation"),
    ("null pointer", "check-null-propagation"),
    ("dereference without check", "check-null-propagation"),
    ("use without null check", "check-null-propagation"),
    ("integer narrowing", "check-integer-narrowing"),
    ("integer widening", "check-integer-narrowing"),
    ("truncation", "check-integer-narrowing"),
    ("narrowing conversion", "check-integer-narrowing"),
    ("implicit cast", "check-integer-narrowing"),
    ("type truncation", "check-integer-narrowing"),
    ("loss of data", "check-integer-narrowing"),
    ("size_t to int", "check-integer-narrowing"),
]


def hypothesis_to_smt_verb(hypothesis: str) -> Optional[str]:
    """Map a hypothesis to an SMT solver verb."""
    hyp_lower = hypothesis.lower()
    for keyword, verb in _SMT_HYPOTHESIS_VERBS:
        if keyword in hyp_lower:
            return verb
    if re.search(r"negative.*bypass|bypass.*negative|signed.*unsigned", hyp_lower):
        return "check-negative-bypass"
    return None


_COCCI_RULES_DIR = Path(__file__).resolve().parents[2] / "engine" / "coccinelle" / "rules"


def hypothesis_to_cocci_check(hypothesis: str) -> Optional[str]:
    """Map a hypothesis to a Coccinelle consistency-check rule.

    Returns the path to a .cocci rule file, or None.
    """
    if not _COCCI_RULES_DIR.is_dir():
        return None

    hyp_lower = hypothesis.lower()

    if "unchecked return" in hyp_lower or "return value" in hyp_lower:
        rule = _COCCI_RULES_DIR / "unchecked_return.cocci"
        if rule.exists():
            return str(rule)

    if "missing null check" in hyp_lower or "null check" in hyp_lower:
        rule = _COCCI_RULES_DIR / "missing_null_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "rcu_dereference", "rcu_read_lock", "rcu lock",
        "rcu grace period", "rcu protection",
    )):
        rule = _COCCI_RULES_DIR / "rcu_dereference_outside_rcu.cocci"
        if rule.exists():
            return str(rule)
        rule = _COCCI_RULES_DIR / "rcu_no_lock.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock scope", "lock gap", "accessed after unlock",
        "outside lock", "unprotected access",
    )):
        rule = _COCCI_RULES_DIR / "lock_scope_gap.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock ordering", "deadlock", "abba",
        "lock order", "lock inversion",
    )):
        rule = _COCCI_RULES_DIR / "lock_order_violation.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock held", "lock imbalance", "without unlock",
        "missing lock", "lock not released",
    )):
        rule = _COCCI_RULES_DIR / "lock_imbalance.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "copy_to_user", "info leak", "kernel memory to userspace",
        "not fully initialized", "leak uninitialized kernel memory",
        "padding", "copied to userspace",
    )):
        rule = _COCCI_RULES_DIR / "copy_to_user_uninit.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uninitialized", "not initialized", "uninitialised",
        "indeterminate value",
    )):
        rule = _COCCI_RULES_DIR / "uninitialized_return.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "bounds check", "out of bounds", "out-of-bounds",
        "array index", "without validation",
    )):
        rule = _COCCI_RULES_DIR / "missing_bounds_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "double fetch", "read from user", "copy_from_user",
    )):
        rule = _COCCI_RULES_DIR / "double_fetch.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "toctou", "time-of-check", "time of check",
        "check-then-use", "check-use",
    )) or re.search(r"check.*then.*use", hyp_lower):
        rule = _COCCI_RULES_DIR / "toctou_check_use.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "list_del", "list corruption", "list_for_each",
        "unsafe list", "linked list",
    )):
        rule = _COCCI_RULES_DIR / "unsafe_list_del.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uid truncat", "gid truncat", "truncating conversion",
        "narrowing", "__old_uid", "__old_gid",
    )):
        rule = _COCCI_RULES_DIR / "uid_truncation.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "resource leak", "memory leak", "not freed",
        "missing free", "leak on error",
    )):
        rule = _COCCI_RULES_DIR / "resource_leak_err.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "memory barrier", "smp_wmb",
        "smp_rmb", "smp_mb", "write ordering",
        "missing barrier", "reorder",
    )) or re.search(r"store.*load", hyp_lower):
        rule = _COCCI_RULES_DIR / "missing_memory_barrier.cocci"
        if rule.exists():
            return str(rule)

    if re.search(r"atomic.*race|check.*then.*act|atomic_read", hyp_lower):
        rule = _COCCI_RULES_DIR / "atomic_check_then_act.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "race condition", "use-after-free", "use after free",
        "after unlock", "freed while",
        "concurrent", "non-atomic",
    )) or re.search(r"after.*lock.*released", hyp_lower):
        rule = _COCCI_RULES_DIR / "use_after_unlock.cocci"
        if rule.exists():
            return str(rule)

    return None
