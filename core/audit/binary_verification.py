"""Binary-target mechanical verification for /audit.

Decompiler rule selection: curated Semgrep YAML rules that tolerate
synthetic variable names and decompiler output quirks. Fed into the
standard tool chain via ``decompiler_rules_for_hypothesis``.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent / "rules" / "decompiler"


_CWE_RULE_MAP: dict[str, list[str]] = {
    "CWE-134": ["format-string.yaml"],
    "CWE-120": ["buffer-overflow.yaml"],
    "CWE-121": ["buffer-overflow.yaml"],
    "CWE-122": ["buffer-overflow.yaml", "memory-safety.yaml"],
    "CWE-78": ["command-injection.yaml"],
    "CWE-190": ["integer-overflow.yaml"],
    "CWE-195": ["integer-overflow.yaml"],
    "CWE-680": ["integer-overflow.yaml"],
    "CWE-416": ["memory-safety.yaml"],
    "CWE-415": ["memory-safety.yaml"],
}

_KEYWORD_RULE_MAP: dict[str, str] = {
    "format string": "format-string.yaml",
    "printf": "format-string.yaml",
    "sprintf": "format-string.yaml",
    "buffer overflow": "buffer-overflow.yaml",
    "stack overflow": "buffer-overflow.yaml",
    "heap overflow": "buffer-overflow.yaml",
    "heap buffer": "buffer-overflow.yaml",
    "strcpy": "buffer-overflow.yaml",
    "strcat": "buffer-overflow.yaml",
    "command injection": "command-injection.yaml",
    "os command": "command-injection.yaml",
    "use after free": "memory-safety.yaml",
    "use-after-free": "memory-safety.yaml",
    "double free": "memory-safety.yaml",
    "double-free": "memory-safety.yaml",
    "memcpy": "memory-safety.yaml",
    "memmove": "memory-safety.yaml",
    "size mismatch": "memory-safety.yaml",
    "bounds check": "memory-safety.yaml",
    "integer overflow": "integer-overflow.yaml",
    "integer truncation": "integer-overflow.yaml",
    "narrowing cast": "integer-overflow.yaml",
    "integer wraparound": "integer-overflow.yaml",
}


def decompiler_rules_for_hypothesis(
    hypothesis: str,
    cwe: str = "",
) -> list[Path]:
    """Select decompiler Semgrep rules for a hypothesis + CWE.

    Returns resolved paths to YAML rule files.
    """
    rule_files: set[str] = set()

    if cwe:
        normalised = cwe.upper().replace("_", "-")
        if not normalised.startswith("CWE-"):
            normalised = "CWE-" + normalised
        for rf in _CWE_RULE_MAP.get(normalised, []):
            rule_files.add(rf)

    hyp_lower = hypothesis.lower()
    for keyword, rf in _KEYWORD_RULE_MAP.items():
        if keyword in hyp_lower:
            rule_files.add(rf)

    if not rule_files:
        for yaml_file in _RULES_DIR.glob("*.yaml"):
            rule_files.add(yaml_file.name)

    resolved = []
    for rf in sorted(rule_files):
        path = _RULES_DIR / rf
        if path.is_file():
            resolved.append(path)

    return resolved


def decompiler_rules_for_tree() -> list[Path]:
    """The whole curated decompiler corpus, for tree-scope sweeps.

    Tree-wide widening of :func:`decompiler_rules_for_hypothesis` —
    same resolution path (its no-hypothesis branch already resolves
    every rule file in the corpus), so the two consumers can never
    select from different rule sets. Used by the audit's decomp-tree
    sweep (:mod:`core.audit.decomp_sweep`), which has no hypothesis
    to narrow by: every curated decompiler-tolerant rule runs over
    the whole tree.
    """
    return decompiler_rules_for_hypothesis("", "")


def run_heap_copy_check(
    function_name: str,
    decompiled_c: str,
    *,
    file: str = "",
) -> list[dict]:
    """Run heap-size-to-copy-size analysis on a single function.

    Works on source or decompiled C. Returns a list of finding dicts.
    """
    from .heap_copy_checker import check_decompiled_function

    findings = check_decompiled_function(
        function_name, decompiled_c, file=file,
    )
    return [f.to_dict() for f in findings]


def run_integer_truncation_check(
    function_name: str,
    decompiled_c: str,
    *,
    file: str = "",
) -> list[dict]:
    """Run integer truncation → alloc mismatch analysis."""
    from .integer_truncation_checker import check_integer_truncation

    findings = check_integer_truncation(
        function_name, decompiled_c, file=file,
    )
    return [f.to_dict() for f in findings]


def run_proto_length_check(
    function_name: str,
    decompiled_c: str,
    *,
    file: str = "",
) -> list[dict]:
    """Run protocol-parser length discipline analysis."""
    from .proto_length_checker import check_proto_length

    findings = check_proto_length(
        function_name, decompiled_c, file=file,
    )
    return [f.to_dict() for f in findings]


def run_struct_field_check(
    function_name: str,
    decompiled_c: str,
    *,
    file: str = "",
) -> list[dict]:
    """Run struct-field-size vs copy-length analysis."""
    from .struct_field_checker import check_struct_field_copy

    findings = check_struct_field_copy(
        function_name, decompiled_c, file=file,
    )
    return [f.to_dict() for f in findings]


# Dynamic engagement intentionally does NOT live here. An earlier Frida
# auto-launch path (bare Popen of the target binary, gated on a
# ``config._binary_path`` attribute that was never set — the binary path
# lives in ``config.binary_verdicts``) was unreachable and has been
# removed. Runtime validation of findings is handled by
# ``core/audit/dynamic_sweep.py`` (harness compile + sanitiser run,
# gated on ``config.dynamic_validation`` via ``should_run_dynamic``) and
# Frida process observation by ``core/audit/frida_observe.py``.
