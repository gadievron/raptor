"""Sanitise Ghidra decompiler output for Semgrep's C parser.

Ghidra's decompiler produces C-like output that contains constructs
invalid in C but valid in C++ (or Ghidra-specific). Semgrep parses
this as C and chokes on:

  1. Scoped static variables: ``FuncName(args)::localVar``
  2. Class member access: ``ClassName::memberName``
  3. Method signatures: ``ClassName::method(args)``
  4. CONCAT macros: ``CONCAT44(a, b)`` — Ghidra's byte-concatenation

This module rewrites those into valid C so Semgrep rules can fire.
The rewriting is conservative — it preserves the semantic structure
(variable names, call patterns, sizes) that the rules match on.
"""

from __future__ import annotations

import re


# Paren/operand spans below are bounded: unbounded, every opener
# planted inside a span makes each occurrence re-scan the rest of the
# (hostile, decompiler-derived) text — quadratic. Real Ghidra
# argument and operand spans sit far inside 256 chars; beyond the
# bound the token is left unrewritten rather than scanned without
# bound.

# FuncName(type_args)::staticVar → __static_FuncName__staticVar
_SCOPED_STATIC_RE = re.compile(
    r'\b(\w+)\([^)]{0,256}\)::(\w+)',
)

# ClassName::memberOrMethod → ClassName__memberOrMethod
_CLASS_MEMBER_RE = re.compile(
    r'\b(\w+)::(\w+)',
)

# CONCAT44(a, b) → ((a) | (b))  (preserves both operands for analysis)
_CONCAT_RE = re.compile(
    r'\bCONCAT\d+\s*\(([^,)]{1,256}),([^)]{1,256})\)',
)

# SUB41(expr, n) → (expr)  (Ghidra sub-register extraction)
_SUB_RE = re.compile(
    r'\bSUB\d+\s*\(([^,)]{1,256}),[^)]{1,256}\)',
)

# SEXT14(expr) → (expr)  (sign-extension)
_SEXT_RE = re.compile(
    r'\bSEXT\d+\s*\(([^)]{1,256})\)',
)

# ZEXT14(expr) → (expr)  (zero-extension)
_ZEXT_RE = re.compile(
    r'\bZEXT\d+\s*\(([^)]{1,256})\)',
)


def sanitise(source: str) -> str:
    """Rewrite Ghidra decompiler output into valid C for Semgrep.

    Applies all rewriting rules. Safe to call on source that doesn't
    need sanitising — it returns unchanged if nothing matches.
    """
    result = source

    # Order matters: scoped statics first (they contain '(' which
    # the class-member regex would partially match)
    result = _SCOPED_STATIC_RE.sub(
        lambda m: f"__static_{m.group(1)}__{m.group(2)}",
        result,
    )
    for _ in range(5):
        prev = result
        result = _CLASS_MEMBER_RE.sub(
            lambda m: f"{m.group(1)}__{m.group(2)}",
            result,
        )
        if result == prev:
            break
    for _ in range(5):
        prev = result
        result = _CONCAT_RE.sub(
            lambda m: f"(({m.group(1).strip()}) | ({m.group(2).strip()}))",
            result,
        )
        if result == prev:
            break
    result = _SUB_RE.sub(
        lambda m: f"({m.group(1).strip()})",
        result,
    )
    result = _SEXT_RE.sub(
        lambda m: f"({m.group(1).strip()})",
        result,
    )
    result = _ZEXT_RE.sub(
        lambda m: f"({m.group(1).strip()})",
        result,
    )

    # __thiscall, __fastcall etc. — drop calling convention keywords
    result = re.sub(r'\b__(?:thiscall|fastcall|stdcall|cdecl)\b', '', result)

    # ((type)) with nothing after — broken cast from CONCAT rewrite
    result = re.sub(r'\(\((\w+)\)\)(\w+)', r'((\1)\2)', result)

    return result

