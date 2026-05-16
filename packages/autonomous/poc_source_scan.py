"""Source-level pre-scan for LLM-generated PoC C/C++ before compilation.

Why this exists:

The LLM-generated PoC source flowing into ``ExploitValidator.validate_exploit``
is attacker-influenceable via prompt injection in scanned-target metadata,
finding descriptions, scanner output, etc. The anti-prompt-injection
initiative (PR #273 and follow-ups) is the primary defence at the prompt
side, but if a clever payload survives those layers and convinces the
generator LLM to emit C with ``#include "/etc/passwd"`` or similar, gcc
happily reads the file and leaks the first non-parseable line into stderr,
which then flows back to the refiner LLM. A live probe confirmed the
channel works today (see ``project_poc_source_analysis.md`` memory).

This module is a narrowly-scoped second line of defence: a regex pre-pass
that rejects exfiltration shapes in LLM-generated standalone PoCs. It is
NOT a general C source validator — it only encodes the constraint
"validate_exploit's PoCs don't need to read files outside their own
work_dir or the standard system include path". Generic C compilation
(libxml2 etc.) violates that constraint legitimately and would be wrongly
rejected; that's outside the scope of this consumer.

What we block:

  - ``#include "/abs/path"`` and ``#include </abs/path>`` — direct exfil
  - ``#include "../../traversing"`` — traversal escape from work_dir
  - ``#embed "/abs"`` / ``#embed "../trav"`` — C23 file embedding
  - ``__has_include(<abs>)`` / ``__has_include("../trav")`` — 1-bit oracle
  - ``#pragma GCC dependency "/abs"`` / ``"../trav"`` — stat-based oracle
  - ``.incbin "/abs"`` / ``.incbin "../trav"`` — assembler embed

Angle-bracket includes of bare names (``<sys/socket.h>``) pass through:
gcc resolves them via the toolchain include search path, not the source
directory, so they aren't a traversal vector. ``#include "foo.h"`` and
``#include "subdir/bar.h"`` also pass — same-dir or descending-only.

What we don't try to do:

  - Match obfuscated forms (macro-built paths, stringification tricks).
    Belt-and-braces only: a determined attacker who has already bypassed
    every prompt-injection defence is the threat model, and even then
    most exfil shapes are caught by the obvious patterns.
  - Block destructive runtime constructs (``system()``, ``unlink()``).
    Those are policed at runtime by the sandbox layer, not at source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceScanViolation:
    """One pattern match. ``message`` is suitable for surfacing to the
    refiner LLM as compilation-style feedback so it can iterate."""

    directive: str  # "#include", "#embed", "__has_include", etc.
    path: str       # the offending path string
    reason: str     # "absolute path" or "directory traversal"
    line_no: int    # 1-indexed source line


# Each (directive_label, regex) extracts the path argument from a
# preprocessor or assembler directive. Anchored to line start so we
# don't match inside string literals or comments by accident — multi-line
# block comments containing real ``#include`` directives are vanishingly
# rare in PoC source and aren't worth a full C tokenizer.

# Use ``[ \t]*`` rather than ``\s*`` for leading and intra-directive
# whitespace: ``\s`` includes ``\n`` and lets the regex engine anchor a
# match on a blank line preceding the directive, which throws the
# reported line number off by however many blank lines came before.
_DIRECTIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("#include",
     re.compile(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"]+)[>"]', re.MULTILINE)),
    ("#embed",
     re.compile(r'^[ \t]*#[ \t]*embed[ \t]*[<"]([^>"]+)[>"]', re.MULTILINE)),
    ("#pragma GCC dependency",
     re.compile(r'^[ \t]*#[ \t]*pragma[ \t]+GCC[ \t]+dependency[ \t]+"([^"]+)"', re.MULTILINE)),
    ("__has_include",
     re.compile(r'__has_include\s*\(\s*[<"]([^>"]+)[>"]\s*\)')),
    # ``.incbin "..."`` appears inside ``__asm__("...")`` blocks where the
    # C-string-escape ``\"`` survives into the source we scan. The
    # non-greedy ``[^"]+?`` and trailing ``\\?`` together capture the path
    # without a stray backslash artefact (else the LLM-facing message
    # would read ``/etc/passwd\``).
    (".incbin",
     re.compile(r'\.incbin\s+\\?"([^"]+?)\\?"')),
)


def _classify(path: str) -> str | None:
    """Return a violation reason for ``path``, or None if the path is OK.

    Decision:
      - absolute path (``/...`` or platform-equivalent) → block
      - any segment is ``..`` → block
      - else → allow
    """
    if path.startswith("/") or (len(path) >= 2 and path[1] == ":"):
        # POSIX absolute, or Windows drive-letter absolute
        return "absolute path"
    # Normalise separators and split — mixed ``/`` and ``\`` both possible
    # if a Windows-style path slipped through. We don't care which.
    parts = re.split(r"[/\\]", path)
    if any(p == ".." for p in parts):
        return "directory traversal"
    return None


def scan(source: str) -> list[SourceScanViolation]:
    """Return all violations found in ``source``. Empty list = OK to compile."""
    violations: list[SourceScanViolation] = []
    for directive, pattern in _DIRECTIVE_PATTERNS:
        for m in pattern.finditer(source):
            path = m.group(1)
            reason = _classify(path)
            if reason is None:
                continue
            line_no = source.count("\n", 0, m.start()) + 1
            violations.append(SourceScanViolation(
                directive=directive,
                path=path,
                reason=reason,
                line_no=line_no,
            ))
    return violations


def format_violations(violations: list[SourceScanViolation]) -> list[str]:
    """Render violations as compilation-error-shaped strings the refiner
    LLM can iterate against. Avoids exposing the security mechanism by
    framing the rejection as a coding-style requirement."""
    return [
        f"line {v.line_no}: {v.directive} with {v.reason!s} "
        f"(``{v.path}``) is not allowed; use a same-directory include or "
        f"a standard ``<header>`` instead"
        for v in violations
    ]
