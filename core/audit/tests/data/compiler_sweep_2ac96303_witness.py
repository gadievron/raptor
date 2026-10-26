"""Historical oracle for the compiler-sweep suppression witness.

PROVENANCE: core/audit/compiler_sweep.py at commit 2ac96303, lines
490-677, copied verbatim. The single edit is the function-local
``from .source_view import sanitized_view`` made absolute so this file
loads outside the package. Its constants and dependencies
(``core.audit.source_view.sanitized_view``,
``core.source.read_text_capped``) are pinned by
test_compiler_sweep.py::TestHistoricalOracle.

Tests compare the live base layer of compiler_sweep against THIS copy,
so the live base and its oracle cannot narrow together. Never edit
this file to follow a change in compiler_sweep.py: a deliberate base
change must update the pinned sha in the oracle tests instead.
"""
from __future__ import annotations

import re
from pathlib import Path

from core.source import read_text_capped


# Diagnostic-suppression witness: any of these in the analysed TU
# means analyzer silence is repo-steerable, so it cannot refute. The
# scan runs on the sanitized view (a pragma spelled inside a comment
# or string literal is inert and must not disqualify) — except
# ``_Pragma``, whose payload lives in a string literal by definition,
# so the operator token alone is the witness.
_DIAG_SUPPRESSION_RE = re.compile(
    r"#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+ignored"
    # Both compilers accept both spellings of the system-header pragma
    # (a system-header TU suppresses warnings AND analyzer reports for
    # the rest of the file) — enumerating only the GCC spelling let a
    # clang-path TU open with `#pragma clang system_header` and earn a
    # forged refutation from the resulting silence.
    r"|#\s*pragma\s+(?:GCC|clang)\s+system_header"
    # GNU linemarkers whose flag list carries 3 (`# 1 "x.h" 3`,
    # preprocessed-output `# 1 "x.h" 1 3 4`) mark the region as a
    # system header with no pragma anywhere — silencing warnings AND
    # analyzer reports on both compiler paths (clang --analyze and
    # gcc -fanalyzer). Plain renumbering (`#line 1 "x.h"`,
    # `# 1 "x.c" 1`) carries no 3 flag and stays inert.
    r"|#\s*(?:line\s+)?\d+\s+\"[^\"]*\"(?:\s+\d+)*?\s+3\b"
    r"|\b_Pragma\s*\("
    r"|\b__clang_analyzer__\b"
    # Analyzer-report suppression attributes ([[clang::suppress]],
    # [[gsl::suppress(...)]], __attribute__((suppress))) — honoured by
    # the clang static analyzer; silence under one is repo-steerable.
    r"|\[\[\s*(?:clang|gsl)\s*::\s*suppress\b"
    r"|__attribute__\s*\(\s*\(\s*suppress\b",
)


def _suppression_witness(source_text: str) -> str:
    """First diagnostic-suppression construct in one file, or ''."""
    from core.audit.source_view import sanitized_view
    m = _DIAG_SUPPRESSION_RE.search(sanitized_view(source_text, "tu.c"))
    return m.group(0).strip() if m else ""


# ---------------------------------------------------------------------------
# Include-closure suppression vet (refutation precondition)
# ---------------------------------------------------------------------------
# The single-file witness above covers only the text it is handed.
# GCC/clang diagnostic pragmas without push/pop persist for the REST
# OF THE TRANSLATION UNIT, including the includer's code after the
# `#include` — so a one-line repo header forges analyzer silence on a
# "reliable" family without any construct in the scanned file. The
# closure vet reads the compiler's own preprocessed output (`-E`):
# every textual spelling — includes (quoted or `-I`-resolved angle
# includes), `_Pragma` operators, and token-pasted (`##`) pragma
# synthesis — lands there as a `#pragma` line or a system-header
# linemarker, attributed to the file that authored it. Repo-authored
# closure files additionally get the raw single-file scan, because
# conditional-compilation tokens (`#ifndef __clang_analyzer__`)
# resolve away in `-E` output. Any failure to vet fails toward
# unknown — never toward refuted.

_PP_LINEMARKER_RE = re.compile(
    r'^#\s*(?:line\s+)?\d+\s+"([^"]*)"((?:\s+\d+)*)\s*$',
)

# Directive-shaped suppression in PREPROCESSED output. `_Pragma` and
# `__clang_analyzer__` are deliberately absent: the preprocessor has
# already expanded the former into `#pragma` lines and resolved the
# latter's conditionals — both are caught here post-expansion or by
# the raw per-file scan.
_PP_SUPPRESSION_RE = re.compile(
    r"^\s*#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+ignored"
    r"|^\s*#\s*pragma\s+(?:GCC|clang)\s+system_header"
    r"|\[\[\s*(?:clang|gsl)\s*::\s*suppress\b"
    r"|__attribute__\s*\(\s*\(\s*suppress\b",
)

_MAX_CLOSURE_FILES = 200
_MAX_CLOSURE_FILE_BYTES = 2_000_000
_MAX_PP_TEXT_BYTES = 64_000_000

# Source-level linemarker / #line directive (any flags), scanned on
# RAW repo text — the sanitized view blanks the quoted path.
_SRC_LINEMARKER_RE = re.compile(
    r'^[ \t]*#[ \t]*(?:line[ \t]+)?\d+[ \t]+"([^"]*)"', re.MULTILINE,
)


def _repo_authored(name: str, target_resolved: Path) -> bool:
    """Closure filename the scanned repo controls.

    Anything under the target tree is attacker-authored; compiler
    pseudo-files (``<built-in>``, ``<command-line>``) and system
    paths outside the tree are not. Non-absolute and unresolvable
    names count as repo-authored — unattributable means unvetted,
    which fails toward refusal.
    """
    if not name or name.startswith("<"):
        return False
    p = Path(name)
    if not p.is_absolute():
        return True
    try:
        return p.resolve().is_relative_to(target_resolved)
    except OSError:
        return True


def _closure_suppression_witness(
    pp_text: str,
    target_path: Path,
    full_path: Path,
) -> tuple[str, str]:
    """Suppression witness over the TU's preprocessed closure.

    Returns ``(witness, vet_failure)``: a non-empty *witness* names
    the first suppression construct attributed to a repo-authored
    closure file (or a repo file marked as a system header via a
    flag-3 linemarker); a non-empty *vet_failure* means the closure
    could not be fully vetted (caps, unreadable file) and refutation
    must be withheld. Both empty = vetted clean.
    """
    try:
        target_resolved = target_path.resolve()
    except OSError:
        return "", "target path unresolvable"
    if len(pp_text) > _MAX_PP_TEXT_BYTES:
        return "", "preprocessed output exceeds the scan cap"
    current = str(full_path)
    # Files to raw-scan: the TU plus every repo file the preprocessor
    # actually OPENED (flag-1 enter markers). Flag-less markers are
    # renames (#line directives) — the named path may not exist as a
    # file at all (generated sources cite their grammar files), but
    # its region's text lives in the physical file that carries the
    # directive, which IS scanned.
    repo_files: dict[str, None] = {str(full_path): None}
    for line in pp_text.splitlines():
        lm = _PP_LINEMARKER_RE.match(line)
        if lm:
            # Flag-3 (system header) markers are NOT a witness here:
            # the preprocessor emits benign ones around every
            # system-macro expansion (`NULL` → `# N "tu.c" 3 4`), and
            # every construct that can put a REPO region into
            # system-header state is textual in a repo file (pragma /
            # linemarker — the raw scan below) or lands as a #pragma
            # line in this output (token-pasted _Pragma — the
            # directive scan). system_header state also does not
            # persist across the include return, so a header cannot
            # silence the includer's code this way.
            fname, flags = lm.group(1), lm.group(2).split()
            if "1" in flags and _repo_authored(fname, target_resolved):
                repo_files.setdefault(fname)
            current = fname
            continue
        m = _PP_SUPPRESSION_RE.search(line)
        if m and _repo_authored(current, target_resolved):
            return f"{m.group(0).strip()} (in {current})", ""
    if len(repo_files) > _MAX_CLOSURE_FILES:
        return "", (
            f"{len(repo_files)} repo files in the include closure "
            f"exceed the vet cap ({_MAX_CLOSURE_FILES})"
        )
    for fname in repo_files:
        p = Path(fname)
        # Capped fd read, not stat-then-read (target-writable files
        # race a by-name gate; FIFO plants block raw reads).
        got = read_text_capped(p, _MAX_CLOSURE_FILE_BYTES)
        if got is None:
            return "", f"closure file {fname} unreadable"
        text, truncated = got
        if truncated:
            return "", f"closure file {fname} exceeds the byte cap"
        w = _suppression_witness(text)
        if w:
            return f"{w} (in {fname})", ""
        # Attribution laundering: a plain linemarker in a repo file
        # re-attributes its own subsequent lines — including a
        # token-pasted pragma expanded there — to any path it names,
        # so the pp walk above would classify the construct as
        # system-authored. A repo linemarker naming a path OUTSIDE
        # the target tree makes attribution unverifiable: refuse.
        # In-tree names (bison/flex-generated sources cite their
        # grammar files) stay vetted — their regions classify as
        # repo-authored either way.
        for lm in _SRC_LINEMARKER_RE.finditer(text):
            if not _repo_authored(lm.group(1), target_resolved):
                return "", (
                    f"linemarker in {fname} re-attributes lines to "
                    f"{lm.group(1) or '<empty>'} — suppression "
                    f"attribution unverifiable"
                )
    return "", ""

