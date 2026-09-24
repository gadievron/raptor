"""Compiler-static-analyzer sweep for /audit.

Runs the compiler's own static analyzer — ``gcc -fanalyzer`` (preferred)
or ``clang --analyze`` / clang warning passes (fallback) — against a
single translation unit and maps the diagnostics onto a hypothesis
outcome.

Design constraints (the scanned repo is UNTRUSTED):

* NOTHING from the repo may execute.  No build system is ever invoked —
  ``make`` / ``cmake`` / ``configure`` are repo-controlled code.  The
  compiler is invoked directly on exactly one translation unit with
  ``-c -o /dev/null``; include paths are derived mechanically from the
  directory layout, never by running anything.
* The compiler itself parses hostile input (attacker-authored source),
  so the invocation goes through ``core.sandbox.run`` with
  ``block_network=True`` plus Landlock target/output confinement — the
  same trusted-binary/untrusted-input posture as the r2 binary-edge
  extraction.
* A broken compile must NEVER read as refutation.  Missing generated
  headers, exotic dialects, and analyzer crashes are ``inconclusive`` /
  ``error`` — refutation is only allowed when the analyzer ran cleanly
  AND the CWE family is one the analyzer covers reliably.

Evidence stamps are namespaced ``compiler:<diagnostic-id>`` (e.g.
``compiler:-Wanalyzer-use-after-free``); the ``compiler`` namespace is
registered in :mod:`core.audit.evidence_grade`.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from core.source import read_text_capped
from typing import Any

from core.json import load_json
from core.run.scratch import scratch_dir

from ._util import safe_join
from .run_memo import BoundedMemo
from .sweep import SweepResult
from core.security.env_sanitisation import safe_subprocess_env

logger = logging.getLogger(__name__)

_COMPILE_TIMEOUT_S = 120
_PROBE_TIMEOUT_S = 30
_MAX_INCLUDE_DIRS = 8
_INCLUDE_WALK_DEPTH = 3
_INCLUDE_DIR_NAMES = frozenset({"include", "includes", "inc"})
_WALK_SKIP_DIRS = frozenset({"node_modules", "vendor", "third_party"})
_MAX_RAW_OUTPUT = 20_000
# gcc -fdiagnostics-format=sarif-file output over target code — the
# SARIF budget class shared with core.sarif.parser.load_sarif.
_MAX_SARIF_BYTES = 100 * 1024 * 1024

_C_SUFFIXES = frozenset({".c"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".C"})


# ---------------------------------------------------------------------------
# CWE-family → diagnostic-id map
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FamilySpec:
    """How one CWE family maps onto compiler diagnostics.

    ``reliable`` marks families the analyzer covers well enough that a
    clean run with no in-range diagnostic counts as refutation.  For
    everything else the sweep is confirm-only: no diagnostic means
    ``inconclusive``, never ``refuted``.
    """

    gcc_ids: tuple[str, ...]
    gcc_flags: tuple[str, ...]
    clang_engine: str  # "analyze" (path-sensitive) | "warning" (sema -W pass)
    clang_ids: tuple[str, ...]
    clang_flags: tuple[str, ...]
    clang_message_re: str  # "" = no message discrimination needed
    reliable: bool


_OOB_SPEC = FamilySpec(
    gcc_ids=(
        "-Wanalyzer-out-of-bounds",
        "-Wstringop-overflow",
        "-Wstringop-overread",
        "-Warray-bounds",
    ),
    gcc_flags=(),
    clang_engine="warning",
    clang_ids=("-Warray-bounds", "-Wfortify-source"),
    clang_flags=("-Warray-bounds",),
    clang_message_re="",
    # Constant/locally-provable cases only — silence proves nothing
    # about runtime-sized accesses, so no refutation from this family.
    reliable=False,
)

COMPILER_CWE_MAP: dict[str, FamilySpec] = {
    "CWE-416": FamilySpec(
        gcc_ids=("-Wanalyzer-use-after-free",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc", "cplusplus.NewDelete"),
        clang_flags=(),
        clang_message_re=r"after it is (?:freed|deleted)|use.?after.?free",
        reliable=True,
    ),
    "CWE-415": FamilySpec(
        gcc_ids=("-Wanalyzer-double-free",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc", "cplusplus.NewDelete"),
        clang_flags=(),
        clang_message_re=r"free released memory|double.?free",
        reliable=True,
    ),
    "CWE-476": FamilySpec(
        gcc_ids=(
            "-Wanalyzer-null-dereference",
            "-Wanalyzer-possible-null-dereference",
        ),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("core.NullDereference", "core.CallAndMessage"),
        clang_flags=(),
        clang_message_re=r"null",
        reliable=True,
    ),
    "CWE-401": FamilySpec(
        gcc_ids=("-Wanalyzer-malloc-leak",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc",),
        clang_flags=(),
        clang_message_re=r"leak",
        reliable=True,
    ),
    "CWE-134": FamilySpec(
        gcc_ids=("-Wformat-security", "-Wformat-nonliteral"),
        gcc_flags=("-Wformat=2", "-Wformat-security"),
        clang_engine="warning",
        clang_ids=("-Wformat-security", "-Wformat-nonliteral"),
        clang_flags=("-Wformat=2", "-Wformat-security"),
        clang_message_re="",
        # -Wformat-security fires only when the non-literal format is
        # visible in this TU; wrappers defeat it — confirm-only.
        reliable=False,
    ),
    "CWE-120": _OOB_SPEC,
    "CWE-121": _OOB_SPEC,
    "CWE-122": _OOB_SPEC,
    "CWE-125": _OOB_SPEC,
    "CWE-130": _OOB_SPEC,
    "CWE-787": _OOB_SPEC,
    # Type confusion via pointer punning: strict-aliasing diagnostics
    # fire only on TU-visible casts the optimiser may exploit —
    # confirm-only (silence proves nothing about cross-TU punning).
    "CWE-843": FamilySpec(
        gcc_ids=("-Wstrict-aliasing",),
        gcc_flags=("-fstrict-aliasing", "-Wstrict-aliasing=1"),
        clang_engine="warning",
        clang_ids=("-Wstrict-aliasing",),
        clang_flags=("-fstrict-aliasing", "-Wstrict-aliasing"),
        clang_message_re="",
        reliable=False,
    ),
    # Loop with unreachable exit condition: the analyzer's
    # infinite-loop diagnostic (gcc >= 14) and clang's -Wloop-analysis
    # (loop variable not updated / suspicious condition) fire only on
    # locally-provable shapes — confirm-only (silence proves nothing
    # about data-dependent loop bounds).
    "CWE-835": FamilySpec(
        gcc_ids=("-Wanalyzer-infinite-loop",),
        gcc_flags=(),
        clang_engine="warning",
        clang_ids=("-Wloop-analysis",),
        clang_flags=("-Wloop-analysis",),
        clang_message_re="",
        reliable=False,
    ),
    "CWE-457": FamilySpec(
        gcc_ids=("-Wanalyzer-use-of-uninitialized-value",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("core.uninitialized", "core.UndefinedBinaryOperatorResult"),
        clang_flags=(),
        clang_message_re=r"uninitial|garbage|undefined",
        reliable=False,
    ),
    # Unchecked return value: corroborates the fail_open channel's
    # ignored-return leg (the diagnostic is receipt material on its
    # confirmations).
    "CWE-252": FamilySpec(
        gcc_ids=("-Wunused-result",),
        gcc_flags=("-Wunused-result",),
        clang_engine="warning",
        clang_ids=("-Wunused-result",),
        clang_flags=("-Wunused-result",),
        clang_message_re="",
        # Fires only for warn_unused_result-attributed callees visible
        # in this TU; silence proves nothing — confirm-only.
        reliable=False,
    ),
}


def _normalise_cwe(cwe: str) -> str:
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return normalized


def compiler_applicable(cwe: str) -> bool:
    """True when the CWE has a compiler-diagnostic mapping."""
    return _normalise_cwe(cwe) in COMPILER_CWE_MAP


def get_compiler_check_role(cwe: str) -> str:
    """Role of the compiler check for a CWE.

    ``"verification"`` for mapped families (a diagnostic of the mapped
    family, in range, implicating the hypothesised identifier is
    authoritative); ``"detection"`` for everything else — unmapped
    families never reach ``confirmed``/``refuted`` anyway.
    """
    return "verification" if compiler_applicable(cwe) else "detection"


# ---------------------------------------------------------------------------
# Toolchain probing (once per process, cached)
# ---------------------------------------------------------------------------

_PROBE_LOCK = threading.Lock()
_PROBE_CACHE: dict[str, Any] = {}


def _reset_probe_cache() -> None:
    """Test hook: forget probe results (e.g. after monkeypatching which)."""
    with _PROBE_LOCK:
        _PROBE_CACHE.clear()


def _gcc_probe_ok(gcc: str, fmt: str) -> bool:
    """Check gcc accepts ``-fanalyzer`` + the diagnostics format.

    Probe input is ``/dev/null`` (RAPTOR-chosen, no repo content), so a
    plain subprocess with the safe env is the right trust level — the
    sandbox is reserved for the real sweep, which parses hostile source.
    Runs in a throwaway cwd because ``sarif-file`` drops a ``.sarif``
    next to whatever it compiles.
    """
    with tempfile.TemporaryDirectory(prefix="raptor_cc_probe_") as td:
        try:
            proc = subprocess.run(
                [gcc, "-fanalyzer", f"-fdiagnostics-format={fmt}",
                 "-fsyntax-only", "-x", "c", os.devnull],
                capture_output=True, text=True, check=False,
                timeout=_PROBE_TIMEOUT_S, env=safe_subprocess_env(), cwd=td,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0


def _gcc_analyzer() -> tuple[str, str] | None:
    """Return ``(gcc_path, diagnostics_mode)`` or None.

    Mode is ``"sarif-file"`` (gcc 13+) or ``"json"`` (gcc 10-12, where
    ``-fanalyzer`` exists but SARIF output does not).  gcc < 10 rejects
    ``-fanalyzer`` itself and probes as unavailable.
    """
    with _PROBE_LOCK:
        if "gcc" in _PROBE_CACHE:
            return _PROBE_CACHE["gcc"]
    gcc = shutil.which("gcc")
    result: tuple[str, str] | None = None
    if gcc:
        for fmt in ("sarif-file", "json"):
            if _gcc_probe_ok(gcc, fmt):
                result = (gcc, fmt)
                break
    with _PROBE_LOCK:
        _PROBE_CACHE["gcc"] = result
    return result


def _clang_path() -> str | None:
    with _PROBE_LOCK:
        if "clang" in _PROBE_CACHE:
            return _PROBE_CACHE["clang"]
    clang = shutil.which("clang")
    with _PROBE_LOCK:
        _PROBE_CACHE["clang"] = clang
    return clang


# ---------------------------------------------------------------------------
# Per-TU analysis cache
# ---------------------------------------------------------------------------

# One full-TU analyzer run emits ALL diagnostics for the translation
# unit; per-hypothesis dispatch only differs in the post-run filtering
# (diagnostic family, line range, identifier attribution). Cache the
# parsed run record per (invocation, compiler identity, TU content)
# so N hypotheses against one TU pay for one compile per flag family,
# not N.
#
# Size trade-off: smaller → audits whose hypothesis batch spans many
# (TU, flag-family) combinations re-pay full analyzer compiles
# (10-120s each) as entries rotate out; larger → more retained
# diagnostic lists plus capped stderr blobs (~20 KB each) held for
# the cache's lifetime.
#
# Lifetime: the orchestrator passes per-RUN instances owned by its
# OrchestratorConfig (``tu_cache`` / ``include_dirs_memo``,
# default_factory — exactly like ``sweep_memo``), because the key's
# correctness argument is run-scoped: the TU content hash pins the
# file itself, but its ``#include`` closure is not hashed and only
# the run's read-only-target-tree contract bounds it (a header edit
# between in-process runs would otherwise serve stale diagnostics).
# The module-level instances below serve direct callers and tests
# only (reset via ``_reset_tu_cache``).
_TU_CACHE_MAX_ENTRIES = 64
_tu_cache: BoundedMemo[dict[str, Any]] = BoundedMemo(_TU_CACHE_MAX_ENTRIES)

# The include-dir walk scans the whole target tree; its result is a
# function of the (target, TU dir) pair only, so derive it once per
# pair per cache lifetime instead of once per hypothesis. Same bound
# and lifetime rationale as the TU cache, but entries are small path
# lists.
_include_dirs_memo: BoundedMemo[list[str]] = BoundedMemo(_TU_CACHE_MAX_ENTRIES)


def _reset_tu_cache() -> None:
    """Test hook: forget cached TU analyses and include-dir walks."""
    _tu_cache.clear()
    _include_dirs_memo.clear()


class _AnalyzerSignalKilled(Exception):
    """The analyzer subprocess died to a signal (negative returncode).

    Raised out of the memoized compute so the TU cache stores nothing
    — a signal kill is environment pressure (OOM killer, sandbox
    kill), not a property of the TU, and pinning it would disable the
    compiler channel for that TU for the cache's whole lifetime.
    """

    def __init__(self, signal: int) -> None:
        super().__init__(f"analyzer killed by signal {signal}")
        self.signal = signal


def _tu_cache_key(cmd: list[str], full_path: Path) -> tuple | None:
    """Cache key for one analyzer invocation.

    ``cmd`` already embeds the compiler path, diagnostics mode /
    engine, per-family flags, derived include dirs, and the TU path;
    the TU content hash catches edits to the file and the compiler
    binary's stat signature catches a toolchain swap at the same
    path. An unreadable TU returns None — run uncached.
    """
    import hashlib

    try:
        tu_hash = hashlib.sha256(full_path.read_bytes()).hexdigest()
    except OSError:
        return None
    bin_sig: tuple | None
    try:
        st = os.stat(cmd[0])
        bin_sig = (st.st_size, st.st_mtime_ns)
    except OSError:
        bin_sig = None
    return ("compiler_tu", tuple(cmd), bin_sig, tu_hash)


# ---------------------------------------------------------------------------
# Mechanical include-path derivation (never executes anything)
# ---------------------------------------------------------------------------


def _derive_include_dirs(target_path: Path, file_dir: Path) -> list[str]:
    """Target root + the TU's own dir + common ``include/`` dirs.

    Bounded directory walk (depth ≤ 3, symlinks not followed, result
    capped) so a hostile tree cannot blow the sweep up.  Purely
    mechanical — no repo code runs to discover flags.
    """
    dirs: list[str] = []
    for d in (str(target_path), str(file_dir)):
        if d not in dirs:
            dirs.append(d)

    found: list[str] = []
    base_depth = len(target_path.resolve().parts)
    try:
        for root, subdirs, _files in os.walk(target_path, followlinks=False):
            if len(Path(root).parts) - base_depth >= _INCLUDE_WALK_DEPTH:
                subdirs[:] = []
                continue
            subdirs[:] = [
                d for d in subdirs
                if not d.startswith(".") and d not in _WALK_SKIP_DIRS
            ]
            found.extend(os.path.join(root, d) for d in subdirs if d.lower() in _INCLUDE_DIR_NAMES)
            if len(found) >= _MAX_INCLUDE_DIRS:
                break
    except OSError:
        pass

    for d in sorted(found)[:_MAX_INCLUDE_DIRS]:
        if d not in dirs:
            dirs.append(d)
    return dirs


def _cached_include_dirs(
    target_path: Path,
    file_dir: Path,
    memo: BoundedMemo[list[str]] | None = None,
) -> list[str]:
    """Memoized :func:`_derive_include_dirs` per (target, TU dir) pair.

    *memo* is the caller's per-run instance; None falls back to the
    module-level one. A copy is returned so callers cannot mutate the
    shared entry.
    """
    try:
        key: tuple | None = (
            "include_dirs",
            str(target_path.resolve()),
            str(file_dir.resolve()),
        )
    except OSError:
        key = None
    _memo = memo if memo is not None else _include_dirs_memo
    dirs, _cached = _memo.get_or_compute(
        key, lambda: _derive_include_dirs(target_path, file_dir),
    )
    return list(dirs)


# ---------------------------------------------------------------------------
# Hypothesis identifier extraction (negative control)
# ---------------------------------------------------------------------------

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
    from .source_view import sanitized_view
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


_MARKED_ID_RE = re.compile(r"[`'\"]([A-Za-z_]\w*)[`'\"]")
_WORD_RE = re.compile(r"[A-Za-z_]\w*")

# Vulnerability-vocabulary + prose words that must not count as "the
# hypothesis names an identifier".  Mirrors the sweep.py stop-word
# convention, extended with the diagnostic families this module covers.
_STOP_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "attacker", "be", "buffer",
    "bounds", "by", "bytes", "call", "can", "causes", "cause", "check",
    "checked", "code", "controlled", "copy", "could", "deref",
    "dereference", "dereferenced", "double", "field", "for", "format",
    "free", "freed", "frees", "from", "function", "garbage", "heap",
    "if", "in", "index", "input", "int", "integer", "into", "is", "it",
    "its", "later", "leading", "leads", "leak", "leaked", "length",
    "may", "memory", "might", "missing", "no", "not", "null", "of",
    "off", "on", "or", "out", "overflow", "pointer", "read", "return",
    "returned", "size", "sized", "stack", "string", "struct", "that",
    "the", "then", "this", "to", "unchecked", "uninitialized",
    "uninitialised", "use", "used", "user", "value", "via", "when",
    "where", "which", "will", "with", "without", "write", "written",
})


def extract_hypothesis_identifiers(
    hypothesis: str,
    source_text: str,
    function_name: str = "",
) -> list[str]:
    """Identifiers the hypothesis names, for diagnostic attribution.

    Backtick/quote-marked identifiers win (the sweep.py convention);
    otherwise prose tokens are kept only when they survive the
    stop-word filter AND appear verbatim as identifiers in the TU
    source — ungrounded prose ("the buffer", "attacker") never blocks
    a confirmation.  The audited function's own name is excluded (the
    line-range check already attributes diagnostics to the function).
    """
    marked = [
        m for m in dict.fromkeys(_MARKED_ID_RE.findall(hypothesis or ""))
        if m.lower() not in _STOP_WORDS and m != function_name
    ]
    if marked:
        return marked

    prose = [
        w for w in dict.fromkeys(_WORD_RE.findall(hypothesis or ""))
        if len(w) > 1 and w.lower() not in _STOP_WORDS and w != function_name
    ]
    return [
        w for w in prose
        if re.search(rf"\b{re.escape(w)}\b", source_text or "")
    ]


def _diag_implicates(
    diag: dict[str, Any],
    identifiers: list[str],
    source_lines: list[str],
) -> bool:
    """Does the diagnostic implicate one of the hypothesis identifiers?

    True when any identifier appears (word-boundary) in the diagnostic
    message OR on the source line the diagnostic points at.  gcc quotes
    names with typographic quotes and clang often names no variable at
    all, so the source-line check carries the clang side.
    """
    if not identifiers:
        return True
    hay = [str(diag.get("message", ""))]
    line = diag.get("line", 0)
    if isinstance(line, int) and 0 < line <= len(source_lines):
        hay.append(source_lines[line - 1])
    for ident in identifiers:
        pat = rf"\b{re.escape(ident)}\b"
        if any(re.search(pat, h) for h in hay):
            return True
    return False


# ---------------------------------------------------------------------------
# Diagnostic parsers — normalised record:
#   {"id": str, "kind": str, "line": int, "file": str, "message": str}
# ---------------------------------------------------------------------------


def _parse_gcc_json(stderr: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(stderr or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    diags = []
    for d in data:
        if not isinstance(d, dict):
            continue
        locs = d.get("locations") or [{}]
        caret = (locs[0] or {}).get("caret", {}) if locs else {}
        diags.append({
            "id": d.get("option") or "",
            "kind": d.get("kind", ""),
            "line": caret.get("line", 0) or 0,
            "file": caret.get("file", "") or "",
            "message": d.get("message", "") or "",
        })
    return diags


def _parse_gcc_sarif(sarif_path: Path) -> list[dict[str, Any]]:
    data = load_json(sarif_path, max_bytes=_MAX_SARIF_BYTES)
    if not isinstance(data, dict):
        return []
    diags = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations") or [{}]
            phys = (locs[0] or {}).get("physicalLocation", {}) if locs else {}
            region = phys.get("region", {})
            diags.append({
                "id": result.get("ruleId", "") or "",
                "kind": result.get("level", "") or "",
                "line": region.get("startLine", 0) or 0,
                "file": phys.get("artifactLocation", {}).get("uri", "") or "",
                "message": (result.get("message", {}) or {}).get("text", "") or "",
            })
    return diags


_CLANG_DIAG_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):\d+:\s+"
    r"(?P<kind>warning|error|fatal error):\s+"
    r"(?P<msg>.*?)(?:\s+\[(?P<id>[^\]]+)\])?\s*$"
)


def _parse_clang_text(stderr: str) -> list[dict[str, Any]]:
    diags = []
    for line in (stderr or "").splitlines():
        m = _CLANG_DIAG_RE.match(line.strip())
        if not m:
            continue
        diags.append({
            "id": m.group("id") or "",
            "kind": m.group("kind"),
            "line": int(m.group("line")),
            "file": m.group("file"),
            "message": m.group("msg"),
        })
    return diags


def _id_matches(diag_id: str, family_ids: tuple[str, ...]) -> bool:
    """Match a diagnostic id against the family's id list.

    gcc appends ``=`` to parameterised options (``-Wstringop-overflow=``);
    clang checker groups match by prefix (``core.uninitialized`` covers
    ``core.uninitialized.UndefReturn``).
    """
    norm = (diag_id or "").rstrip("=")
    for fam in family_ids:
        fam_norm = fam.rstrip("=")
        if norm == fam_norm or norm.startswith(fam_norm + "."):
            return True
    return False


def _same_file(diag_file: str, full_path: Path) -> bool:
    """Is the diagnostic located in the TU we compiled?

    Single-TU compile, so basename equality is the workhorse; absolute
    diagnostic paths additionally require realpath equality so a
    same-named header elsewhere can't masquerade as the TU.
    """
    if not diag_file:
        return False
    if os.path.basename(diag_file) != full_path.name:
        return False
    if os.path.isabs(diag_file):
        try:
            return os.path.realpath(diag_file) == os.path.realpath(full_path)
        except OSError:
            return False
    return True


def _in_range(line: int, line_start: int, line_end: int) -> bool:
    if not line_start or not line_end:
        return True
    return line_start <= line <= line_end


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------


def _error(
    file_path: str, function_name: str, msg: str, *, rule_id: str | None = None,
) -> SweepResult:
    return SweepResult(
        tool="compiler", file_path=file_path, function_name=function_name,
        outcome="error", errors=[msg], rule_id=rule_id,
    )


def _inconclusive(
    file_path: str, function_name: str, msg: str,
    *, details: dict[str, Any] | None = None,
) -> SweepResult:
    return SweepResult(
        tool="compiler", file_path=file_path, function_name=function_name,
        outcome="inconclusive", errors=[msg] if msg else [],
        details=details,
    )


def run_compiler_analyzer_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    cwe: str,
    line_start: int = 0,
    line_end: int = 0,
    out_dir: Path | None = None,
    tu_cache: BoundedMemo[dict[str, Any]] | None = None,
    include_dirs_memo: BoundedMemo[list[str]] | None = None,
) -> SweepResult:
    """Run the compiler's static analyzer on one TU against a hypothesis.

    Args:
        target_path: Root of the (untrusted) target codebase.
        file_path: Relative path to the translation unit.
        function_name: Function being audited.
        hypothesis: Hypothesis text (used for identifier attribution).
        cwe: CWE identifier selecting the diagnostic family.
        line_start: Function start line (diagnostic range filter).
        line_end: Function end line.
        out_dir: Run output directory — scratch space for SARIF output
            and the sandbox's writable surface.  A temp dir is used
            when None.
        tu_cache: Per-run TU analysis cache. The orchestrator passes
            its run's ``config.tu_cache`` so cached compiles live
            exactly one run; None falls back to the module-level
            instance (direct callers, tests via ``_reset_tu_cache``).
        include_dirs_memo: Per-run include-dir walk memo, same
            contract as *tu_cache*.

    Returns:
        SweepResult with tool="compiler".  Outcomes:

        * ``confirmed`` — a diagnostic of the mapped family, located
          inside ``[line_start, line_end]``, implicating an identifier
          the hypothesis names (when it names any).
        * ``refuted`` — analyzer ran cleanly, the family is one it
          covers reliably, and no such diagnostic exists in range.
        * ``inconclusive`` — unmapped family, non-C/C++ TU, compile
          failure (missing generated headers etc.), or a non-reliable
          family with no diagnostic.
        * ``error`` — no analyzer installed, sandbox/subprocess
          failure, analyzer timeout or crash.
    """
    norm_cwe = _normalise_cwe(cwe)
    spec = COMPILER_CWE_MAP.get(norm_cwe)
    if spec is None:
        return _inconclusive(
            file_path, function_name,
            f"no compiler diagnostic mapping for {cwe or '<no CWE>'}",
        )

    full_path = safe_join(target_path, file_path)
    if full_path is None:
        return _error(
            file_path, function_name, f"path escapes target: {file_path}",
        )
    if not full_path.is_file():
        return _error(
            file_path, function_name, f"file not found: {full_path}",
        )

    suffix = full_path.suffix
    is_c = suffix in _C_SUFFIXES
    is_cxx = suffix in _CXX_SUFFIXES
    if not (is_c or is_cxx):
        return _inconclusive(
            file_path, function_name,
            f"not a C/C++ translation unit: {suffix or '<no suffix>'}",
        )

    gcc = _gcc_analyzer() if is_c else None  # gcc -fanalyzer is C-only
    clang = _clang_path()
    if gcc is None and clang is None:
        if is_cxx and _gcc_analyzer() is not None:
            return _inconclusive(
                file_path, function_name,
                "C++ TU needs clang --analyze (gcc -fanalyzer is "
                "unsupported for C++); clang not installed",
            )
        return _error(
            file_path, function_name,
            "compiler static analyzer not installed "
            "(need gcc >= 10 with -fanalyzer, or clang)",
        )

    include_dirs = _cached_include_dirs(
        target_path, full_path.parent, memo=include_dirs_memo,
    )
    include_flags = [f"-I{d}" for d in include_dirs]

    if gcc is not None:
        gcc_path, mode = gcc
        compiler_name = "gcc"
        cmd = [
            gcc_path, "-fanalyzer", *spec.gcc_flags,
            f"-fdiagnostics-format={mode}",
            *include_flags, "-c", str(full_path), "-o", os.devnull,
        ]
    else:
        compiler_name = "clang"
        mode = spec.clang_engine
        if spec.clang_engine == "analyze":
            cmd = [
                clang, "--analyze", "--analyzer-output", "text",
                *include_flags, str(full_path),
            ]
        else:
            cmd = [
                clang, "-fsyntax-only", *spec.clang_flags,
                *include_flags, str(full_path),
            ]

    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        # Constraint #1: the compiler parses hostile source — never
        # run it unsandboxed.
        return _error(
            file_path, function_name,
            "core.sandbox unavailable — refusing to run the compiler "
            "on untrusted source without isolation",
        )

    def _run_tu_analysis() -> dict[str, Any]:
        """One sandboxed analyzer run over the whole TU, parsed.

        The record is invocation-shaped, not hypothesis-shaped: every
        per-hypothesis concern (family filter, line range, identifier
        attribution, suppression witness) happens on the parsed
        diagnostics afterwards, so the same record serves every
        hypothesis sharing the cache key.
        """
        scratch_root = str(out_dir) if out_dir else None
        with scratch_dir("compiler_sweep_", dir=scratch_root) as workdir:
            proc = sandbox_run(
                cmd,
                block_network=True,
                target=str(target_path),
                output=str(workdir),
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT_S,
                caller_label="audit-compiler-sweep",
            )
            if compiler_name == "gcc" and mode == "sarif-file":
                diags = _parse_gcc_sarif(workdir / f"{full_path.name}.sarif")
            elif compiler_name == "gcc":
                diags = _parse_gcc_json(proc.stderr or "")
            else:
                diags = _parse_clang_text(proc.stderr or "")
            if proc.returncode < 0:
                # Signal-killed compile (OOM killer, sandbox kill):
                # transient environment pressure, not a property of
                # the TU — caching it would kill the compiler channel
                # for this TU for the cache's whole lifetime, exactly
                # while parallel passes raise memory pressure. Raise
                # so the memo caches nothing (same contract as
                # TimeoutExpired) and the caller reports an error.
                raise _AnalyzerSignalKilled(-proc.returncode)
            return {
                "returncode": proc.returncode,
                "diags": diags,
                "raw": (proc.stderr or "")[:_MAX_RAW_OUTPUT],
            }

    try:
        # Completed runs are cached whatever the ORDINARY exit code (a
        # broken compile is deterministic too, and re-paying it per
        # hypothesis is the dominant waste on ungeneratable-header
        # targets); exceptions propagate uncached — timeouts,
        # invocation failures, and signal kills (negative returncode)
        # are transient and must stay retryable.
        _cache = tu_cache if tu_cache is not None else _tu_cache
        record, _cached = _cache.get_or_compute(
            _tu_cache_key(cmd, full_path), _run_tu_analysis,
        )
    except subprocess.TimeoutExpired:
        return _error(
            file_path, function_name,
            f"analyzer timed out ({_COMPILE_TIMEOUT_S}s)",
            rule_id=f"compiler:{norm_cwe.lower()}",
        )
    except _AnalyzerSignalKilled as exc:
        return _error(
            file_path, function_name,
            f"analyzer killed by signal {exc.signal}",
            rule_id=f"compiler:{norm_cwe.lower()}",
        )
    except (subprocess.SubprocessError, OSError, ValueError,
            TypeError) as exc:
        return _error(
            file_path, function_name,
            f"analyzer invocation failed: {exc}",
            rule_id=f"compiler:{norm_cwe.lower()}",
        )

    # The cached record is shared by every hypothesis on this TU —
    # hand out copies of the diagnostics (isolation parity with the
    # CodeQL memo) so a consumer mutating its view cannot corrupt
    # another hypothesis's.
    diags = copy.deepcopy(record["diags"])
    returncode: int = record["returncode"]
    raw: str = record["raw"]

    details: dict[str, Any] = {
        "compiler": compiler_name,
        "mode": mode,
        "cwe": norm_cwe,
        "diagnostics_total": len(diags),
    }

    if returncode != 0:
        # Compile failure (missing generated headers, dialect gaps,
        # ICE). The analyzer never saw well-formed code — silence
        # here proves nothing. NEVER refute from a broken compile.
        error_msgs = [
            d["message"] for d in diags
            if "error" in str(d.get("kind", ""))
        ][:3]
        summary = "; ".join(error_msgs) or f"exit code {returncode}"
        result = _inconclusive(
            file_path, function_name,
            f"compile failed — cannot analyse: {summary}",
            details=details,
        )
        result.raw_output = raw
        return result

    got_src = read_text_capped(full_path)
    source_text = "" if got_src is None else got_src[0]
    source_lines = source_text.split("\n")
    identifiers = extract_hypothesis_identifiers(
        hypothesis, source_text, function_name,
    )
    details["hypothesis_identifiers"] = identifiers

    family_in_range = [
        d for d in diags
        if _id_matches(d["id"], spec.gcc_ids + spec.clang_ids)
        and (
            compiler_name == "gcc"
            or not spec.clang_message_re
            or re.search(spec.clang_message_re, d["message"], re.IGNORECASE)
        )
        and _same_file(d["file"], full_path)
        and _in_range(d["line"], line_start, line_end)
    ]
    attributed = [
        d for d in family_in_range
        if _diag_implicates(d, identifiers, source_lines)
    ]
    details["family_in_range"] = len(family_in_range)
    details["attributed"] = len(attributed)

    if attributed:
        matches = [
            {
                "line": d["line"],
                "rule_id": d["id"],
                "message": d["message"],
                "file": file_path,
            }
            for d in attributed
        ]
        return SweepResult(
            tool="compiler",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=matches,
            rule_id=f"compiler:{attributed[0]['id'] or norm_cwe.lower()}",
            raw_output=raw,
            details=details,
        )

    if family_in_range:
        # Diagnostics of the right family exist in range but none
        # implicate the identifier the hypothesis names — do not
        # confirm on someone else's bug, do not refute either.
        details["unattributed"] = [
            {"line": d["line"], "id": d["id"], "message": d["message"]}
            for d in family_in_range[:5]
        ]
        result = _inconclusive(
            file_path, function_name,
            "family diagnostics in range do not implicate the "
            "hypothesised identifier(s)",
            details=details,
        )
        result.raw_output = raw
        return result

    if spec.reliable:
        # Refutation = analyzer silence on an ATTACKER-AUTHORED
        # TU. Silence is forgeable: '#pragma GCC diagnostic
        # ignored "-Wanalyzer-use-after-free"' suppresses the
        # family diagnostic with rc 0, and '#ifndef
        # __clang_analyzer__' compiles a clean variant under
        # clang --analyze. Any suppression construct in the TU
        # fails toward "unknown" — never toward refuted.
        suppression = _suppression_witness(source_text)
        if not suppression:
            # "In the TU" means the WHOLE translation unit: a
            # diagnostic pragma in an included repo header persists
            # past its #include into the includer's code, so the
            # closure must be vetted before silence can refute. The
            # vet runs the compiler's own preprocessor — a spelling
            # the -E output does not carry cannot act on the
            # compile either.
            pp_cmd = [cmd[0], "-E", *include_flags, str(full_path)]
            if compiler_name == "clang" and mode == "analyze":
                # Match the analyzer's macro environment so
                # conditional includes resolve the same way they do
                # under --analyze.
                pp_cmd.insert(2, "-D__clang_analyzer__=1")

            def _run_closure_vet() -> dict[str, Any]:
                # The cached record is the VERDICT, never the
                # preprocessed text: -E output runs to megabytes per
                # TU and the memo holds up to _TU_CACHE_MAX_ENTRIES
                # of them for the run's lifetime.
                scratch_root = str(out_dir) if out_dir else None
                with scratch_dir(
                    "compiler_pp_", dir=scratch_root,
                ) as ppdir:
                    proc = sandbox_run(
                        pp_cmd,
                        block_network=True,
                        target=str(target_path),
                        output=str(ppdir),
                        cwd=str(ppdir),
                        capture_output=True,
                        text=True,
                        timeout=_COMPILE_TIMEOUT_S,
                        caller_label="audit-compiler-sweep",
                    )
                    if proc.returncode < 0:
                        raise _AnalyzerSignalKilled(-proc.returncode)
                if proc.returncode != 0:
                    return {
                        "witness": "",
                        "vet_failure": (
                            f"preprocessor exited {proc.returncode}"
                        ),
                    }
                witness, failure = _closure_suppression_witness(
                    (proc.stdout or "")[:_MAX_PP_TEXT_BYTES + 1],
                    target_path, full_path,
                )
                return {"witness": witness, "vet_failure": failure}

            vet_failure = ""
            try:
                vet_record, _pp_cached = _cache.get_or_compute(
                    _tu_cache_key(pp_cmd, full_path), _run_closure_vet,
                )
                suppression = vet_record["witness"]
                vet_failure = vet_record["vet_failure"]
            except (subprocess.TimeoutExpired, _AnalyzerSignalKilled,
                    subprocess.SubprocessError, OSError, ValueError,
                    TypeError):
                vet_failure = "preprocessor run failed"
            if vet_failure and not suppression:
                details["closure_unvetted"] = vet_failure
                result = _inconclusive(
                    file_path, function_name,
                    f"include closure could not be vetted "
                    f"({vet_failure}) — analyzer silence is not "
                    f"evidence; cannot refute",
                    details=details,
                )
                result.raw_output = raw
                return result
        if suppression:
            details["suppression_witness"] = suppression
            result = _inconclusive(
                file_path, function_name,
                f"diagnostic-suppression construct in the TU "
                f"({suppression}) — analyzer silence is not "
                f"evidence; cannot refute",
                details=details,
            )
            result.raw_output = raw
            return result
        return SweepResult(
            tool="compiler",
            file_path=file_path,
            function_name=function_name,
            outcome="refuted",
            rule_id=f"compiler:{norm_cwe.lower()}",
            raw_output=raw,
            details=details,
        )

    result = _inconclusive(
        file_path, function_name,
        f"{norm_cwe} is confirm-only for the compiler analyzer; "
        "no diagnostic does not refute",
        details=details,
    )
    result.raw_output = raw
    return result


# Public probe aliases (appended so cross-module consumers — the
# prefilter ledger's corroboration sampler — need no private names).
gcc_analyzer_available = _gcc_analyzer
clang_path_available = _clang_path
