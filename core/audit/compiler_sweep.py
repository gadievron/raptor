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

import bisect
import contextvars
import copy
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from array import array
from dataclasses import dataclass
from pathlib import Path

from core.source import open_regular, read_text_capped
from core.source.lines import split_lines
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

# Loop-bound family: the analyzer's infinite-loop diagnostic
# (gcc >= 14) and clang's -Wloop-analysis (loop variable not updated /
# suspicious condition) fire only on locally-provable shapes —
# confirm-only (silence proves nothing about data-dependent loop
# bounds). Shared by CWE-835 (unreachable exit condition) and its
# parent CWE-834 (excessive iteration).
_LOOP_SPEC = FamilySpec(
    gcc_ids=("-Wanalyzer-infinite-loop",),
    gcc_flags=(),
    clang_engine="warning",
    clang_ids=("-Wloop-analysis",),
    clang_flags=("-Wloop-analysis",),
    clang_message_re="",
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
    "CWE-834": _LOOP_SPEC,
    "CWE-835": _LOOP_SPEC,
    # Uncontrolled recursion: -Winfinite-recursion (gcc >= 12, clang)
    # fires only when every path through a function provably calls
    # itself — confirm-only (silence proves nothing about
    # data-dependent recursion depth, and an older gcc that rejects
    # the flag degrades this family to inconclusive, never a wrong
    # verdict).
    "CWE-674": FamilySpec(
        gcc_ids=("-Winfinite-recursion",),
        gcc_flags=("-Winfinite-recursion",),
        clang_engine="warning",
        clang_ids=("-Winfinite-recursion",),
        clang_flags=("-Winfinite-recursion",),
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
        # Whole-file bytes BY DESIGN (a capped hash would equate TUs
        # differing past the cap and serve a stale memo); the open is
        # the hardened one, so FIFO/symlink plants refuse.
        fh = open_regular(full_path, "rb")
        if fh is None:
            return None
        with fh:
            tu_hash = hashlib.sha256(fh.read()).hexdigest()
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


def _base_suppression_witness(source_text: str) -> str:
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


def _base_closure_suppression_witness(
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
        w = _base_suppression_witness(text)
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


# ---------------------------------------------------------------------------
# Additive suppression checks (monotonic over the base witness above)
# ---------------------------------------------------------------------------
# The two functions the callers use are the BASE implementation (kept
# verbatim above as ``_base_suppression_witness`` /
# ``_base_closure_suppression_witness``) OR a set of additive checks.
# The additive checks may only ADD a witness or a vet failure — they
# never run when the base already found one and can never clear one —
# so for the sweep every change moves refuted → inconclusive (the
# FN-safe direction), never the other way. They are deliberately
# simple, line-local and linear:
#
# * line splices (backslash-newline) are joined and the base re-run;
# * an attribute-list opener — ``[[`` / ``<:<:`` / ``<:[`` / ``[<:``
#   or ``__attribute[__]((`` — followed later on the same line, or on
#   one of the next ``_ADD_ATTR_CARRY_LINES`` (8) lines while the list
#   is still open, by the word ``suppress`` / ``__suppress__``, on the
#   sanitized view for repo files and on the raw -E text for the
#   closure. Lists this line-local check misses (a nested ``))`` /
#   ``]]`` in an argument, a ``suppress`` more than 8 lines on) are
#   covered by layer 2 (``_attr_token_scan``) below;
# * directives after any C directive whitespace (space, tab, FF, VT,
#   comments) and the ``%:`` digraph: system-header / diagnostic-ignore
#   pragmas and flag-3 linemarkers are witnesses; a ``#line`` /
#   linemarker whose name is not a provable plain literal (macro
#   operand, invalid escape — names are decoded with C escape
#   semantics, ``\x`` taking every hex digit) or names a path outside
#   the tree fails the vet;
# * in -E output, linemarker names are decoded the same way; a
#   column-0 linemarker that does not parse fails the vet; a flagless
#   (rename) marker that moves a REPO region to a path outside the
#   tree fails the vet; missing/empty output fails the vet.
#
# Accepted false positives (each only adds a witness or a vet failure):
# ``suppress`` as an attribute ARGUMENT or inside a string on such a
# line (``cleanup(suppress)``, ``deprecated("… suppress …")``), and a
# C++ raw string whose line starts ``# <digit>`` in -E output (reads
# as an unparseable linemarker → unvetted). Inherited from the base
# (unchanged here): ANY ``_Pragma(`` is a witness, including portability
# macros such as ``_Pragma("inline=forced")``. All only withhold a
# refutation / annotate a TU.
#
# The witness remains ADVISORY and incomplete: it is a text scan, so a
# suppression the preprocessor assembles without leaving text in the
# sources or the -E output (``__clang_analyzer__`` built by token
# pasting in ``#if``), clang lexing beyond layer 2's model, nameless or
# in-tree ``#line`` relabelling (the sweep may still refute there; the
# scan keeps the finding), and a self-include with
# ``_Pragma("clang system_header")`` are not detected. The gcc
# ``-fanalyzer`` path is untested. Cost: each check is a linear pass over
# size-capped input; name resolution is bounded by the limits below.

_ADD_SPLICE_RE = re.compile(r"\\[ \t\f\v]*\r?\n")
_ADD_ATTR_OPEN_RE = re.compile(
    r"(?:\[|<:)[ \t\f\v]*(?:\[|<:)"
    r"|\b__attribute(?:__)?[ \t\f\v]*\([ \t\f\v]*\(",
)
_ADD_ATTR_CLOSE_RE = re.compile(r"(?:\]|:>)[ \t\f\v]*(?:\]|:>)|\)[ \t\f\v]*\)")
_ADD_SUPPRESS_RE = re.compile(r"\b(?:__)?suppress(?:__)?\b")
# Applied per line with .match — never MULTILINE over whole text.
_ADD_DIRECTIVE_RE = re.compile(r"[ \t\f\v]*(?:#|%:)[ \t\f\v]*(pragma\b|line\b|[0-9])")
_ADD_PRAGMA_RE = re.compile(
    r"(?:GCC|clang)[ \t\f\v]+(?:diagnostic[ \t\f\v]+ignored|system_header)\b",
)
_ADD_ATTR_CARRY_LINES = 8
_DIRECTIVE_WS = " \t\f\v"
_ASCII_DIGITS = frozenset("0123456789")
_C_SIMPLE_ESCAPES = {
    "'": 0x27, '"': 0x22, "?": 0x3F, "\\": 0x5C, "a": 0x07, "b": 0x08,
    "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09, "v": 0x0B,
    "e": 0x1B, "E": 0x1B,  # GNU extension, accepted by gcc and clang
}
_HEX = frozenset("0123456789abcdefABCDEF")
_OCT = frozenset("01234567")


def _decode_c_string(token: str) -> str | None:
    """Decode a plain ``"..."`` literal with C escape semantics, or None
    when it is not a terminated plain literal or uses an escape this
    decoder cannot prove (UCNs, unknown escapes, values over 0xFF, NUL)."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        return None
    body = token[1:-1]
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == '"' or c == "\n":
            return None
        if c != "\\":
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        i += 1
        if i >= n:
            return None
        c = body[i]
        if c in _C_SIMPLE_ESCAPES:
            out.append(_C_SIMPLE_ESCAPES[c])
            i += 1
        elif c in _OCT:
            j = i
            while j < n and j < i + 3 and body[j] in _OCT:
                j += 1
            value = int(body[i:j], 8)
            if value > 0xFF:
                return None
            out.append(value)
            i = j
        elif c == "x":
            j = i + 1
            while j < n and body[j] in _HEX:
                j += 1
            if j == i + 1:
                return None
            value = int(body[i + 1:j], 16)
            if value > 0xFF:
                return None
            out.append(value)
            i = j
        else:
            return None
    if 0 in out:
        return None
    return os.fsdecode(bytes(out))


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in _DIRECTIVE_WS:
        i += 1
    return i


def _parse_marker_operands(
    s: str, flags_view: str | None = None,
) -> tuple[str, list[str]] | None:
    """Operands of a linemarker / ``#line`` starting at ``line`` or the
    line number. ``("", [])`` = nameless; None = not provable."""
    i = 0
    if s.startswith("line"):
        i = _skip_ws(s, 4)
    j = i
    while j < len(s) and s[j] in _ASCII_DIGITS:
        j += 1
    if j == i:
        return None
    i = _skip_ws(s, j)
    if i >= len(s) or not s[i:].strip(_DIRECTIVE_WS + "\r"):
        return "", []
    if s[i] != '"':
        return None
    j = i + 1
    while j < len(s) and s[j] != '"':
        j += 2 if s[j] == "\\" else 1
    if j >= len(s):
        return None
    name = _decode_c_string(s[i:j + 1])
    if name is None:
        return None
    tail = (flags_view if flags_view is not None else s)[j + 1:]
    flags = tail.split()
    if not all(f and set(f) <= _ASCII_DIGITS for f in flags):
        return None
    return name, flags


def _add_repo_authored(name: str, target_resolved: Path) -> bool:
    """``_repo_authored`` with the resolution done by the bounded
    resolver (same answer whenever no limit trips)."""
    if not name or name.startswith("<"):
        return False
    p = Path(name)
    if not p.is_absolute():
        return True
    try:
        return _resolve_bounded(p).is_relative_to(target_resolved)
    except (OSError, ValueError):  # e.g. embedded NUL — unattributable
        return True


def _attr_line_witness(line: str, carry: int) -> tuple[str, int]:
    """``(witness, carry)`` for one line: carry > 0 means an attribute
    list opened on an earlier line is still open."""
    if carry:
        start = scan_from = 0
    else:
        m = _ADD_ATTR_OPEN_RE.search(line)
        if not m:
            return "", 0
        start, scan_from = m.start(), m.end()
    s = _ADD_SUPPRESS_RE.search(line, scan_from)
    if s:
        return " ".join(line[start:s.end()].split())[:200], 0
    if _ADD_ATTR_CLOSE_RE.search(line, scan_from):
        return "", 0
    return "", (carry - 1 if carry else _ADD_ATTR_CARRY_LINES)


@dataclass
class _SrcDirectives:
    witness: str
    # (decoded name, or None when unprovable; directive text)
    linemarkers: list[tuple[str | None, str]]


def _additive_file_scan(source_text: str) -> _SrcDirectives:
    """Additive witness + source linemarkers for one repo file."""
    from .source_view import sanitized_view
    spliced = _ADD_SPLICE_RE.sub("", source_text)
    if spliced != source_text:
        w = _base_suppression_witness(spliced)
        if w:
            return _SrcDirectives(w, [])
    view = sanitized_view(spliced, "tu.c")
    # line-model: \n-only split pairs raw and sanitized lines column for
    # column; each line is only prefix-matched (.match) and its operands
    # parsed with \r stripped, so a CRLF trailing \r cannot change a result.
    vlines = view.split("\n")  # line-model: see above (column-aligned pair)
    rlines = spliced.split("\n")  # line-model: see above (column-aligned pair)
    if len(vlines) != len(rlines):  # defensive: keep columns aligned
        rlines = vlines
    witness = ""
    carry = 0
    linemarkers: list[tuple[str | None, str]] = []
    for vline, rline in zip(vlines, rlines):
        if not witness:
            w, carry = _attr_line_witness(vline, carry)
            if w:
                witness = w
        m = _ADD_DIRECTIVE_RE.match(vline)
        if not m:
            continue
        text = vline[m.start():].strip()[:200]
        if m.group(1) == "pragma":
            rest = vline[m.end():].lstrip(_DIRECTIVE_WS)
            if not witness and _ADD_PRAGMA_RE.match(rest):
                witness = text
            continue
        parsed = _parse_marker_operands(
            rline[m.start(1):], flags_view=vline[m.start(1):],
        )
        if parsed is None:
            linemarkers.append((None, rline[m.start():].strip()[:200]))
            continue
        name, flags = parsed
        linemarkers.append((name, rline[m.start():].strip()[:200]))
        if not witness and "3" in flags:
            witness = rline[m.start():].strip()[:200]
    return _SrcDirectives(witness, linemarkers)


# ---------------------------------------------------------------------------
# Layer 2: further additive checks (presumed names, attribute lists)
# ---------------------------------------------------------------------------
# The composite witness is base, else layer 1 (the checks above), else
# layer 2. A non-clean base or layer-1 result is returned unchanged, so
# both earlier floors hold by construction; layer 2 can only ADD a witness
# or a vet failure (for the sweep: refuted -> inconclusive). That property
# keeps earlier results compatible; it does NOT by itself make layer 2
# detect what it promises — the direct layer-2 tests do that.
#
# Presumed names. A ``#line`` / linemarker file name is a PRESUMED
# filename: a label clang reports, not a path clang resolves. Layer 2
# applies compiler-scan's consumer policy (``_rel_under_target`` resolves
# a relative diagnostic path against the TU directory and drops it when
# it lands outside the target): a relative name is resolved against the
# TU directory, an absolute one is checked as is, and a name that cannot
# be resolved, or that looks like a Windows path (conservative
# Windows-like-name policy: a drive prefix or ANY backslash — backslashes
# are legal POSIX filename characters, so this may over-report), fails
# the vet instead of counting as "in tree". An include-ENTRY marker
# (flag 1) with a RELATIVE name means the compiler was given a relative
# TU or ``-I`` path; such a name is resolved against the compiler's cwd,
# not the vetting process's, so its provenance is unverifiable and it
# fails the vet.
#
# Attribute lists (``_attr_token_scan``). A single forward scan over
# one master regex: string / char literals (any encoding prefix; they end
# at an unescaped quote or at a newline, as in C), ``//`` and ``/* */``
# comments and C++ raw strings (``R"d( … )d"``; raw strings do not nest,
# only the outer ``)d"`` terminates) are skipped; a raw-string prefix only
# counts at a token start (identifiers include every non-ASCII code point,
# so ``a<U+0301>R"("`` is an identifier followed by a plain string). In
# -E text column-0 ``#`` lines are directives and are skipped; in raw
# source, directive bodies (``#define``) are scanned. Openers: ``[[``,
# ``[<:``, ``<:[``, ``<:<:`` (an ambiguous ``<::`` is read as an opener —
# the conservative reading) and ``__attribute[__]((``. Inside a list a
# typed stack matches ``( [ { <: <%`` with their closers (``]``/``:>`` and
# ``}``/``%>`` interchangeable); the list ends when the stack empties and
# scanning resumes for further openers. The identifier ``suppress`` /
# ``__suppress__`` ANYWHERE in a list (arguments included) is a witness.
# Input the scan cannot verify is reported as a witness, never as absence:
# a mismatched closer, a list still open at end of input, nesting deeper
# than ``_L2_MAX_DEPTH``, or a literal / comment that runs to end of input
# while a list is open or with an opener in the swallowed text. Trigraphs
# (enabled in clang only by ``-trigraphs`` / strict ISO modes) are handled
# conservatively: if the text contains any trigraph, it is scanned a
# second time with trigraphs translated and both readings count.
#
# Linear time. Every master-regex alternative is anchored to its first
# character; a failed attempt at a position costs O(1) except the opener
# alternatives, whose ``[ \t\f\v\n]*`` run can only be re-scanned from the
# single ``[`` / ``<:`` / ``(`` immediately before it, so each character
# is examined O(1) times by failed attempts. A matched literal / comment
# is skipped by one forward regex match or ``str.find`` and the scan jumps
# past it; a raw-string delimiter is bounded at 16 characters; a runaway
# literal ends the scan. The stack is bounded by ``_L2_MAX_DEPTH``; hits
# are yielded lazily (O(1) memory); witness snippets are sliced to at
# most 400 characters. Inputs are already capped by the callers
# (``_MAX_CLOSURE_FILE_BYTES`` per file, ``_MAX_PP_TEXT_BYTES`` per -E
# text), and a capped / truncated read fails the vet (base) — layer 2
# repeats that verdict rather than scanning a partial file.

_L2_MAX_DEPTH = 4096
_L2_UNICODE_DIRECTIVE_RE = re.compile(
    r"[ \t\f\v]*[  　][ \t\f\v  　]*"
    r"(?:#|%:)[ \t\f\v]*(pragma\b|line\b|[0-9])",
)
_WINDOWS_LIKE_NAME_RE = re.compile(r"^[A-Za-z]:|\\")
_TOK_RE = re.compile(
    r"(?P<dir>^\#[^\n]*)"
    r"|(?P<lc>//)|(?P<bc>/\*)"
    r"|(?P<raw>(?:u8|[uUL])?R\")"
    r"|(?P<str>(?:u8|[uUL])?\")|(?P<chr>(?:u8|[uUL])?')"
    r"|(?P<open>\[[ \t\f\v\n]*(?:\[|<:)|<:[ \t\f\v\n]*(?:<:|\[)"
    r"|\b__attribute(?:__)?[ \t\f\v\n]*\([ \t\f\v\n]*\()"
    r"|(?P<sup>\b(?:__)?suppress(?:__)?\b)"
    r"|(?P<dig><:(?!:(?![:>]))|:>|<%|%>)"
    r"|(?P<del>[()\[\]{}])"
    r"|(?P<id>[A-Za-z_$0-9\x80-\U0010ffff]+(?:'[A-Za-z0-9_]+)*)",
    re.MULTILINE,
)
_STR_BODY_RE = re.compile(r'(?:[^"\\\n]|\\.)*"?')
_CHR_BODY_RE = re.compile(r"(?:[^'\\\n]|\\.)*'?")
_RAW_DELIM_RE = re.compile(r'([^ ()\\\t\v\f\n"]{0,16})\(')
_L2_CLOSER = {"(": ")", "[": "]", "{": "}", "<:": "]", "<%": "}"}
_L2_CLOSE_NORM = {")": ")", "]": "]", ":>": "]", "}": "}", "%>": "}"}
_TRIGRAPHS = {"=": "#", "(": "[", ")": "]", "/": "\\", "'": "^",
              "<": "{", ">": "}", "!": "|", "-": "~"}
_TRIGRAPH_RE = re.compile(r"\?\?([=()/'<>!-])")


def _attr_token_scan(text: str, *, preprocessed: bool):
    """Yield ``(offset, witness)`` for every attribute list in *text*
    that names ``suppress`` or cannot be verified. Trigraphs, when
    present, are scanned under both readings; offsets are always
    offsets into *text*."""
    yield from _attr_token_scan_one(text, preprocessed=preprocessed)
    if _TRIGRAPH_RE.search(text):
        # Sparse offset map: the translated offset of each trigraph's
        # replacement character (one entry per trigraph). A translated
        # offset ``at`` lies after ``k`` replacements, k = the number of
        # entries < at, and each one shortened the text by two.
        shifts = array("q")

        def translate(m: re.Match) -> str:
            shifts.append(m.start() - 2 * len(shifts))
            return _TRIGRAPHS[m.group(1)]

        translated = _TRIGRAPH_RE.sub(translate, text)
        for at, w in _attr_token_scan_one(translated, preprocessed=preprocessed):
            yield at + 2 * bisect.bisect_left(shifts, at), w


def _witness_snippet(text: str, start: int, end: int, preprocessed: bool) -> str:
    """Up to 400 characters of list text from *start*, whitespace
    collapsed. In -E text, column-0 directive lines (the scanner's
    ``dir`` token: linemarkers, which carry toolchain and host paths, and
    surviving pragmas) are not list text: each becomes one space, before
    the window is cut."""
    if not preprocessed:
        return " ".join(text[start:min(end, start + 400)].split())
    out: list[str] = []
    kept, pos = 0, start
    while pos < end and kept < 400:
        nl = text.find("\n", pos, end)
        stop = end if nl < 0 else nl
        if pos > start and text.startswith("#", pos):
            out.append(" ")
        else:
            seg = text[pos:min(stop, pos + 400 - kept)]
            out.append(seg)
            kept += len(seg)
        out.append("\n")
        pos = stop + 1
    return " ".join("".join(out).split())


def _attr_token_scan_one(text: str, *, preprocessed: bool):
    n = len(text)
    pos = 0
    stack: list[str] | None = None
    list_start = 0

    def hit(at: int, end: int, why: str = "") -> tuple[int, str]:
        snippet = _witness_snippet(text, list_start, end, preprocessed)
        return at, snippet[:200] + (f" … ({why})" if why else "")

    while pos < n:
        m = _TOK_RE.search(text, pos)
        if m is None:
            break
        kind = m.lastgroup
        start, end = m.start(), m.end()
        if kind == "dir":
            pos = end if preprocessed else start + 1
            continue
        if kind in ("lc", "bc", "raw", "str", "chr"):
            runaway = False
            if kind == "lc":
                nl = text.find("\n", end)
                stop = n if nl < 0 else nl
            elif kind == "bc":
                close = text.find("*/", end)
                stop, runaway = (n, True) if close < 0 else (close + 2, False)
            elif kind == "raw":
                dm = _RAW_DELIM_RE.match(text, end)
                if dm is None:            # `R` then an ordinary string
                    stop = _STR_BODY_RE.match(text, end).end()
                else:
                    term = ")" + dm.group(1) + '"'
                    close = text.find(term, dm.end())
                    stop, runaway = ((n, True) if close < 0
                                     else (close + len(term), False))
            else:
                body = _STR_BODY_RE if kind == "str" else _CHR_BODY_RE
                stop = body.match(text, end).end()
            if runaway:
                if stack is None and _ADD_ATTR_OPEN_RE.search(text, end) is None:
                    return
                if stack is None:
                    list_start = start
                yield hit(start, start + 200,
                          "unverifiable: literal or comment runs to end of input")
                return
            pos = max(stop, end)
            continue
        pos = end
        if stack is None:
            if kind == "open":
                stack = [")", ")"] if m.group(0).endswith("(") else ["]", "]"]
                list_start = start
            continue
        if kind == "sup":
            yield hit(start, end)
            stack = None
            continue
        if kind == "open":
            stack.extend([")", ")"] if m.group(0).endswith("(") else ["]", "]"])
        elif kind in ("del", "dig"):
            tok = m.group(0)
            if tok in _L2_CLOSER:
                stack.append(_L2_CLOSER[tok])
            elif not stack or stack[-1] != _L2_CLOSE_NORM[tok]:
                yield hit(start, end, "unbalanced attribute list")
                stack = None
                continue
            else:
                stack.pop()
                if not stack:
                    stack = None
                continue
        else:
            continue
        if len(stack) > _L2_MAX_DEPTH:
            yield hit(start, end, "attribute list nesting exceeds the scan limit")
            stack = None
    if stack is not None:
        yield hit(n, n, "attribute list still open at end of input")


def _presumed_name_outside(name: str, tu_dir: Path, target_resolved: Path) -> str:
    """Why a PRESUMED file name leaves the tree under the consumer
    policy (relative = TU-directory relative), or ''."""
    if not name or name.startswith("<"):
        return ""
    if _WINDOWS_LIKE_NAME_RE.search(name):
        return f"names a Windows-like path {name!r}"
    p = Path(name)
    try:
        real = _resolve_bounded(p if p.is_absolute() else tu_dir / p)
    except (OSError, ValueError, RuntimeError):
        return f"names unresolvable path {name!r}"
    if real.is_relative_to(target_resolved):
        return ""
    return f"re-attributes lines to {name}"


@dataclass
class _L2File:
    witness: str
    # (decoded presumed name, or None when unprovable; directive text)
    linemarkers: list[tuple[str | None, str]]


def _l2_file_scan(source_text: str) -> _L2File:
    """Layer-2 witness and source linemarkers of one repo file."""
    from .source_view import sanitized_view
    spliced = _ADD_SPLICE_RE.sub("", source_text)
    witness = next((w for _at, w in _attr_token_scan(
        spliced, preprocessed=False)), "")
    view = sanitized_view(spliced, "tu.c")
    vlines, rlines = split_lines(view), split_lines(spliced)
    if len(vlines) != len(rlines):
        rlines = vlines
    markers: list[tuple[str | None, str]] = []
    for vline, rline in zip(vlines, rlines):
        m = _ADD_DIRECTIVE_RE.match(vline) or _L2_UNICODE_DIRECTIVE_RE.match(vline)
        if not m:
            continue
        text = rline[m.start():].strip()[:200]
        if m.group(1) == "pragma":
            if not witness and _ADD_PRAGMA_RE.match(
                    vline[m.end():].lstrip(_DIRECTIVE_WS + "  　")):
                witness = text
            continue
        parsed = _parse_marker_operands(
            rline[m.start(1):], flags_view=vline[m.start(1):])
        if parsed is None:
            markers.append((None, text))
            continue
        markers.append((parsed[0], text))
        if not witness and "3" in parsed[1]:
            witness = text
    return _L2File(witness, markers)


# Linemarker-name classification, shared by the layer-1 and layer-2 walks.
# Inputs: ``_add_repo_authored(name, target_resolved)`` depends on the name,
# the resolved target and the filesystem; ``_presumed_name_outside(name,
# tu_dir, target_resolved)`` on the name, the TU directory, the resolved
# target and the filesystem. Within one walk the target and TU directory are
# fixed, so each predicate is memoised per call keyed by the exact name, in a
# SEPARATE store per predicate. Stability policy: the tree is assumed static
# during one scan; a filesystem change during a call may be seen stale, in
# either direction; nothing is cached across calls.
#
# Quota: every DISTINCT name string that reaches either predicate in one
# call counts once — marker names, the current file's name, the TU's own
# name, names in repo-file ``#line`` directives and the owners of reported
# attribute lists. The quota is checked before any resolution or cache
# insertion; repeated names cost nothing. Over the quota the walk stops and
# the closure is reported "not vetted" (sweep: inconclusive). Legitimate
# TUs measured: at most 813 distinct names (a C++ TU including ten
# standard-library headers); brotli, Go cgo and the repo's own C fixtures
# at most 251.
#
# Resolution work: the quota bounds how many names are classified, not the
# work per name. Names are resolved by ``_bounded_realpath`` (the POSIX
# realpath semantics of Python 3.13+), which charges every ``os.lstat``,
# every ``os.readlink`` and every component of a spliced symlink target,
# BEFORE doing it, to ONE per-TU budget (``_MAX_RESOLVE_OPS_PER_TU``
# operations) shared by the layer-1 and layer-2 walks of that TU, and
# follows at most ``_MAX_SYMLINK_HOPS`` links per name (the next one trips).
# Every name about to be resolved (a memo miss; repeats cost nothing) is
# first checked against a per-name limit: ``_MAX_RESOLVED_NAME_CHARS``
# characters of name and ``_MAX_RESOLVED_NAME_PARTS`` components of the path
# resolved (TU directory included for a relative name). The target root is
# resolved by the same function, so containment compares like with like. A
# cooperative per-TU deadline (``_VET_DEADLINE_SECONDS``, monotonic clock)
# is checked at walk entry, before every filesystem operation, in the
# layer-2 marker, hit and repo-file loops and before a "vetted" result is
# accepted; it cannot interrupt a blocked system call or the uninstrumented
# scans (the -E line split, the attribute token scan), which are linear in
# capped input. Over any limit the walk stops and the closure is "not
# vetted"; a witness or vet failure found earlier (base, then layer 1) still
# wins. The base check (main's, unchanged) runs before these limits and is
# not covered by them: a long symlink chain named by absolute paths is as
# slow there as on main. Limit reasons carry counts and the -E line number
# only, never path text. Measured on 4,405 real clang -E closures: names at
# most 181 characters and 22 components, at most 21,825 filesystem
# operations per TU, at most 2 symlink hops per name; each limit is at least
# 10x that. Containment is decided for POSIX filesystems as clang reports
# them; Windows paths and case-insensitive matching are not supported
# (Windows-like names fail the vet).
_MAX_DISTINCT_MARKER_NAMES = 20_000
_MAX_RESOLVED_NAME_CHARS = 4096
_MAX_RESOLVED_NAME_PARTS = 256
_MAX_RESOLVE_OPS_PER_TU = 250_000
_MAX_SYMLINK_HOPS = 40
_VET_DEADLINE_SECONDS = 60
_vet_clock = time.monotonic


class _VetLimitExceeded(Exception):
    """A closure walk hit a work limit: the closure is "not vetted"."""


class _DistinctNameQuotaExceeded(_VetLimitExceeded):
    """A closure walk met more distinct linemarker names than the quota."""


class _ResolveBudget:
    """Filesystem operations and wall-clock time for one TU's closure
    vet, shared by the layer-1 and layer-2 walks. ``where`` locates the
    name being classified (an -E line number, never path text)."""

    def __init__(self) -> None:
        self.spent = 0
        self.where = ""
        self.deadline = _vet_clock() + _VET_DEADLINE_SECONDS

    def tick(self, site: str) -> None:
        """Raise once the per-TU deadline has passed (*site* names the
        check, for diagnostics and tests)."""
        if _vet_clock() >= self.deadline:
            raise _VetLimitExceeded(
                f"closure vet exceeded its {_VET_DEADLINE_SECONDS} s deadline "
                f"— suppression attribution unverified")

    def op(self, kind: str, n: int = 1) -> None:
        """Admit *n* filesystem operations of *kind* (``lstat``,
        ``readlink``, ``target``) or raise; called before the work."""
        self.tick("resolve")
        if self.spent + n > _MAX_RESOLVE_OPS_PER_TU:
            raise _VetLimitExceeded(
                f"linemarker-name resolution budget exhausted (more than "
                f"{_MAX_RESOLVE_OPS_PER_TU} filesystem operations in the "
                f"closure{self.where}) — suppression attribution unverified")
        self.spent += n

    def charge(self, name: str, path: Path) -> None:
        """Per-name limits for resolving *path* (for marker *name*);
        called before the resolve, never after."""
        if len(name) > _MAX_RESOLVED_NAME_CHARS:
            raise _VetLimitExceeded(
                f"linemarker name of {len(name)} characters{self.where} "
                f"exceeds the resolution limit ({_MAX_RESOLVED_NAME_CHARS} "
                f"characters) — suppression attribution unverified")
        parts = len(path.parts)
        if parts > _MAX_RESOLVED_NAME_PARTS:
            raise _VetLimitExceeded(
                f"linemarker name{self.where} resolves through {parts} path "
                f"components, over the resolution limit "
                f"({_MAX_RESOLVED_NAME_PARTS} path components) — suppression "
                f"attribution unverified")


def _bounded_realpath(filename: str, budget: _ResolveBudget) -> str:
    """``os.path.realpath(filename, strict=False)`` on POSIX, with every
    lstat, readlink and spliced target component charged to *budget*
    before it happens and at most ``_MAX_SYMLINK_HOPS`` links followed.
    Raises ``_VetLimitExceeded`` when a limit trips (the only divergence
    from ``os.path.realpath``).

    The equivalence is with the Python 3.13+ ``os.path.realpath``, whose
    loop handling this mirrors. On Python 3.12 the stdlib resolves names
    that pass through a symlink loop differently; in every such case
    measured, this function's result places the name inside the
    repository, so its region is scanned rather than trusted."""
    sep = "/"
    rest = filename.split(sep)[::-1]
    part_count = len(rest)
    path = sep if filename.startswith(sep) else os.getcwd()
    # symlink path -> fully resolved target (None while being resolved:
    # meeting it again is a loop, left unresolved as realpath does)
    seen: dict[str, str | None] = {}
    hops = 0
    while part_count:
        name = rest.pop()
        if name is None:
            seen[rest.pop()] = path
            continue
        part_count -= 1
        if not name or name == ".":
            continue
        if name == "..":
            path = path[:path.rindex(sep)] or sep
            continue
        newpath = path + name if path == sep else path + sep + name
        budget.op("lstat")
        try:
            if not stat.S_ISLNK(os.lstat(newpath).st_mode):
                path = newpath
                continue
            if newpath in seen:
                cached = seen[newpath]
                path = newpath if cached is None else cached
                continue
            budget.op("readlink")
            target = os.readlink(newpath)
        except OSError:
            path = newpath
            continue
        hops += 1
        if hops > _MAX_SYMLINK_HOPS:
            raise _VetLimitExceeded(
                f"linemarker name{budget.where} resolves through more than "
                f"{_MAX_SYMLINK_HOPS} symbolic links — suppression attribution "
                f"unverified")
        target_parts = target.split(sep)[::-1]
        budget.op("target", len(target_parts))
        if target.startswith(sep):
            path = sep
        seen[newpath] = None
        rest.append(newpath)
        rest.append(None)
        rest.extend(target_parts)
        part_count += len(target_parts)
    return path


# The budget of the classifier currently calling a predicate (per thread).
_ACTIVE_BUDGET: contextvars.ContextVar[_ResolveBudget | None] = (
    contextvars.ContextVar("compiler_sweep_resolve_budget", default=None))


def _resolve_bounded(path: Path) -> Path:
    """``path.resolve()`` through ``_bounded_realpath``, charged to the
    calling classifier's budget (a fresh budget outside a walk)."""
    budget = _ACTIVE_BUDGET.get() or _ResolveBudget()
    return Path(_bounded_realpath(str(path), budget))


def _repo_resolve_arg(name: str) -> Path | None:
    """The path ``_add_repo_authored`` resolves, or None when it resolves
    nothing (mirrors ``_repo_authored``)."""
    if not name or name.startswith("<"):
        return None
    p = Path(name)
    return p if p.is_absolute() else None


def _outside_resolve_arg(name: str, tu_dir: Path) -> Path | None:
    """The path ``_presumed_name_outside`` resolves, or None when it
    resolves nothing."""
    if not name or name.startswith("<") or _WINDOWS_LIKE_NAME_RE.search(name):
        return None
    p = Path(name)
    return p if p.is_absolute() else tu_dir / p


class _NameClassifier:
    def __init__(self, target_resolved: Path, tu_dir: Path,
                 budget: _ResolveBudget | None = None) -> None:
        self._target = target_resolved
        self._tu_dir = tu_dir
        self._budget = budget if budget is not None else _ResolveBudget()
        self.budget = self._budget
        self._seen: set[str] = set()
        self._authored: dict[str, bool] = {}
        self._outside: dict[str, str] = {}

    def _admit(self, name: str) -> None:
        if name in self._seen:
            return
        if len(self._seen) >= _MAX_DISTINCT_MARKER_NAMES:
            raise _DistinctNameQuotaExceeded(
                f"more than {_MAX_DISTINCT_MARKER_NAMES} distinct linemarker "
                f"names in the closure — suppression attribution unverified")
        self._seen.add(name)

    def repo(self, name: str) -> bool:
        self._admit(name)
        if name not in self._authored:
            arg = _repo_resolve_arg(name)
            if arg is not None:
                self._budget.charge(name, arg)
            token = _ACTIVE_BUDGET.set(self._budget)
            try:
                self._authored[name] = _add_repo_authored(name, self._target)
            finally:
                _ACTIVE_BUDGET.reset(token)
        return self._authored[name]

    def outside(self, name: str) -> str:
        self._admit(name)
        if name not in self._outside:
            arg = _outside_resolve_arg(name, self._tu_dir)
            if arg is not None:
                self._budget.charge(name, arg)
            token = _ACTIVE_BUDGET.set(self._budget)
            try:
                self._outside[name] = _presumed_name_outside(
                    name, self._tu_dir, self._target)
            finally:
                _ACTIVE_BUDGET.reset(token)
        return self._outside[name]


def _l2_closure(
    pp_text: str,
    target_path: Path,
    full_path: Path,
    budget: _ResolveBudget | None = None,
) -> tuple[str, str]:
    """Layer-2 checks over the -E closure (runs on a base- and
    layer-1-clean closure only; see ``_closure_suppression_witness``)."""
    try:
        return _l2_closure_walk(pp_text, target_path, full_path, budget)
    except _VetLimitExceeded as exc:
        return "", str(exc)


@dataclass
class _L2Owners:
    """Owner of every -E offset, stored at owner CHANGE points only:
    ``names[i]`` owns the lines starting at or after ``starts[i]`` up to
    the next change. ``starts[0] == 0`` (the TU file); a marker's new
    owner takes effect at the start of the line after the marker line."""
    starts: array
    names: list[str]

    def at(self, offset: int) -> str:
        return self.names[bisect.bisect_right(self.starts, offset) - 1]


def _l2_marker_pass(
    pp_text: str, full_path: Path, names: _NameClassifier,
) -> tuple[_L2Owners, dict[str, None], str]:
    """Walk the -E linemarkers: ``(owners, repo include entries, vet
    failure)``. Only lines starting with ``#`` can change the owner, so
    the walk jumps between them with ``str.find`` (no per-line list and
    no per-line Python work)."""
    current = str(full_path)
    repo = names.repo
    budget = names.budget
    repo_files: dict[str, None] = {current: None}
    owners = _L2Owners(array("q", [0]), [current])
    canonical: dict[str, str] = {current: current}
    n = len(pp_text)
    nxt = pp_text.find("\n#")
    pos = 0 if pp_text.startswith("#") else (-1 if nxt < 0 else nxt + 1)
    lineno, counted = 1, 0
    while pos >= 0:
        budget.tick("markers")
        lineno += pp_text.count("\n", counted, pos)
        counted = pos
        budget.where = f" at -E line {lineno}"
        nl = pp_text.find("\n", pos)
        end = n if nl < 0 else nl
        # line-model: a line is pp_text[pos:end] and starts with "#";
        # offsets count raw chars (paired with _attr_token_scan offsets);
        # \r stripped below
        line = pp_text[pos:end].rstrip("\r")
        m = _ADD_DIRECTIVE_RE.match(line)
        if m and m.group(1) != "pragma":
            parsed = _parse_marker_operands(line[m.start(1):])
            if parsed is None or not parsed[0]:
                return owners, repo_files, (
                    f"unparseable linemarker in preprocessed output "
                    f"({line[:120]!r}) — closure attribution unverifiable")
            name, flags = parsed
            if ("1" in flags and not name.startswith("<")
                    and not Path(name).is_absolute()):
                return owners, repo_files, (
                    f"relative include marker {name!r} in preprocessed "
                    f"output — resolved against the compiler's cwd, "
                    f"provenance unverifiable")
            if ("1" not in flags and "2" not in flags and name != current
                    and not name.startswith("<") and repo(current)):
                why = names.outside(name)
                if why:
                    return owners, repo_files, (
                        f"linemarker in {current} {why} — suppression "
                        f"attribution unverifiable")
            if "1" in flags and repo(name):
                repo_files.setdefault(name)
            if name != current:
                name = canonical.setdefault(name, name)
                owners.starts.append(end + 1)
                owners.names.append(name)
            current = name
        if nl < 0:
            break
        nxt = pp_text.find("\n#", nl)
        pos = -1 if nxt < 0 else nxt + 1
    return owners, repo_files, ""


def _l2_closure_walk(
    pp_text: str,
    target_path: Path,
    full_path: Path,
    budget: _ResolveBudget | None = None,
) -> tuple[str, str]:
    budget = budget if budget is not None else _ResolveBudget()
    budget.tick("entry")
    budget.where = " resolving the target root"
    try:
        target_resolved = Path(_bounded_realpath(str(target_path), budget))
    except OSError:
        return "", "target path unresolvable"
    if len(pp_text) > _MAX_PP_TEXT_BYTES:
        return "", "preprocessed output exceeds the scan cap"
    names = _NameClassifier(target_resolved, full_path.parent, budget)
    repo = names.repo
    owners, repo_files, failure = _l2_marker_pass(pp_text, full_path, names)
    if failure:
        return "", failure
    lineno, counted = 1, 0
    for at, w in _attr_token_scan(pp_text, preprocessed=True):
        budget.tick("hits")
        if at < counted:              # the second (trigraph) reading restarts
            lineno, counted = 1, 0
        lineno += pp_text.count("\n", counted, at)
        counted = at
        budget.where = f" at -E line {lineno}"
        owner = owners.at(at)
        if repo(owner):
            return f"{w} (in {owner})", ""
    if len(repo_files) > _MAX_CLOSURE_FILES:
        return "", (f"{len(repo_files)} repo files in the include closure "
                    f"exceed the vet cap ({_MAX_CLOSURE_FILES})")
    for k, fname in enumerate(repo_files, 1):
        budget.tick("files")
        got = read_text_capped(Path(fname), _MAX_CLOSURE_FILE_BYTES)
        if got is None:
            return "", f"closure file {fname} unreadable"
        text, truncated = got
        if truncated:
            return "", f"closure file {fname} exceeds the byte cap"
        scan = _l2_file_scan(text)
        if scan.witness:
            return f"{scan.witness} (in {fname})", ""
        for j, (named, dtext) in enumerate(scan.linemarkers, 1):
            budget.tick("files")
            budget.where = f" in repo include file {k}, directive {j}"
            if named is None:
                return "", (f"linemarker in {fname} has unverifiable operands "
                            f"({dtext[:120]!r}) — suppression attribution "
                            f"unverifiable")
            why = names.outside(named) if named else ""
            if why:
                return "", (f"linemarker in {fname} {why} — suppression "
                            f"attribution unverifiable")
    budget.tick("accept")
    return "", ""


def _has_flag3_tail(witness: str) -> bool:
    """A linemarker-shaped witness (``# N "name" flags``) whose flags
    include 3. Split-based, no regex (linear on any input)."""
    tail = witness.rpartition('"')[2].split()
    return bool(tail) and all(t.isdigit() for t in tail) and "3" in tail


# Presentation only: never changes a witness or a verdict.
_WITNESS_KINDS = (
    ("unverifiable_attribute_list", "unverifiable attribute list",
     lambda w: " … (" in w),
    ("pragma_operator", "`_Pragma` operator, payload not checked",
     lambda w: w.startswith("_Pragma")),
    ("analyzer_conditional", "analyzer-conditional code (`__clang_analyzer__`)",
     lambda w: w.startswith("__clang_analyzer__")),
    ("diagnostic_pragma", "diagnostic-ignore pragma",
     lambda w: "diagnostic" in w and "ignored" in w),
    ("system_header", "system-header pragma or line marker",
     lambda w: "system_header" in w or _has_flag3_tail(w)),
    ("suppress_attribute", "`suppress` attribute",
     lambda w: bool(_ADD_SUPPRESS_RE.search(w))),
)


def _witness_kind(witness: str) -> tuple[str, str]:
    """``(kind, label)`` of a witness string, for operator-facing text."""
    head = witness.split(" (in ")[0]
    for kind, label, pred in _WITNESS_KINDS:
        if pred(head):
            return kind, label
    return "other", "other suppression construct"


def _suppression_witness(source_text: str) -> str:
    """First diagnostic-suppression construct in one file, or ''.

    The base witness, else layer 1, else layer 2: never fewer witnesses
    than the base, and every base or layer-1 witness returned unchanged."""
    return (_base_suppression_witness(source_text)
            or _additive_file_scan(source_text).witness
            or _l2_file_scan(source_text).witness)


def _closure_suppression_witness(
    pp_text: str,
    target_path: Path,
    full_path: Path,
) -> tuple[str, str]:
    """Suppression witness over the TU's preprocessed closure.

    Returns ``(witness, vet_failure)`` exactly like the base
    implementation, which runs first and wins: a base witness or vet
    failure is returned unchanged, then a layer-1 one; only a closure
    both call clean gets layer 2, which may add a witness or a vet
    failure."""
    base = _base_closure_suppression_witness(pp_text, target_path, full_path)
    if base[0] or base[1]:
        return base
    budget = _ResolveBudget()        # one resolution budget per TU
    layer1 = _additive_closure(pp_text, target_path, full_path, budget)
    if layer1[0] or layer1[1]:
        return layer1
    return _l2_closure(pp_text, target_path, full_path, budget)


def _additive_closure(
    pp_text: str,
    target_path: Path,
    full_path: Path,
    budget: _ResolveBudget | None = None,
) -> tuple[str, str]:
    try:
        return _additive_closure_walk(pp_text, target_path, full_path, budget)
    except _VetLimitExceeded as exc:
        return "", str(exc)


def _additive_closure_walk(
    pp_text: str,
    target_path: Path,
    full_path: Path,
    budget: _ResolveBudget | None = None,
) -> tuple[str, str]:
    budget = budget if budget is not None else _ResolveBudget()
    budget.tick("entry")
    budget.where = " resolving the target root"
    try:
        target_resolved = Path(_bounded_realpath(str(target_path), budget))
    except OSError:
        return "", "target path unresolvable"
    if not pp_text.strip():
        # Real -E output always carries at least the TU's linemarker.
        return "", "preprocessed output empty"
    current = str(full_path)
    repo_files: dict[str, None] = {str(full_path): None}
    carry = 0
    # Per-call memo + distinct-name quota + resolution limits (see
    # _NameClassifier): the walk asks for repo authorship on every -E line.
    repo = _NameClassifier(target_resolved, full_path.parent, budget).repo
    budget.where = " at -E line 1"

    for lineno, line in enumerate(pp_text.split("\n"), 1):  # line-model: each element is rstrip("\r")-ed on the next line
        line = line.rstrip("\r")
        if line.startswith("#"):
            budget.where = f" at -E line {lineno}"
            m = _ADD_DIRECTIVE_RE.match(line)
            if m and m.group(1) != "pragma":
                parsed = _parse_marker_operands(line[m.start(1):])
                if parsed is None or not parsed[0]:
                    return "", (
                        f"unparseable linemarker in preprocessed output "
                        f"({line[:120]!r}) — closure attribution "
                        f"unverifiable"
                    )
                name, flags = parsed
                if ("1" not in flags and "2" not in flags
                        and name != current and not name.startswith("<")
                        and repo(current) and not repo(name)):
                    return "", (
                        f"linemarker re-attributes repo lines from "
                        f"{current} to {name} — suppression attribution "
                        f"unverifiable"
                    )
                if "1" in flags and repo(name):
                    repo_files.setdefault(name)
                current = name
                carry = 0
                continue
        if not repo(current):
            carry = 0
            continue
        w, carry = _attr_line_witness(line, carry)
        if w:
            return f"{w} (in {current})", ""
    if len(repo_files) > _MAX_CLOSURE_FILES:
        return "", (
            f"{len(repo_files)} repo files in the include closure "
            f"exceed the vet cap ({_MAX_CLOSURE_FILES})"
        )
    for k, fname in enumerate(repo_files, 1):
        budget.tick("files")
        got = read_text_capped(Path(fname), _MAX_CLOSURE_FILE_BYTES)
        if got is None:
            return "", f"closure file {fname} unreadable"
        text, truncated = got
        if truncated:
            return "", f"closure file {fname} exceeds the byte cap"
        w = _base_suppression_witness(text)
        scan = _additive_file_scan(text)
        w = w or scan.witness
        if w:
            return f"{w} (in {fname})", ""
        for j, (named, dtext) in enumerate(scan.linemarkers, 1):
            budget.where = f" in repo include file {k}, directive {j}"
            if named is None:
                return "", (
                    f"linemarker in {fname} has unverifiable operands "
                    f"({dtext[:120]!r}) — suppression attribution "
                    f"unverifiable"
                )
            if named and not repo(named):
                return "", (
                    f"linemarker in {fname} re-attributes lines to "
                    f"{named} — suppression attribution unverifiable"
                )
    budget.tick("accept")
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
                clang, "--analyze", "--analyzer-output", "text",  # type: ignore[list-item]
                *include_flags, str(full_path),
            ]
        else:
            cmd = [
                clang, "-fsyntax-only", *spec.clang_flags,  # type: ignore[list-item]
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
    source_lines = source_text.split("\n")  # line-model: read_text_capped universal-newline read above
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
