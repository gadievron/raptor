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
from typing import Any

from core.run.scratch import scratch_dir

from ._util import safe_join
from .sweep import SweepResult

logger = logging.getLogger(__name__)

_COMPILE_TIMEOUT_S = 120
_PROBE_TIMEOUT_S = 30
_MAX_INCLUDE_DIRS = 8
_INCLUDE_WALK_DEPTH = 3
_INCLUDE_DIR_NAMES = frozenset({"include", "includes", "inc"})
_WALK_SKIP_DIRS = frozenset({"node_modules", "vendor", "third_party"})
_MAX_RAW_OUTPUT = 20_000

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


def _safe_env() -> dict | None:
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except ImportError:
        return None


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
                timeout=_PROBE_TIMEOUT_S, env=_safe_env(), cwd=td,
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
            for d in subdirs:
                if d.lower() in _INCLUDE_DIR_NAMES:
                    found.append(os.path.join(root, d))
            if len(found) >= _MAX_INCLUDE_DIRS:
                break
    except OSError:
        pass

    for d in sorted(found)[:_MAX_INCLUDE_DIRS]:
        if d not in dirs:
            dirs.append(d)
    return dirs


# ---------------------------------------------------------------------------
# Hypothesis identifier extraction (negative control)
# ---------------------------------------------------------------------------

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
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
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
    is_cxx = suffix in _CXX_SUFFIXES or suffix == ".C"
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

    include_dirs = _derive_include_dirs(target_path, full_path.parent)
    include_flags = [f"-I{d}" for d in include_dirs]

    scratch_root = str(out_dir) if out_dir else None
    with scratch_dir("compiler_sweep_", dir=scratch_root) as workdir:
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

        try:
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
        except subprocess.TimeoutExpired:
            return _error(
                file_path, function_name,
                f"analyzer timed out ({_COMPILE_TIMEOUT_S}s)",
                rule_id=f"compiler:{norm_cwe.lower()}",
            )
        except (subprocess.SubprocessError, OSError, ValueError,
                TypeError) as exc:
            return _error(
                file_path, function_name,
                f"analyzer invocation failed: {exc}",
                rule_id=f"compiler:{norm_cwe.lower()}",
            )

        if compiler_name == "gcc" and mode == "sarif-file":
            diags = _parse_gcc_sarif(workdir / f"{full_path.name}.sarif")
        elif compiler_name == "gcc":
            diags = _parse_gcc_json(proc.stderr or "")
        else:
            diags = _parse_clang_text(proc.stderr or "")

        details: dict[str, Any] = {
            "compiler": compiler_name,
            "mode": mode,
            "cwe": norm_cwe,
            "diagnostics_total": len(diags),
        }
        raw = (proc.stderr or "")[:_MAX_RAW_OUTPUT]

        if proc.returncode != 0:
            # Compile failure (missing generated headers, dialect gaps,
            # ICE). The analyzer never saw well-formed code — silence
            # here proves nothing. NEVER refute from a broken compile.
            error_msgs = [
                d["message"] for d in diags
                if "error" in str(d.get("kind", ""))
            ][:3]
            summary = "; ".join(error_msgs) or f"exit code {proc.returncode}"
            result = _inconclusive(
                file_path, function_name,
                f"compile failed — cannot analyse: {summary}",
                details=details,
            )
            result.raw_output = raw
            return result

        try:
            source_text = full_path.read_text(errors="replace")
        except OSError:
            source_text = ""
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
