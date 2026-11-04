"""Compiler-analyzer scan channel for /scan and /agentic.

Same channel as :mod:`core.audit.compiler_sweep`, opposite direction:
instead of testing one hypothesis against one translation unit, this
module walks every C/C++ TU in the target during the SCAN phase and
turns the compiler's own static-analyzer diagnostics (``gcc
-fanalyzer`` preferred, ``clang --analyze`` fallback) into scan
findings — a peer of the semgrep / CodeQL / coccinelle stages whose
SARIF feeds the dedup/analysis pipeline.

The heavy machinery is REUSED from compiler_sweep, not reimplemented:
toolchain probing (:func:`core.audit.compiler_sweep._gcc_analyzer` /
``_clang_path``), mechanical include-path derivation
(``_derive_include_dirs``), the diagnostic parser dispatch (``_parse_analyzer_output``), the per-TU timeout, and
the CWE family map (``COMPILER_CWE_MAP``) for tagging diagnostics with
a CWE — plus the shared in-source suppression witness
(``_suppression_witness`` / ``_closure_suppression_witness`` and their
caps) that both channels use. Importing the module-private helpers
follows the existing precedent (:mod:`core.audit.preprocessor_view`
imports ``_derive_include_dirs`` the same way).

Design constraints (the scanned repo is UNTRUSTED — identical posture
to compiler_sweep):

* NOTHING from the repo may execute.  No build system is invoked; the
  compiler runs directly on exactly one TU per invocation with
  ``-c -o /dev/null`` and mechanically derived include paths.
* The compiler parses hostile source, so every invocation goes through
  ``core.sandbox.context.run`` with ``block_network=True`` plus
  Landlock target/output confinement.  If the sandbox cannot be
  imported the scan REFUSES to run (``ok=False`` with reason) rather
  than degrading to unsandboxed execution.
* A broken compile contributes NO findings — the analyzer never saw
  well-formed code, so its (partial) output proves nothing.  Failed
  TUs are counted and reported, never silently dropped.
* Bounded: a shared analysis deadline, per-TU timeout from compiler_sweep's
  ``_COMPILE_TIMEOUT_S`` and a TU cap (``max_tus``). Unfinished coverage is
  reported explicitly; completed findings survive deadline exhaustion.
* Analyzer silence on attacker-authored source is repo-steerable
  (``[[clang::suppress]]``, ``#ifndef __clang_analyzer__``, flag-3
  system-header linemarkers — in the TU or a repo header). Each cleanly
  analysed TU gets compiler_sweep's suppression witness (file + include
  closure); a hit is recorded as a COVERAGE LIMITATION (summary clause
  + SARIF tool-execution notification), never as a finding and never
  as a filter on findings that still fire.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Repo root on sys.path — this module lives in a hyphenated package
# directory (not importable as a package) and is loaded via importlib
# by scanner.py or the tests. Python path safety: the only permitted
# sys.path addition is the launcher-pinned RAPTOR_DIR (hard lookup,
# no __file__-derived fallback — a relocated/vendored copy must fail
# loudly rather than silently import another tree's core.*).
_REPO_ROOT = os.environ["RAPTOR_DIR"]
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.detectors.compiler_families import compiler_diagnostic_is_candidate
from core.detectors.compiler_paths import attach_paths, PATH_KIND, PathBudget

from core.audit.compiler_sweep import (
    _COMPILE_TIMEOUT_S,
    _MAX_CLOSURE_FILE_BYTES,
    _MAX_PP_TEXT_BYTES,
    COMPILER_CWE_MAP,
    _clang_path,
    _closure_suppression_witness,
    _derive_include_dirs,
    _cached_include_dirs,
    _gcc_analyzer,
    _id_matches,
    _parse_analyzer_output,
    _suppression_witness,
    _witness_kind,
    _resolve_bounded,
    _VetLimitExceeded,
)
from core.audit.run_memo import BoundedMemo
from core.inventory.exclusions import DEFAULT_EXCLUDES, should_exclude
from core.detectors.compiler import (
    CompilerInvocationError, CompilerRequest, run_compiler_analysis,
)
from core.detectors.budget import DEFAULT_COMPILER_SCAN_SECONDS, WorkBudget, bounded_futures, positive_seconds
from core.detectors.setup import AnalysisSetup
from core.detectors.memcpy_overlap import OVERLAP_ID, run_memcpy_overlap
from core.detectors.stack_return import (
    CANDIDATE_ID as STACK_RETURN_ID, RULE_ID as STACK_RETURN_RULE_ID, run_stack_return,
)
from core.sarif import emit
from core.source import read_text_capped

logger = logging.getLogger(__name__)

DEFAULT_MAX_TUS = 2000
_MAX_WORKERS = 4

_C_SUFFIXES = frozenset({".c"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".C"})
_TU_SUFFIXES = _C_SUFFIXES | _CXX_SUFFIXES

_SARIF_SCHEMA_URI = emit.SCHEMA_URI_COMMITTEE
_TOOL_NAME = "compiler"
_TOOL_FULL_NAME = "Compiler static analyzers (gcc -fanalyzer / clang --analyze)"


def _sandbox_runner():
    """The sandboxed process runner, or None when unavailable.

    Split out so tests (and hosts without core.sandbox) exercise the
    refusal path deterministically.  The compiler parses hostile
    source — this module NEVER runs it unsandboxed.
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        return None
    return sandbox_run


# ---------------------------------------------------------------------------
# Scan-mode flag union (all families at once — the scan direction wants
# every diagnostic the analyzers can produce, not one CWE family)
# ---------------------------------------------------------------------------


def _union_flags(attr: str) -> list[str]:
    """Ordered, deduped union of one flag attribute across the family map."""
    seen: list[str] = []
    for spec in COMPILER_CWE_MAP.values():
        for flag in getattr(spec, attr):
            if flag not in seen:
                seen.append(flag)
    return seen


def _cwe_for_diag_id(diag_id: str) -> str | None:
    """Map a diagnostic id to a CWE via compiler_sweep's family map.

    First matching family wins (dict order).  Shared out-of-bounds ids
    map to the first OOB family key — the tag marks the family, not a
    precise sub-classification.
    """
    for cwe, spec in COMPILER_CWE_MAP.items():
        if _id_matches(diag_id, spec.gcc_ids + spec.clang_ids):
            return cwe
    return None


def _keep_diag_id(diag_id: str) -> bool:
    """Should a diagnostic id become a scan finding?

    Keep: family-mapped ids (CWE-tagged), any ``-Wanalyzer-*`` id
    (gcc's analyzer is a bug-finder by design), and clang static-
    analyzer checker ids (dotted, e.g. ``unix.Malloc``).  Plain
    compiler warnings outside the family map (``-Wunused-variable``
    etc.) are style noise for a security pipeline and are dropped.
    """
    if not diag_id or compiler_diagnostic_is_candidate(diag_id):
        return False
    # This frontend warning also fires in dead arms. It is input to the
    # corroborating detector, never a scan finding by itself.
    if diag_id.rstrip("=") == STACK_RETURN_ID:
        return False
    if _cwe_for_diag_id(diag_id) is not None:
        return True
    if diag_id.startswith("-Wanalyzer-"):
        return True
    # clang checker ids: dotted lowercase-package form, no leading dash.
    return "." in diag_id and not diag_id.startswith("-")


# ---------------------------------------------------------------------------
# TU enumeration (inventory exclusion rules reused)
# ---------------------------------------------------------------------------


def enumerate_tus(target_path: Path) -> list[str]:
    """Sorted repo-relative C/C++ TU paths under *target_path*.

    Reuses :data:`core.inventory.exclusions.DEFAULT_EXCLUDES` via
    :func:`should_exclude` so vendored / test / build / generated
    directories are skipped consistently with the inventory builder.
    Symlinks are not followed.
    """
    target_path = Path(target_path)
    tus: list[str] = []
    for root, subdirs, files in os.walk(target_path, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith("."))
        for name in sorted(files):
            if Path(name).suffix not in _TU_SUFFIXES:
                continue
            rel = os.path.relpath(os.path.join(root, name), target_path)
            if should_exclude(rel, DEFAULT_EXCLUDES):
                continue
            tus.append(rel.replace(os.sep, "/"))
    return sorted(tus)


# ---------------------------------------------------------------------------
# Per-TU analysis
# ---------------------------------------------------------------------------


@dataclass
class TuDiagnostics:
    """Result of analysing one translation unit."""

    file_path: str  # repo-relative TU path
    ok: bool
    compiler: str = ""
    reason: str = ""
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    # Coverage limitations (ok TUs only; never findings): the first
    # in-source analyzer-suppression construct in the TU or its repo
    # include closure, or why the closure could not be vetted.
    suppression_witness: str = ""
    suppression_unvetted: str = ""
    stack_return_candidates: list[dict[str, Any]] = field(default_factory=list)
    review_candidates: list[dict[str, Any]] = field(default_factory=list)


def _rel_under_target(diag_file: str, target_path: Path, tu_dir: Path) -> str | None:
    """Repo-relative path for a diagnostic location, or None.

    Only locations under the target root are attributable scan
    findings; system headers and builtins are noise for this channel.
    Relative diagnostic paths are resolved against the TU's directory
    (the compiler was invoked with an absolute TU path, so relative
    forms are rare — belt and braces).
    """
    if not diag_file or diag_file.startswith("<"):
        return None
    p = Path(diag_file)
    if not p.is_absolute():
        p = tu_dir / p
    try:
        real = os.path.realpath(p)
        root = os.path.realpath(target_path)
    except OSError:
        return None
    if real == root:
        return None
    if not real.startswith(root + os.sep):
        return None
    return os.path.relpath(real, root).replace(os.sep, "/")


def _suppression_vet(
    cmd0: str,
    compiler_name: str,
    include_flags: list[str],
    target_path: Path,
    full_path: Path,
    workdir: Path,
    sandbox_run,
) -> tuple[str, str]:
    """``(witness, vet_failure)`` for one cleanly analysed TU.

    Same two-step vet as compiler_sweep's refutation gate: the raw
    single-file witness first, then the compiler's own ``-E`` output
    over the include closure (with the analyzer's macro environment on
    the clang path so conditional includes resolve as under
    ``--analyze``). Override flags (``-U``/``-D``) are deliberately NOT
    used on the analysis itself — an in-source ``#define``/``#undef``
    defeats them; the witness cannot be defeated that way.
    """
    got = read_text_capped(full_path, _MAX_CLOSURE_FILE_BYTES)
    if got is None:
        return "", "TU unreadable"
    text, truncated = got
    if truncated:
        return "", "TU exceeds the byte cap"
    witness = _suppression_witness(text)
    if witness:
        return witness, ""
    pp_cmd = [cmd0, "-E", *include_flags, str(full_path)]
    if compiler_name == "clang":
        pp_cmd.insert(2, "-D__clang_analyzer__=1")
    try:
        proc = sandbox_run(
            pp_cmd,
            block_network=True,
            target=str(target_path),
            output=str(workdir),
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=_COMPILE_TIMEOUT_S,
            caller_label="compiler-scan",
        )
    except (subprocess.SubprocessError, OSError, ValueError, TypeError):
        return "", "preprocessor run failed"
    if proc.returncode != 0:
        return "", f"preprocessor exited {proc.returncode}"
    if not isinstance(proc.stdout, str) or not proc.stdout:
        # Real -E output always carries at least the TU's linemarker;
        # missing output is an unvetted closure, never an empty one.
        return "", "preprocessor produced no output"
    return _closure_suppression_witness(
        proc.stdout[:_MAX_PP_TEXT_BYTES + 1], target_path, full_path,
    )


def _scan_diagnostics(raw, target_path: Path, full_path: Path, compiler_name: str, rel_path: str,
                      *, review_candidates: bool = False):
    kept: list[dict[str, Any]] = []
    @lru_cache(maxsize=256)
    def locate_event(name):
        return _rel_under_target(name, target_path, full_path.parent)
    for d in raw:
        if "error" in str(d.get("kind", "")):
            continue
        diag_id = d.get("id") or ""
        candidate = compiler_diagnostic_is_candidate(diag_id)
        if candidate != review_candidates or (not candidate and not _keep_diag_id(diag_id)):
            continue
        rel = _rel_under_target(
            d.get("file", ""), target_path, full_path.parent,
        )
        if rel is None:
            continue
        line = d.get("line", 0)
        if not isinstance(line, int) or line <= 0:
            continue
        kept.append({
            "rule_id": diag_id,
            "file": rel,
            "line": line,
            "message": d.get("message", ""),
            "cwe": _cwe_for_diag_id(diag_id),
            "compiler": compiler_name,
            "tu": rel_path,
        })
        attach_paths(kept[-1], d, locate_event)
    return kept


def analyze_tu(
    target_path: Path,
    rel_path: str,
    *,
    sandbox_run,
    scratch_root: str | None = None,
    include_dirs_memo: BoundedMemo[list[str]] | None = None,
) -> TuDiagnostics:
    """Run the compiler analyzer over one TU; return kept diagnostics.

    Mirrors compiler_sweep's invocation exactly (same probing, include
    derivation, sandbox posture, timeout) but with the scan-mode flag
    union instead of a single CWE family, and with diagnostics kept
    for ANY file under the target root (headers included), not just
    the TU itself.
    """
    target_path = Path(target_path)
    full_path = target_path / rel_path
    if not full_path.is_file():
        return TuDiagnostics(rel_path, ok=False, reason="file not found")

    is_c = full_path.suffix in _C_SUFFIXES
    gcc = _gcc_analyzer() if is_c else None  # gcc -fanalyzer is C-only
    clang = _clang_path()
    if gcc is None and clang is None:
        return TuDiagnostics(
            rel_path, ok=False,
            reason="compiler static analyzer not installed "
                   "(need gcc >= 10 with -fanalyzer, or clang)",
        )

    include_dirs = (_derive_include_dirs(target_path, full_path.parent)
                    if include_dirs_memo is None else
                    _cached_include_dirs(target_path, full_path.parent, include_dirs_memo))
    include_flags = [f"-I{d}" for d in include_dirs]

    if gcc is not None:
        gcc_path, mode = gcc
        compiler_name = "gcc"
        cmd = [
            gcc_path, "-fanalyzer", *_union_flags("gcc_flags"),
            f"-fdiagnostics-format={mode}",
            *include_flags, "-c", str(full_path), "-o", os.devnull,
        ]
    else:
        compiler_name = "clang"
        mode = "analyze"
        # ``--analyze`` runs sema too, so the warning-engine flags
        # (-Wformat=2 etc.) fire in the same invocation.
        cmd = [
            clang, "--analyze", "--analyzer-output", "text",
            *_union_flags("clang_flags"),
            *include_flags, str(full_path),
        ]

    def interpret(record: dict[str, Any], workdir: Path) -> TuDiagnostics:
        kept = _scan_diagnostics(record["diags"], target_path, full_path, compiler_name, rel_path)
        try:
            witness, unvetted = _suppression_vet(
                cmd[0], compiler_name, include_flags, target_path,
                full_path, workdir, sandbox_run,
            )
        except Exception as exc:  # noqa: BLE001 — the vet only annotates; it must never cost this TU its findings
            witness, unvetted = "", f"suppression vet failed: {type(exc).__name__}"
        return TuDiagnostics(
            rel_path, ok=True, compiler=compiler_name, diagnostics=kept,
            suppression_witness=witness, suppression_unvetted=unvetted,
            stack_return_candidates=[d for d in record["diags"]
                                     if compiler_name == "gcc" and d.get("id") == STACK_RETURN_ID
                                     and d.get("kind") == "warning"],
            review_candidates=_scan_diagnostics(record["diags"], target_path, full_path,
                                                 compiler_name, rel_path, review_candidates=True),
        )

    try:
        execution = run_compiler_analysis(
            CompilerRequest(
                command=tuple(cmd), target=target_path,
                timeout=_COMPILE_TIMEOUT_S, caller_label="compiler-scan",
                scratch_prefix="compiler_scan_", scratch_root=scratch_root,
                analyze=interpret,
                parse=lambda workdir, stderr: _parse_analyzer_output(
                    workdir, stderr, compiler_name=compiler_name,
                    mode=mode, full_path=full_path,
                ),
            ),
            sandbox_run,
        )
    except CompilerInvocationError as exc:
        if isinstance(exc.error, subprocess.TimeoutExpired):
            seconds = exc.error.timeout
            reason = (f"analyzer timed out ({seconds:g}s)" if isinstance(seconds, (int, float))
                      else "analyzer timed out")
        else:
            reason = f"analyzer invocation failed: {exc}"
        return TuDiagnostics(rel_path, ok=False, compiler=compiler_name, reason=reason)

    record = execution.value.record
    assert record is not None
    raw_diags = record["diags"]

    if record["returncode"] != 0:
        # Broken compile (missing generated headers, dialect gaps,
        # ICE) — the analyzer never saw well-formed code, so its
        # partial output proves nothing.  No findings from here.
        error_msgs = [
            d["message"] for d in raw_diags
            if "error" in str(d.get("kind", ""))
        ][:3]
        summary = "; ".join(error_msgs) or f"exit code {record['returncode']}"
        return TuDiagnostics(
            rel_path, ok=False, compiler=compiler_name,
            reason=f"compile failed — cannot analyse: {summary}",
        )

    assert isinstance(execution.value.result, TuDiagnostics)
    return execution.value.result


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


@dataclass
class CompilerScanResult:
    """Aggregate result of the compiler scan across all TUs."""

    ok: bool
    reason: str = ""
    tus_total: int = 0        # candidate TUs discovered (post-exclusion)
    tus_analyzed: int = 0     # TUs the analyzer ran cleanly on
    tus_failed: int = 0       # compile failure / timeout / invocation error
    tus_skipped_cap: int = 0  # dropped by the max_tus cap
    findings: list[dict[str, Any]] = field(default_factory=list)
    # Coverage limitations on ANALYSED TUs — never findings, never a
    # claim about the code: {"tu", "suppression_witness"} where an
    # in-source construct can silence the analyzer, {"tu", "reason"}
    # where the include closure could not be vetted for one.
    suppressed_tus: list[dict[str, str]] = field(default_factory=list)
    unvetted_tus: list[dict[str, str]] = field(default_factory=list)

    detector_limitations: list[dict[str, str]] = field(default_factory=list)
    tus_skipped_budget: int = 0  # never submitted before the analysis deadline
    budget_exhausted: bool = False
    review_candidates: list[dict[str, Any]] = field(default_factory=list)

    def summary_line(self) -> str:
        """One-line operator-facing summary (LOUD about skips)."""
        parts = [
            (
                f"compiler-scan: {len(self.findings)} finding(s) from "
                f"{self.tus_analyzed}/{self.tus_total} TU(s)"
            )
        ]
        if self.review_candidates:
            parts.append(f"{len(self.review_candidates)} compiler review candidate(s) require corroboration")
        if self.tus_failed:
            parts.append(f"{self.tus_failed} TU(s) failed to compile")
        if self.tus_skipped_cap:
            parts.append(
                f"⚠️  {self.tus_skipped_cap} TU(s) SKIPPED by the TU cap "
                f"— raise --compiler-scan-max-tus to cover them"
            )
        if self.budget_exhausted:
            parts.append(f"analysis time budget exhausted; {self.tus_skipped_budget} TU(s) not started; "
                         "completed findings retained — raise --compiler-scan-max-seconds for more coverage")
        if self.suppressed_tus:
            # The kind labels are presentation only: every listed TU is
            # a coverage limitation regardless of its kind.
            kinds: dict[str, int] = {}
            for s in self.suppressed_tus:
                label = _witness_kind(s["suppression_witness"])[1]
                kinds[label] = kinds.get(label, 0) + 1
            detail = ", ".join(
                f"{n} {label}"
                for label, n in sorted(kinds.items(), key=lambda kv: -kv[1])
            )
            parts.append(
                f"⚠️  {len(self.suppressed_tus)} TU(s) carry an in-source "
                f"analyzer suppression or steering construct ({detail}) — "
                f"silence there is not evidence"
            )
        if self.unvetted_tus:
            parts.append(
                f"⚠️  {len(self.unvetted_tus)} TU(s) not vetted for "
                f"analyzer suppression — silence there is not evidence"
            )
        if self.detector_limitations:
            parts.append(f"{len(self.detector_limitations)} additional analyzer limitation(s)")
        return "; ".join(parts)


def scan_target(
    target_path: Path,
    *,
    max_tus: int = DEFAULT_MAX_TUS,
    out_dir: Path | None = None,
    max_workers: int = _MAX_WORKERS,
    setup: AnalysisSetup | None = None,
    max_seconds: float = DEFAULT_COMPILER_SCAN_SECONDS,
) -> CompilerScanResult:
    """Run compiler analyzers over capped C/C++ TUs in *target_path*.

    Returns a :class:`CompilerScanResult`.  ``ok=False`` (with reason,
    never an exception) when no analyzer is installed or the sandbox is
    unavailable — the scan refuses to run the compiler on untrusted
    source without isolation. ``max_seconds`` bounds analysis after discovery.
    Expiry returns ``ok=True`` with ``budget_exhausted=True`` and explicit
    coverage limitations, preserving completed findings; it is not full coverage.
    """
    # Discovery precedes the shared analysis window; it keeps its own probe caps.
    max_seconds = positive_seconds(max_seconds)
    target_path = Path(target_path)
    sandbox_run = _sandbox_runner()
    if sandbox_run is None:
        return CompilerScanResult(
            ok=False,
            reason="core.sandbox unavailable — refusing to run the "
                   "compiler on untrusted source without isolation",
        )
    if _gcc_analyzer() is None and _clang_path() is None:
        return CompilerScanResult(
            ok=False,
            reason="compiler static analyzer not installed "
                   "(need gcc >= 10 with -fanalyzer, or clang)",
        )

    tus = enumerate_tus(target_path)
    result = CompilerScanResult(ok=True, tus_total=len(tus))
    if not tus:
        return result

    if max_tus is not None and max_tus >= 0 and len(tus) > max_tus:
        result.tus_skipped_cap = len(tus) - max_tus
        logger.warning(
            "compiler-scan: TU cap reached — analysing %d of %d TU(s); "
            "%d SKIPPED (raise --compiler-scan-max-tus to cover them)",
            max_tus, len(tus), result.tus_skipped_cap,
        )
        tus = tus[:max_tus]

    scratch_root = str(out_dir) if out_dir else None
    if scratch_root:
        os.makedirs(scratch_root, exist_ok=True)

    # Shared only within this scan: a later run must discover header-directory
    # changes. Bound entries and collapse concurrent lookups of the same TU dir.
    setup = setup if setup is not None else AnalysisSetup()
    include_dirs_memo = setup.include_dirs_memo
    budget = WorkBudget(max_seconds)
    sandbox_run = budget.runner(sandbox_run)
    path_budget = PathBudget(8 * 1024 * 1024)
    def retain_path_context(diagnostic):
        path_budget.retain(diagnostic, diagnostic.get("code_flows", []), diagnostic.get("compiler_path_notes", []))
    seen_candidates: set[tuple[str, str, int]] = set()
    seen: dict[tuple[str, str, int], dict[str, Any]] = {}
    workers = max(1, min(max_workers, len(tus)))
    per_tu: dict[str, TuDiagnostics] = {}
    def analyze(rel):
        return analyze_tu(target_path, rel, sandbox_run=sandbox_run, scratch_root=scratch_root,
                          include_dirs_memo=include_dirs_memo)
    for rel, future in bounded_futures(tus, analyze, workers=workers, budget=budget):
        try:
            per_tu[rel] = future.result()
            for diagnostic in (*per_tu[rel].diagnostics, *per_tu[rel].review_candidates):
                retain_path_context(diagnostic)
        except Exception as exc:  # one failed TU must not erase completed work
            per_tu[rel] = TuDiagnostics(rel, ok=False, reason=f"unexpected failure: {exc}")
    result.tus_skipped_budget = len(tus) - len(per_tu)

    eligible = tuple(rel for rel in tus
                     if Path(rel).suffix in _C_SUFFIXES and per_tu.get(rel) is not None
                     and per_tu[rel].ok)
    if eligible and budget.remaining() > 0:
        gcc = _gcc_analyzer()

        def overlap_request(rel):
            assert gcc is not None
            gcc_path, mode = gcc
            full = target_path / rel
            includes = [f"-I{d}" for d in _cached_include_dirs(
                target_path, full.parent, include_dirs_memo)]
            return CompilerRequest(
                command=(gcc_path, "-fanalyzer", OVERLAP_ID, "-fno-builtin-memcpy",
                         f"-fdiagnostics-format={mode}", *includes,
                         "-c", str(full), "-o", os.devnull),
                target=target_path, timeout=_COMPILE_TIMEOUT_S,
                caller_label="compiler-scan", scratch_prefix="compiler_overlap_",
                scratch_root=scratch_root,
                parse=lambda workdir, stderr: _parse_analyzer_output(
                    workdir, stderr, compiler_name="gcc", mode=mode, full_path=full,
                ),
            )

        try:
            extra = run_memcpy_overlap(
                target_path, eligible, request_for=overlap_request if gcc else None,
                sandbox_run=sandbox_run, max_workers=workers,
                include_dirs_memo=include_dirs_memo, setup=setup, budget=budget,
            ).value
            result.detector_limitations.extend({
                "tu": item["tu"], "reason": _relativise(item["reason"], target_path),
            } for item in extra.limitations)
            for rel, raw in extra.diagnostics.items():
                kept = _scan_diagnostics(raw, target_path, target_path / rel, "gcc", rel)
                for diagnostic in kept:
                    retain_path_context(diagnostic)
                per_tu[rel].diagnostics.extend(kept)
        except Exception as exc:  # additive detector failures cannot erase baseline findings
            result.detector_limitations.append({
                "tu": "", "reason": f"memcpy overlap detector failed: {type(exc).__name__}",
            })

    elif eligible:
        budget.mark_exhausted()

    stack_seeds = {rel: item.stack_return_candidates for rel, item in per_tu.items()
                   if item.ok and item.compiler == "gcc" and item.stack_return_candidates}
    if stack_seeds and budget.remaining() > 0:
        from core.audit.preprocessor_view import expand_translation_unit

        clang = _clang_path()
        gcc = _gcc_analyzer()

        @lru_cache(maxsize=512)
        def stack_file(name, tu):
            # A compiler #line name is still target-controlled. Reuse the
            # bounded resolver, and cache both accepted and refused names.
            if not name or name.startswith("<") or len(name) > 4096:
                return None
            path = Path(name)
            if not path.is_absolute():
                path = (target_path / tu).parent / path
            try:
                rel = _resolve_bounded(path).relative_to(_resolve_bounded(target_path))
            except (OSError, ValueError, RuntimeError, _VetLimitExceeded):
                return None
            return rel.as_posix() if rel != Path(".") else None

        def locate_stack(diagnostic, tu):
            line, name = diagnostic.get("line", 0), diagnostic.get("file", "")
            if (not isinstance(line, int) or isinstance(line, bool) or line <= 0
                    or not isinstance(name, str)):
                return None
            rel = stack_file(name, tu)
            return (rel, line) if rel is not None else None

        def prepare_stack(tu, scratch):
            assert gcc is not None
            return expand_translation_unit(
                target_path=target_path, file_path=tu, out_dir=scratch,
                preprocessor=(gcc[0], "-fanalyzer", *_union_flags("gcc_flags"), "-E", "-x", "c"),
                include_dirs_memo=include_dirs_memo, setup=setup,
                timeout=budget.remaining(),
            )

        def stack_request(tu, source):
            assert clang is not None
            return CompilerRequest(
                command=(clang, "--analyze", "--analyzer-output", "text", "-x", "c", str(source)),
                target=source.parent, timeout=_COMPILE_TIMEOUT_S,
                caller_label="compiler-scan", scratch_prefix="stack_clang_", scratch_root=str(source.parent),
                parse=lambda workdir, stderr: _parse_analyzer_output(
                    workdir, stderr, compiler_name="clang", mode="analyze", full_path=source,
                ),
            )

        try:
            extra_stack = run_stack_return(
                target_path, stack_seeds, request_for=stack_request if clang and gcc else None,
                sandbox_run=sandbox_run, locate=locate_stack, prepare_view=prepare_stack,
                scratch_root=scratch_root, max_workers=workers, budget=budget,
            ).value
            result.detector_limitations.extend({
                "tu": item["tu"], "reason": _relativise(item["reason"], target_path),
                "detector": "stack_return",
            } for item in extra_stack.limitations)
            for rel, raw in extra_stack.diagnostics.items():
                for diagnostic in _scan_diagnostics(raw, target_path, target_path / rel, "clang", rel):
                    diagnostic["rule_id"] = STACK_RETURN_RULE_ID
                    diagnostic["cwe"] = "CWE-562"
                    diagnostic["corroborated_by"] = ["gcc", "clang"]
                    diagnostic["preprocessed_by"] = "gcc"
                    per_tu[rel].diagnostics.append(diagnostic)
        except Exception as exc:
            result.detector_limitations.append({
                "tu": "", "reason": f"stack-return detector failed: {type(exc).__name__}",
                "detector": "stack_return",
            })

    elif stack_seeds:
        budget.mark_exhausted()

    # Raw warnings remain candidates unless the shared scalar-access proof
    # succeeds. One AST per affected TU, never one subprocess per warning.
    from core.detectors.scalar_aliasing import corroborate_aliasing, RULE_ID as ALIASING_RULE_ID
    alias_tus = [rel for rel in tus if rel in per_tu and per_tu[rel].ok
                 and per_tu[rel].compiler == "gcc" and per_tu[rel].review_candidates
                 and Path(rel).suffix == ".c"]
    if alias_tus:
        gcc, clang = _gcc_analyzer(), _clang_path()
        def analyze_aliasing(rel):
            return corroborate_aliasing(
                target_path, rel, per_tu[rel].review_candidates,
                gcc=gcc[0] if gcc else None, clang=clang, sandbox_run=sandbox_run,
                budget=budget, setup=setup, include_dirs_memo=include_dirs_memo,
                scratch_root=scratch_root,
                preprocessor=(gcc[0], "-fanalyzer", *_union_flags("gcc_flags"), "-E", "-x", "c") if gcc else None,
            )
        attempted = 0
        for rel, future in bounded_futures(alias_tus[:25], analyze_aliasing, workers=1, budget=budget):
            attempted += 1
            try:
                extra_aliasing = future.result()
                result.detector_limitations.extend({"tu": rel, "detector": "scalar_aliasing", "reason": reason}
                                                   for reason in extra_aliasing.limitations)
                promoted = set()
                for proof in extra_aliasing.proofs if extra_aliasing.complete else ():
                    diagnostic = {"rule_id": ALIASING_RULE_ID, "file": proof["file"], "line": proof["line"],
                                  "message": f"{proof['object']} has declared type {proof['declared_type']} "
                                             f"but is accessed through {proof['access_type']}",
                                  "cwe": "CWE-843", "compiler": "gcc+clang-ast", "tu": rel,
                                  "corroborated_by": ["gcc", "clang-ast"], "preprocessed_by": "gcc",
                                  "aliasing_proof": proof}
                    per_tu[rel].diagnostics.append(diagnostic)
                    promoted.add((proof["file"], proof["candidate_line"]))
                per_tu[rel].review_candidates = [c for c in per_tu[rel].review_candidates
                    if (c["file"], c["line"]) not in promoted]
            except Exception as exc:
                result.detector_limitations.append({"tu": rel, "detector": "scalar_aliasing",
                    "reason": f"scalar aliasing corroboration failed: {type(exc).__name__}"})
        if attempted < len(alias_tus):
            result.detector_limitations.append({"tu": "", "detector": "scalar_aliasing",
                "reason": f"scalar aliasing cap or analysis budget left {len(alias_tus) - attempted} TU(s) unresolved"})

    result.budget_exhausted = budget.exhausted
    if result.budget_exhausted:
        result.detector_limitations.append({
            "tu": "", "detector": "compiler_budget",
            "reason": f"compiler analysis budget exhausted ({max_seconds:g}s); "
                      f"{result.tus_skipped_budget} TU(s) not started; completed findings retained",
        })

    # Deterministic aggregation order regardless of completion order.
    for rel in tus:
        tu = per_tu.get(rel)
        if tu is None:
            continue
        if not tu.ok:
            result.tus_failed += 1
            logger.debug("compiler-scan: %s — %s", rel, tu.reason)
            continue
        result.tus_analyzed += 1
        if tu.suppression_witness:
            result.suppressed_tus.append({
                "tu": rel, "suppression_witness": _relativise(
                    tu.suppression_witness, target_path),
            })
        elif tu.suppression_unvetted:
            result.unvetted_tus.append({
                "tu": rel, "reason": _relativise(
                    tu.suppression_unvetted, target_path),
            })
        for candidate in tu.review_candidates:
            key = (candidate["rule_id"], candidate["file"], candidate["line"])
            if key not in seen_candidates:
                seen_candidates.add(key)
                result.review_candidates.append(candidate)
        for diag in tu.diagnostics:
            # Same header pulled into many TUs repeats its diagnostics —
            # dedup on (rule, file, line).
            key = (diag["rule_id"], diag["file"], diag["line"])
            if key in seen:
                attach_paths(seen[key], diag)
                continue
            seen[key] = diag
            result.findings.append(diag)

    return result


# ---------------------------------------------------------------------------
# SARIF (scan-findings shape the dedup pipeline consumes)
# ---------------------------------------------------------------------------


def to_sarif(result: CompilerScanResult) -> dict[str, Any]:
    """SARIF 2.1.0 document for ``merge_sarif`` / the dedup pipeline.

    Mirrors the shape the semgrep / coccinelle legs emit: one run,
    ``tool.driver.name = "compiler"``, ``ruleId`` = the diagnostic id,
    CWE carried in both rule and result ``properties`` (the tag form
    ``external/cwe/cwe-N`` matches what core.sarif.parser extracts).
    """
    rule_index = emit.RuleIndex()
    sarif_results: list[dict[str, Any]] = []

    for f in result.findings:
        rule_id = f["rule_id"]
        if compiler_diagnostic_is_candidate(rule_id):
            continue
        cwe = f.get("cwe")
        props: dict[str, Any] = {}
        if cwe:
            props["cwe"] = cwe
            props["tags"] = [f"external/cwe/{cwe.lower()}"]
        rule_index.add(emit.minimal_rule(
            rule_id,
            full_description=f"Compiler static-analyzer diagnostic {rule_id}",
            properties=props or None,
        ))

        res_props: dict[str, Any] = {
            "tool": _TOOL_NAME,
            "compiler": f.get("compiler", ""),
        }
        if cwe:
            res_props["cwe"] = cwe
        if f.get("corroborated_by"):
            res_props["corroborated_by"] = f["corroborated_by"]
        if f.get("aliasing_proof"):
            res_props["aliasing_proof"] = f["aliasing_proof"]
        if f.get("preprocessed_by"):
            res_props["preprocessed_by"] = f["preprocessed_by"]
        evidence: dict[str, Any] = {}
        def export_event(name):
            path = Path(name)
            return name if path.parts and not path.is_absolute() and ".." not in path.parts else None
        attach_paths(evidence, f, export_event)
        if evidence:
            res_props["code_flow_kind"] = PATH_KIND
        if evidence.get("compiler_path_notes"):
            res_props["compiler_path_notes"] = evidence["compiler_path_notes"]
        entry = emit.result(
            rule_id,
            f.get("message") or f"{rule_id} diagnostic",
            [emit.location(f["file"], {"startLine": f["line"]})],
            properties=res_props,
        )
        if evidence.get("code_flows"):
            entry["codeFlows"] = evidence["code_flows"]
        sarif_results.append(entry)

    run = emit.run(
        _TOOL_NAME, rule_index.rules(), sarif_results,
        full_name=_TOOL_FULL_NAME,
    )
    # Coverage limitations ride as tool-execution notifications (the
    # coccinelle precedent), NOT results and NOT ``artifacts``: they
    # survive merge_sarif, never enter SarifCache's result index or
    # its declared-coverage lane, and say only that analyzer silence
    # on these TUs is not evidence of absence.
    notifications = [
        _limitation_note(
            s["tu"], "suppression_witness",
            f"in-source analyzer suppression ({s['suppression_witness']}) "
            f"— analyzer silence on this TU is not evidence of absence",
            suppression_witness=s["suppression_witness"],
            witness_kind=_witness_kind(s["suppression_witness"])[0],
        )
        for s in result.suppressed_tus
    ] + [
        _limitation_note(
            u["tu"], "suppression_unvetted",
            f"include closure not vetted for analyzer suppression "
            f"({u['reason']}) — analyzer silence on this TU is not "
            f"evidence of absence",
            reason=u["reason"],
        )
        for u in result.unvetted_tus
    ] + [
        _limitation_note(item["tu"], item.get("detector", "memcpy_overlap"), item["reason"])
        for item in result.detector_limitations
    ]
    if result.review_candidates:
        notifications.append(_limitation_note("", "review_candidates",
            f"{len(result.review_candidates)} compiler review candidate(s) require independent corroboration; "
            "see compiler-review-candidates.json"))
    if notifications:
        run["invocations"] = [{
            "executionSuccessful": True,
            "toolExecutionNotifications": notifications,
        }]
    return emit.document([run], schema_uri=_SARIF_SCHEMA_URI)


def review_candidates_report(result: CompilerScanResult) -> dict[str, Any]:
    """Operator-only data, deliberately excluded from automatic finding imports."""
    return {"schema_version": 1, "kind": "compiler-review-candidates",
            "candidates": [{"status": "needs_review", "family_hint": c.get("cwe"),
                            "rule_id": c["rule_id"], "file": c["file"], "line": c["line"],
                            "message": c["message"], "compiler": c["compiler"]}
                           for c in result.review_candidates]}


def _relativise(text: str, target_path: Path) -> str:
    """Replace the target root in a witness / reason with a repo-relative
    form, so SARIF and summaries carry no absolute host path."""
    roots = {str(target_path)}
    try:
        roots.add(str(target_path.resolve()))
    except OSError:
        pass
    for root in sorted(roots, key=len, reverse=True):
        text = text.replace(root.rstrip(os.sep) + os.sep, "")
    return text


def _limitation_note(
    tu: str, kind: str, text: str, **props: str,
) -> dict[str, Any]:
    """One SARIF ``notification`` recording a per-TU coverage limitation."""
    note: dict[str, Any] = {
        "level": "warning",
        "message": {"text": text[:500]},
        "properties": {"coverage_limitation": kind, **props},
    }
    if tu:
        note["locations"] = [{
            "physicalLocation": {"artifactLocation": {"uri": tu}},
        }]
    return note
