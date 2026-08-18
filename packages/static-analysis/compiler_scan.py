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
(``_derive_include_dirs``), the diagnostics parsers (``_parse_gcc_sarif``
/ ``_parse_gcc_json`` / ``_parse_clang_text``), the per-TU timeout, and
the CWE family map (``COMPILER_CWE_MAP``) for tagging diagnostics with
a CWE. Importing the module-private helpers follows the existing
precedent (:mod:`core.audit.preprocessor_view` imports
``_derive_include_dirs`` the same way) so compiler_sweep itself stays
byte-identical.

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
* Bounded: per-TU timeout from compiler_sweep's ``_COMPILE_TIMEOUT_S``
  and a TU cap (``max_tus``).  Anything skipped by the cap is reported
  LOUDLY — no silent truncation.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Repo root on sys.path — this module lives in a hyphenated package
# directory (not importable as a package) and is loaded via importlib
# by scanner.py or the tests; make the absolute imports below work
# regardless of which entry point loaded us.
_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.audit.compiler_sweep import (
    _COMPILE_TIMEOUT_S,
    COMPILER_CWE_MAP,
    _clang_path,
    _derive_include_dirs,
    _gcc_analyzer,
    _id_matches,
    _parse_clang_text,
    _parse_gcc_json,
    _parse_gcc_sarif,
)
from core.inventory.exclusions import DEFAULT_EXCLUDES, should_exclude
from core.run.scratch import scratch_dir

logger = logging.getLogger(__name__)

DEFAULT_MAX_TUS = 2000
_MAX_WORKERS = 4

_C_SUFFIXES = frozenset({".c"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".C"})
_TU_SUFFIXES = _C_SUFFIXES | _CXX_SUFFIXES

_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master"
    "/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
)
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
    if not diag_id:
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


def analyze_tu(
    target_path: Path,
    rel_path: str,
    *,
    sandbox_run,
    scratch_root: str | None = None,
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

    include_flags = [
        f"-I{d}" for d in _derive_include_dirs(target_path, full_path.parent)
    ]

    with scratch_dir("compiler_scan_", dir=scratch_root) as workdir:
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
                caller_label="compiler-scan",
            )
        except subprocess.TimeoutExpired:
            return TuDiagnostics(
                rel_path, ok=False, compiler=compiler_name,
                reason=f"analyzer timed out ({_COMPILE_TIMEOUT_S}s)",
            )
        except (subprocess.SubprocessError, OSError, ValueError, TypeError) as exc:
            return TuDiagnostics(
                rel_path, ok=False, compiler=compiler_name,
                reason=f"analyzer invocation failed: {exc}",
            )

        if compiler_name == "gcc" and mode == "sarif-file":
            raw_diags = _parse_gcc_sarif(workdir / f"{full_path.name}.sarif")
        elif compiler_name == "gcc":
            raw_diags = _parse_gcc_json(proc.stderr or "")
        else:
            raw_diags = _parse_clang_text(proc.stderr or "")

        if proc.returncode != 0:
            # Broken compile (missing generated headers, dialect gaps,
            # ICE) — the analyzer never saw well-formed code, so its
            # partial output proves nothing.  No findings from here.
            error_msgs = [
                d["message"] for d in raw_diags
                if "error" in str(d.get("kind", ""))
            ][:3]
            summary = "; ".join(error_msgs) or f"exit code {proc.returncode}"
            return TuDiagnostics(
                rel_path, ok=False, compiler=compiler_name,
                reason=f"compile failed — cannot analyse: {summary}",
            )

        kept: list[dict[str, Any]] = []
        for d in raw_diags:
            if "error" in str(d.get("kind", "")):
                continue
            diag_id = d.get("id") or ""
            if not _keep_diag_id(diag_id):
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
        return TuDiagnostics(
            rel_path, ok=True, compiler=compiler_name, diagnostics=kept,
        )


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

    def summary_line(self) -> str:
        """One-line operator-facing summary (LOUD about skips)."""
        parts = [
            (
                f"compiler-scan: {len(self.findings)} finding(s) from "
                f"{self.tus_analyzed}/{self.tus_total} TU(s)"
            )
        ]
        if self.tus_failed:
            parts.append(f"{self.tus_failed} TU(s) failed to compile")
        if self.tus_skipped_cap:
            parts.append(
                f"⚠️  {self.tus_skipped_cap} TU(s) SKIPPED by the TU cap "
                f"— raise --compiler-scan-max-tus to cover them"
            )
        return "; ".join(parts)


def scan_target(
    target_path: Path,
    *,
    max_tus: int = DEFAULT_MAX_TUS,
    out_dir: Path | None = None,
    max_workers: int = _MAX_WORKERS,
) -> CompilerScanResult:
    """Run the compiler analyzers across every C/C++ TU in *target_path*.

    Returns a :class:`CompilerScanResult`.  ``ok=False`` (with reason,
    never an exception) when no analyzer is installed or the sandbox is
    unavailable — the scan refuses to run the compiler on untrusted
    source without isolation.
    """
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

    seen: set[tuple[str, str, int]] = set()
    workers = max(1, min(max_workers, len(tus)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                analyze_tu, target_path, rel,
                sandbox_run=sandbox_run, scratch_root=scratch_root,
            ): rel
            for rel in tus
        }
        per_tu: dict[str, TuDiagnostics] = {}
        for fut in as_completed(futures):
            rel = futures[fut]
            try:
                per_tu[rel] = fut.result()
            except Exception as exc:  # noqa: BLE001 — one bad TU must not kill the scan
                per_tu[rel] = TuDiagnostics(
                    rel, ok=False, reason=f"unexpected failure: {exc}",
                )

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
        for diag in tu.diagnostics:
            # Same header pulled into many TUs repeats its diagnostics —
            # dedup on (rule, file, line).
            key = (diag["rule_id"], diag["file"], diag["line"])
            if key in seen:
                continue
            seen.add(key)
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
    rule_defs: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    sarif_results: list[dict[str, Any]] = []

    for f in result.findings:
        rule_id = f["rule_id"]
        cwe = f.get("cwe")
        if rule_id not in seen_rules:
            props: dict[str, Any] = {}
            if cwe:
                props["cwe"] = cwe
                props["tags"] = [f"external/cwe/{cwe.lower()}"]
            rule_defs.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "fullDescription": {
                    "text": f"Compiler static-analyzer diagnostic {rule_id}",
                },
                "defaultConfiguration": {"level": "warning"},
                **({"properties": props} if props else {}),
            })
            seen_rules.add(rule_id)

        res_props: dict[str, Any] = {
            "tool": _TOOL_NAME,
            "compiler": f.get("compiler", ""),
        }
        if cwe:
            res_props["cwe"] = cwe
        sarif_results.append({
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": f.get("message") or f"{rule_id} diagnostic"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                },
            }],
            "properties": res_props,
        })

    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "fullName": _TOOL_FULL_NAME,
                    "rules": rule_defs,
                },
            },
            "results": sarif_results,
        }],
    }
