"""Blamed-line execution check for crash root-cause reports.

The crash-analysis agents write ``root-cause-hypothesis-NNN.md`` reports
whose causal chain names blamed source lines in a fixed per-step format
(``**Location:** `file.c:line```). The agent instructions demand that
every such line "is actually executed in the coverage data", but nothing
verifies that mechanically — a hallucinated location survives review
unless the checker agent happens to probe it.

This module extracts the blamed locations, asks the gcov-backed
line-execution checker (the ``line-execution-checker`` crash-analysis
skill's tool) whether each executed, and stamps the results as a
clearly-delimited mechanical section appended to the report plus a JSON
sidecar. A NOT-EXECUTED blamed line is surfaced prominently as a strong
root-cause-refutation signal — evidence for the checker agent and the
operator, never an automatic rejection.

Degrades gracefully: no coverage data, no compiler to build the checker,
or a per-file checker failure all yield ``unknown`` stamps (with the
reason), never an exception out of the crash pipeline.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.json import save_json
from core.security.env_sanitisation import safe_subprocess_env
from core.security.markdown_render import md_inline

logger = logging.getLogger(__name__)

# Per-step location anchor from the crash-analyzer report format.
_LOCATION_RE = re.compile(
    r"\*\*Location:\*\*\s*`(?P<file>[^`:\s]+):(?P<line>\d{1,7})`"
)

# Conservative charset for paths handed to the checker subprocess: the
# report is agent-written but describes a hostile target, so a blamed
# "path" could carry option-shaped or traversal content.
_SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./+-]{0,255}$")

_MAX_BLAMED_LINES = 100
_CHECKER_TIMEOUT_S = 60
_SECTION_MARKER = "## Blamed-line execution check (mechanical)"
_SECTION_FOOTER = ("_Generated mechanically from gcov data by "
                   "packages.binary_analysis.blamed_lines; evidence, "
                   "not a verdict._")

_SKILL_CPP = Path(".claude/skills/crash-analysis/line-execution-checker/"
                  "line_checker.cpp")


@dataclass
class BlamedLineResult:
    file: str
    line: int
    status: str          # "executed" | "not_executed" | "unknown"
    count: int = 0
    reason: str = ""

    def to_dict(self) -> dict:
        d = {"file": self.file, "line": self.line, "status": self.status}
        if self.count:
            d["count"] = self.count
        if self.reason:
            d["reason"] = self.reason
        return d


def extract_blamed_lines(report_text: str) -> list[tuple[str, int]]:
    """Extract (file, line) pairs from a root-cause report's Location anchors.

    Order-preserving, deduplicated, capped at _MAX_BLAMED_LINES (a cap
    hit is logged). Files failing the conservative charset are dropped
    with a warning — they cannot be handed to a subprocess safely.
    """
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for m in _LOCATION_RE.finditer(report_text):
        file, line = m.group("file"), int(m.group("line"))
        if ".." in file.split("/") or not _SAFE_FILE_RE.match(file):
            logger.warning(
                "blamed_lines: dropping unsafe location %r", file[:80])
            continue
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= _MAX_BLAMED_LINES:
            logger.warning(
                "blamed_lines: cap of %d locations reached; remainder "
                "unchecked", _MAX_BLAMED_LINES)
            break
    return out


def _has_coverage_data(coverage_dir: Path) -> bool:
    for pattern in ("*.gcov", "*.gcda"):
        try:
            if next(coverage_dir.rglob(pattern), None) is not None:
                return True
        except OSError:
            return False
    return False


def _resolve_checker(
    build_dir: Path,
    checker_path: str | Path | None,
    raptor_dir: Path | None,
) -> Path | None:
    """Locate or build the line-checker binary.

    Order: explicit path (a caller/operator trust assertion, used
    as-is) → build from the repo-pinned skill line_checker.cpp into
    ``build_dir`` (g++, list argv, safe env). Returns None when
    unavailable.

    Never picks up a pre-existing ``line-checker`` from the coverage
    dir: that directory is written by the instrumented target's own
    build and execution, so anything found there is target-suppliable
    (provenance doctrine: target-writable ⇒ untrusted). Executing a
    planted checker would hand the analysed program host code
    execution AND let it forge the mechanical blamed-line verdicts
    this module exists to make trustworthy. ``build_dir`` is a
    RAPTOR-owned scratch directory for the same reason — the built
    binary must never live where the target can swap it.
    """
    if checker_path:
        p = Path(checker_path)
        return p if p.is_file() else None
    root = raptor_dir or _default_raptor_dir()
    cpp = root / _SKILL_CPP
    if not cpp.is_file():
        return None
    built = Path(build_dir) / "line-checker"
    try:
        proc = subprocess.run(
            ["g++", "-O3", "-std=c++17", str(cpp), "-o", str(built)],
            capture_output=True, text=True, timeout=120, check=False,
            env=safe_subprocess_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("blamed_lines: line-checker build failed: %s", exc)
        return None
    if proc.returncode != 0:
        logger.warning(
            "blamed_lines: line-checker build failed: %s",
            (proc.stderr or "")[:500])
        return None
    return built


def _default_raptor_dir() -> Path:
    return Path(__file__).resolve().parents[2]


_OUTPUT_RE = re.compile(
    r"^(?P<file>\S+):(?P<line>\d+)\s+"
    r"(?:EXECUTED \((?P<count>\d+) times?\)|(?P<not>NOT EXECUTED))\s*$"
)


def _run_checker(
    argv: list[str], coverage_dir: Path,
) -> subprocess.CompletedProcess:
    """Run the line-checker under the full sandbox.

    The checker parses hostile bytes either way — the ``.gcov`` /
    ``.gcda`` files in the coverage dir were emitted while the
    instrumented (untrusted) target executed — so it gets the same
    posture as every other our-tool-over-hostile-data invocation in
    this package (network blocked, Landlock scoped to the coverage
    dir, seccomp, rlimits). ``tool_paths`` grants read/exec on the
    RAPTOR-owned scratch dir holding the freshly built checker.
    """
    # Lazy import — keeps this module importable in unit tests that
    # stub the sandbox (same convention as core.binary.inspect).
    from core.sandbox import run as _sandbox_run
    return _sandbox_run(
        argv,
        block_network=True,
        target=str(coverage_dir),
        tool_paths=[str(Path(argv[0]).resolve().parent)],
        cwd=str(coverage_dir),
        capture_output=True,
        text=True,
        timeout=_CHECKER_TIMEOUT_S,
    )


def check_blamed_lines(
    pairs: list[tuple[str, int]],
    coverage_dir: str | Path,
    *,
    checker_path: str | Path | None = None,
    raptor_dir: Path | None = None,
) -> list[BlamedLineResult]:
    """Check each blamed line against gcov data in ``coverage_dir``.

    One checker invocation per file (the tool aborts its whole batch on
    the first file without coverage data; per-file batching turns that
    into a per-file ``unknown`` instead).
    """
    coverage_dir = Path(coverage_dir)
    if not pairs:
        return []
    if not coverage_dir.is_dir() or not _has_coverage_data(coverage_dir):
        return [BlamedLineResult(f, ln, "unknown", reason="no coverage data")
                for f, ln in pairs]
    with tempfile.TemporaryDirectory(
            prefix="raptor-line-checker-") as build_dir:
        checker = _resolve_checker(Path(build_dir), checker_path, raptor_dir)
        if checker is None:
            return [BlamedLineResult(f, ln, "unknown",
                                     reason="line-checker unavailable")
                    for f, ln in pairs]
        return _check_with_checker(pairs, coverage_dir, checker)


def _check_with_checker(
    pairs: list[tuple[str, int]],
    coverage_dir: Path,
    checker: Path,
) -> list[BlamedLineResult]:
    by_file: dict[str, list[int]] = {}
    for f, ln in pairs:
        by_file.setdefault(f, []).append(ln)

    results: dict[tuple[str, int], BlamedLineResult] = {}
    for file, lines in by_file.items():
        argv = [str(checker)] + [f"{file}:{ln}" for ln in lines]
        try:
            proc = _run_checker(argv, coverage_dir)
        except (OSError, subprocess.SubprocessError) as exc:
            for ln in lines:
                results[(file, ln)] = BlamedLineResult(
                    file, ln, "unknown", reason=f"checker failed: {exc}")
            continue
        except BaseException as exc:
            # SandboxSetupError is a BaseException by design (fail-
            # loud). Here the documented degrade contract wins — the
            # crash pipeline must survive — but the checker NEVER
            # runs unsandboxed as a fallback: no isolation, no
            # verdict. KeyboardInterrupt/SystemExit still propagate.
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            logger.warning(
                "blamed_lines: sandbox unavailable for checker: %s", exc)
            for ln in lines:
                results[(file, ln)] = BlamedLineResult(
                    file, ln, "unknown",
                    reason=f"sandbox unavailable: {exc}")
            continue
        if proc.returncode == 2:
            reason = (proc.stderr or "checker error").strip()[:200]
            for ln in lines:
                results[(file, ln)] = BlamedLineResult(
                    file, ln, "unknown", reason=reason)
            continue
        for out_line in (proc.stdout or "").splitlines():
            m = _OUTPUT_RE.match(out_line.strip())
            if not m:
                continue
            key = (m.group("file"), int(m.group("line")))
            if m.group("not"):
                results[key] = BlamedLineResult(
                    key[0], key[1], "not_executed")
            else:
                results[key] = BlamedLineResult(
                    key[0], key[1], "executed",
                    count=int(m.group("count") or 0))
        for ln in lines:
            results.setdefault(
                (file, ln),
                BlamedLineResult(file, ln, "unknown",
                                 reason="no checker output for line"))
    return [results[(f, ln)] for f, ln in pairs]


def render_section(results: list[BlamedLineResult]) -> str:
    """Render the mechanical section appended to the report."""
    not_executed = [r for r in results if r.status == "not_executed"]
    lines = ["", "---", "", _SECTION_MARKER, ""]
    if not_executed:
        lines.append(
            f"⚠️ **{len(not_executed)} blamed line(s) show NO execution in "
            "the coverage data.** A blamed line that never executed is a "
            "strong signal the causal chain is wrong at that step — "
            "re-verify before accepting this root cause.")
        lines.append("")
    lines += ["| Location | Coverage |", "|----------|----------|"]
    for r in results:
        if r.status == "executed":
            cell = f"Executed ({r.count}×)"
        elif r.status == "not_executed":
            cell = "**NOT EXECUTED**"
        else:
            # The reason cell carries up to 200 chars of checker
            # stderr — hostile-gcov-derived bytes. md_inline keeps a
            # raw pipe from breaking the table row, an embedded
            # newline from splitting the line, and image/autofetch
            # markup from going live in the report.
            reason = md_inline(r.reason) if r.reason else ""
            cell = f"Unknown — {reason}" if reason else "Unknown"
        lines.append(f"| `{md_inline(f'{r.file}:{r.line}')}` | {cell} |")
    lines.append("")
    lines.append(_SECTION_FOOTER)
    return "\n".join(lines) + "\n"


def check_report(
    report_path: str | Path,
    coverage_dir: str | Path,
    *,
    checker_path: str | Path | None = None,
    stamp: bool = True,
) -> dict:
    """Check a root-cause report's blamed lines; stamp + sidecar.

    Returns a summary dict (also written to ``<report>.line-check.json``).
    Re-runs are idempotent: an existing mechanical section is replaced,
    not duplicated.
    """
    report_path = Path(report_path)
    text = report_path.read_text(encoding="utf-8", errors="replace")
    pairs = extract_blamed_lines(text)
    results = check_blamed_lines(pairs, coverage_dir,
                                 checker_path=checker_path)
    summary = {
        "report": report_path.name,
        "blamed_lines": len(pairs),
        "executed": sum(1 for r in results if r.status == "executed"),
        "not_executed": sum(
            1 for r in results if r.status == "not_executed"),
        "unknown": sum(1 for r in results if r.status == "unknown"),
        "results": [r.to_dict() for r in results],
    }
    sidecar = report_path.with_suffix(report_path.suffix + ".line-check.json")
    try:
        save_json(sidecar, summary)
    except OSError as exc:
        logger.warning("blamed_lines: sidecar write failed: %s", exc)
    if stamp and results:
        # Replace only a section WE previously stamped: strip from the
        # LAST delimiter occurrence, and only when the tail carries the
        # mechanical footer. Splitting on the first occurrence
        # truncated a report whose agent prose legitimately contained
        # the delimiter byte sequence.
        delim = "\n---\n\n" + _SECTION_MARKER
        idx = text.rfind(delim)
        if idx != -1 and _SECTION_FOOTER in text[idx:]:
            base = text[:idx]
        else:
            base = text
        try:
            report_path.write_text(
                base.rstrip("\n") + "\n" + render_section(results),
                encoding="utf-8")
        except OSError as exc:
            logger.warning("blamed_lines: report stamp failed: %s", exc)
    if summary["not_executed"]:
        logger.warning(
            "blamed_lines: %d blamed line(s) in %s were NEVER executed — "
            "root cause suspect",
            summary["not_executed"], report_path.name)
    return summary
