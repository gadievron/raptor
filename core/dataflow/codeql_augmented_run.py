"""Subprocess wrapper for ``codeql database analyze`` with optional
data-extension pack.

Produces the two SARIF files :mod:`core.dataflow.finding_diff` needs:
one from a baseline analysis (stdlib queries only), one from an
augmented analysis (stdlib + the PR2a-emitted sanitizer-evidence
pack). The diff between them tells us which findings the augmented
sanitizer models suppressed.

This module wraps the CodeQL CLI; it does NOT generate the
extension pack (PR2a does that) or compute the diff
(:mod:`core.dataflow.finding_diff` does that). Operator wiring
typically:

    1. Build CandidateValidator records via PR1's extraction.
    2. write_extension_pack(...)  # PR2a
    3. baseline_sarif = analyze(db, queries, baseline_out)
    4. augmented_sarif = analyze(db, queries, augmented_out, extension_pack=pack)
    5. diff = diff_sarif_files(baseline_sarif, augmented_sarif)

The subprocess invocation is injectable for tests (``runner``
parameter). Production uses :func:`subprocess.run` with a bounded
timeout. CodeQL exit codes other than 0 raise
:class:`CodeQLRunError`; the caller decides whether to swallow or
propagate.

The augmented pack is RAPTOR-internal (built by PR2a from
LLM-extracted CandidateValidator records that have themselves been
through identifier validation), so we don't enable CodeQL's pack-
trust check here. Two compensating properties bound the exposure:
this module feeds the measurement harness only (baseline-vs-augmented
SARIF diff → suppression-rate metric; not the production finding
path), and ``analyze`` refuses any extension pack that contains
executable query content (``.ql``/``.qll``) — the pack may carry
declarative data extensions only, so a compromised emission step
cannot smuggle runnable queries into the analyze invocation.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.config import RaptorConfig
from packages.codeql.tunables import CodeQLTunables

DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_CODEQL_BIN = "codeql"


#: Subprocess invocation. Returns the completed process. Injected for
#: tests via the ``runner`` arg; defaults to ``subprocess.run``.
RunnerFn = Callable[..., Any]


class CodeQLRunError(RuntimeError):
    """Raised when ``codeql database analyze`` exits non-zero or
    times out. The message includes the CLI command, exit code, and
    captured stderr (trimmed)."""


def _require_data_only_pack(pack_dir: Path) -> None:
    """Refuse extension packs carrying executable query content.

    The pack is loaded with CodeQL's pack-trust check disabled, which
    is safe only because a data-extension pack is declarative YAML.
    A ``.ql``/``.qll`` file inside it would be compiled and run by the
    analyze invocation — enforce the data-only shape here rather than
    trusting the emission step.
    """
    if not pack_dir.is_dir():
        raise ValueError(
            f"extension pack is not a directory: {pack_dir}")
    offenders = [
        p for p in pack_dir.rglob("*")
        if p.suffix in (".ql", ".qll")
    ]
    if offenders:
        raise ValueError(
            "extension pack must contain data extensions only; "
            f"found query content: {offenders[0]}"
            + (f" (+{len(offenders) - 1} more)" if len(offenders) > 1 else "")
        )


@dataclass(frozen=True)
class AnalysisResult:
    """Outcome of one CodeQL analyze invocation."""

    sarif_path: Path
    queries: tuple[str, ...]
    extension_pack: Path | None
    elapsed_seconds: float


def analyze(
    db_path: Path,
    queries: Sequence[str],
    output_path: Path,
    *,
    extension_pack: Path | None = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: RunnerFn | None = None,
    extra_args: Sequence[str] = (),
) -> AnalysisResult:
    """Run ``codeql database analyze`` once.

    Args:
        db_path: Path to the CodeQL DB directory.
        queries: One or more query specs (paths, suite names, or
            ``pack:Subdir/path/Foo.ql`` references). Forwarded as
            positional args after the DB path.
        output_path: Where to write the SARIF output. Parent dir is
            created if missing.
        extension_pack: Optional path to a directory containing a
            ``codeql-pack.yml`` declaring data extensions
            (PR2a's :func:`write_extension_pack` output). When
            supplied, the CLI is invoked with
            ``--additional-packs <pack>``.
        codeql_bin: Path to the ``codeql`` binary.
        timeout_seconds: Hard cap on the subprocess wall time.
        runner: Injection point for tests; defaults to
            :func:`subprocess.run`.
        extra_args: Extra CLI args appended after the standard set.
            Operator-controlled escape hatch.

    Returns:
        :class:`AnalysisResult` carrying the SARIF path, queries
        list, extension pack reference, and elapsed wall time.

    Raises:
        :class:`CodeQLRunError`: on non-zero exit or timeout.
    """
    if not queries:
        raise ValueError("analyze: at least one query spec required")

    if extension_pack is not None:
        _require_data_only_pack(Path(extension_pack))

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        codeql_bin,
        "database",
        "analyze",
        str(db_path),
        *queries,
        "--format=sarif-latest",
        f"--output={output_path}",
    ]
    CodeQLTunables.from_tuning().append_to(cmd, include_disk_cache=False)
    if extension_pack is not None:
        cmd.extend(["--additional-packs", str(extension_pack)])
    cmd.extend(extra_args)

    run = runner or subprocess.run

    import time
    start = time.monotonic()
    try:
        completed = run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=RaptorConfig.get_safe_env(),
        )
    except subprocess.TimeoutExpired as e:
        raise CodeQLRunError(
            f"codeql analyze timed out after {timeout_seconds}s "
            f"(db={db_path})"
        ) from e

    elapsed = time.monotonic() - start

    returncode = getattr(completed, "returncode", 0)
    if returncode != 0:
        stderr = getattr(completed, "stderr", "") or ""
        # Trim very long stderr to keep error message readable.
        stderr_tail = stderr[-2000:] if len(stderr) > 2000 else stderr
        raise CodeQLRunError(
            f"codeql analyze exited {returncode}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stderr (last 2000 chars):\n{stderr_tail}"
        )

    return AnalysisResult(
        sarif_path=output_path,
        queries=tuple(queries),
        extension_pack=extension_pack,
        elapsed_seconds=elapsed,
    )


def run_baseline_and_augmented(
    db_path: Path,
    queries: Sequence[str],
    extension_pack: Path,
    out_dir: Path,
    *,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: RunnerFn | None = None,
) -> tuple[AnalysisResult, AnalysisResult]:
    """Convenience: run baseline and augmented analyses in sequence,
    write both SARIFs under ``out_dir``, return both results.

    The baseline analysis omits ``--additional-packs`` entirely so
    its result matches what the operator's normal CodeQL run would
    produce. Pack-augmented analysis follows.
    """
    baseline = analyze(
        db_path,
        queries,
        out_dir / "baseline.sarif",
        codeql_bin=codeql_bin,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    augmented = analyze(
        db_path,
        queries,
        out_dir / "augmented.sarif",
        extension_pack=extension_pack,
        codeql_bin=codeql_bin,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    return baseline, augmented
