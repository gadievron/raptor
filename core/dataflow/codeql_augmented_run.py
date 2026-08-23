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
from core.dataflow.extension_pack import (
    ExtensionPackResult,
    ModelRow,
    write_extension_pack,
)
from core.dataflow.finding_diff import FindingDiff, diff_sarif_files
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
        msg = f"extension pack is not a directory: {pack_dir}"
        raise ValueError(msg)
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


def _pack_name(pack_dir: Path) -> str:
    """The pack's declared name, from its codeql-pack.yml.

    Strict single-line parse (the emitter writes ``name: <scope/name>``
    as the first key); a pack without a parseable name refuses loudly —
    silently analyzing WITHOUT the models is the vacuous-measurement
    bug this exists to prevent.
    """
    manifest = pack_dir / "codeql-pack.yml"
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.startswith("name:"):
                return line.split(":", 1)[1].strip()
    except OSError as e:
        msg = f"extension pack manifest unreadable: {manifest}"
        raise CodeQLRunError(msg) from e
    msg = f"extension pack has no parseable name: {manifest}"
    raise CodeQLRunError(msg)


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
        msg = "analyze: at least one query spec required"
        raise ValueError(msg)

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
        # --additional-packs only makes the pack RESOLVABLE; data
        # extensions apply to the analysis only when the pack is also
        # named via --model-packs, and cached query results would mask
        # the row changes, so re-evaluation is forced. Verified live:
        # without --model-packs the augmented run is byte-identical to
        # the baseline (the historical zero-delta was vacuous).
        cmd.extend([
            "--additional-packs", str(extension_pack),
            "--model-packs", _pack_name(Path(extension_pack)),
            "--rerun",
        ])
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
        msg = (
            f"codeql analyze timed out after {timeout_seconds}s "
            f"(db={db_path})"
        )
        raise CodeQLRunError(msg) from e

    elapsed = time.monotonic() - start

    returncode = getattr(completed, "returncode", 0)
    if returncode != 0:
        stderr = getattr(completed, "stderr", "") or ""
        # Trim very long stderr to keep error message readable.
        stderr_tail = stderr[-2000:] if len(stderr) > 2000 else stderr
        msg = (
            f"codeql analyze exited {returncode}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stderr (last 2000 chars):\n{stderr_tail}"
        )
        raise CodeQLRunError(msg)

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


@dataclass(frozen=True)
class LearnedModelsMeasurement:
    """End-to-end outcome: pack emission + baseline/augmented runs + diff."""

    pack: ExtensionPackResult
    baseline: AnalysisResult
    augmented: AnalysisResult
    diff: FindingDiff

    def to_dict(self) -> dict:
        return {
            "pack": self.pack.to_dict(),
            "baseline_sarif": str(self.baseline.sarif_path),
            "augmented_sarif": str(self.augmented.sarif_path),
            "diff": self.diff.to_dict(),
        }


def run_learned_models_measurement(
    db_path: Path,
    queries: Sequence[str],
    rows: Sequence[ModelRow],
    *,
    language: str,
    out_dir: Path,
    pack_name: str | None = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: RunnerFn | None = None,
) -> LearnedModelsMeasurement:
    """Vocab → pack → baseline/augmented runs → finding diff, end to end.

    Emits the learned-model extension pack under ``out_dir/pack``,
    runs the baseline and augmented analyses, and returns the
    :class:`FindingDiff` alongside the emission result (whose
    ``rejected`` list callers must surface — rejected rows are the
    difference between "the models found nothing" and "the models
    were never emitted").

    Raises :class:`ValueError` when every input row was rejected:
    an augmented run with an empty pack would measure nothing while
    looking like a clean zero-suppression result.
    """
    pack = write_extension_pack(
        rows, language=language, out_dir=Path(out_dir) / "pack",
        pack_name=pack_name,
    )
    if pack.rows_written == 0:
        raise ValueError(
            "no model rows survived validation; rejected: "
            + "; ".join(f"{r.row} ({r.reason})" for r in pack.rejected[:10])
        )
    baseline, augmented = run_baseline_and_augmented(
        db_path,
        queries,
        pack.pack_dir,
        Path(out_dir),
        codeql_bin=codeql_bin,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    diff = diff_sarif_files(baseline.sarif_path, augmented.sarif_path)
    return LearnedModelsMeasurement(
        pack=pack, baseline=baseline, augmented=augmented, diff=diff,
    )
