"""Atheris (Python) campaign runner.

Atheris is Google's coverage-guided Python fuzzer: libFuzzer driving a
Python ``TestOneInput(data: bytes)`` callback. This runner extends
:class:`~packages.fuzzing.libfuzzer_runner.LibFuzzerRunner` — the
process contract (sandboxed blocking run, file-backed stream capture,
bounded log-tail parsing, stats grammar, crash-artifact layout with
``crash-``/``timeout-``/``oom-`` prefixes, campaign-failure verdict)
is libFuzzer's own — and adds what Python changes:

  - the command is ``<python> <harness.py> <corpus> <libFuzzer flags>``
    instead of a native binary;
  - the campaign environment carries ``PYTHONPATH`` for the target
    package plus the interpreter runtime paths for the sandbox read
    allowlist;
  - crashes are usually uncaught Python exceptions — the exception
    type and traceback parsed from atheris's stderr become the triage
    signal on the normalized crash records.

Containment contract (the harness process IS the sandbox boundary —
atheris executes target code in-process, so the whole interpreter gets
the untrusted-target treatment):

  - Every campaign runs under ``core.sandbox.run`` with
    ``block_network=True`` (network deny), ``restrict_reads=True``
    with an explicit read allowlist (harness dir, target package,
    corpus, output dir, Python runtime roots), and write scoping to
    the run's output directory — no deletion or write path outside it.
  - The sandbox's resource rlimits apply (CPU time, per-file size,
    NPROC, NOFILE, core dumps off); libFuzzer's ``-rss_limit_mb``
    bounds resident memory in-process.
  - The environment is ``RaptorConfig.get_safe_env()`` +
    ``scrub_identity_env`` — never ambient ``os.environ``; only
    ``PYTHONPATH`` / ``PYTHONDONTWRITEBYTECODE`` are added on top.
  - Scratch is disk-backed inside the run directory (working corpus
    copied there through the bounded symlink-refusing stager; crash
    artifacts land under ``<out>/crashes``); harness output is
    captured to files, parsed as a bounded tail, and stripped of
    terminal control sequences before any operator-facing relay.

Known-and-accepted within the boundary: ``PYTHONPATH`` roots at the
target tree, so a hostile package's ``sitecustomize.py`` executes at
interpreter startup — before ``TestOneInput`` ever runs. That is
target code executing inside the same containment with no privilege
change (fuzzing runs target code by definition); nothing outside the
sandbox contract above becomes reachable through it.

Atheris itself is an optional dependency: the RUNNER never imports it
(the spawned harness does), but construction preflights that the
interpreter which will run the harness can find it, and refuses with
an install hint otherwise.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.sandbox import python_runtime_tool_paths
from packages.fuzzing.libfuzzer_runner import (
    LibFuzzerResult,
    LibFuzzerRunner,
)
from packages.fuzzing.output_hygiene import strip_terminal_controls

logger = get_logger()

ATHERIS_INSTALL_HINT = (
    "atheris is not importable by this Python interpreter. "
    "Install it with: pip install atheris"
)

# Bounds on the exception excerpt persisted into crash records and
# relayed to the operator. The traceback comes from the untrusted
# harness process's stderr.
_MAX_TRACEBACK_LINES = 40
_MAX_LINE_CHARS = 300

_EXC_HEADER = "=== Uncaught Python exception: ==="
# "ExceptionType: message" / bare "ExceptionType" / "pkg.mod.Error: m"
_EXC_TYPE_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_.]{0,200})(?::\s?(.*))?$"
)
_FRAME_RE = re.compile(
    r'^\s+File "([^"]{1,300})", line (\d{1,9})(?:, in (.{1,200}))?'
)


def _is_other_interpreter(python_executable: str) -> bool:
    """Whether *python_executable* names a different interpreter than
    the running one — by UNRESOLVED absolute path, because a venv's
    python symlinks to the base interpreter while carrying its own
    site-packages."""
    return (
        Path(python_executable).absolute()
        != Path(sys.executable).absolute()
    )


def atheris_available(python_executable: str | None = None) -> bool:
    """Whether the interpreter that will run the harness can import
    atheris.

    For the in-process interpreter this is a spec lookup (no module
    code executes). A different ``python_executable`` cannot be probed
    without running it, so it is optimistically assumed capable — the
    campaign itself fails loudly (campaign_failed) if the import dies.

    "Different" compares UNRESOLVED absolute paths: a venv's python is
    a symlink to the base interpreter, so resolving would collapse a
    venv (its own site-packages, possibly with atheris) into "same
    interpreter" and wrongly refuse it.
    """
    if python_executable and _is_other_interpreter(python_executable):
        return True
    try:
        return importlib.util.find_spec("atheris") is not None
    except (ImportError, ValueError):
        return False


@dataclass
class PythonExceptionInfo:
    """The uncaught Python exception atheris reported for a crash.

    ``stack_key`` is a short content hash over the exception type and
    the traceback's file:line frames — the Python analogue of the AFL
    path's stack hash, used for crash dedup and witness detail.
    """

    exception_type: str
    message: str = ""
    frames: list[str] = field(default_factory=list)
    stack_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "exception_type": self.exception_type,
            "message": self.message,
            "frames": list(self.frames),
            "stack_key": self.stack_key,
        }


@dataclass
class AtherisResult(LibFuzzerResult):
    """libFuzzer result plus the Python-side triage signal."""

    #: Exception parsed from the campaign's stderr (atheris exits on
    #: the first crash, so at most one is in play per run).
    python_exception: PythonExceptionInfo | None = None
    #: Normalized per-artifact crash records (also persisted to
    #: ``atheris-crashes.json`` in the output dir).
    crash_records: list[dict[str, Any]] = field(default_factory=list)


class AtherisRunner(LibFuzzerRunner):
    """Run an atheris Python harness under the fuzzing sandbox."""

    _ENGINE_NAME = "atheris"

    def __init__(
        self,
        harness_path: Path,
        *,
        target_dir: Path | None = None,
        python_executable: str | None = None,
        corpus_dir: Path | None = None,
        output_dir: Path | None = None,
        dict_path: Path | None = None,
        max_total_time: int = 600,
        max_len: int = 4096,
        timeout_seconds: int = 25,
        rss_limit_mb: int = 2048,
    ) -> None:
        self.python_executable = python_executable or sys.executable
        # An operator-suppliable interpreter path feeds the sandbox
        # read-ALLOWLIST derivation (_sandbox_tool_paths /
        # _readable_paths): a relative value like "python3" would make
        # those derive from the CWD — read-allowing whatever tree the
        # runner happened to be constructed in to hostile in-process
        # code. Validate absolute + existing BEFORE any derivation.
        exe = Path(self.python_executable)
        if not exe.is_absolute():
            msg = (
                f"python_executable must be an absolute path "
                f"(got {self.python_executable!r})"
            )
            raise ValueError(msg)
        if not exe.is_file():
            msg = f"python_executable not found: {self.python_executable}"
            raise ValueError(msg)
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        if not atheris_available(self.python_executable):
            raise RuntimeError(ATHERIS_INSTALL_HINT)
        super().__init__(
            harness_path,
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            dict_path=dict_path,
            max_total_time=max_total_time,
            max_len=max_len,
            timeout_seconds=timeout_seconds,
            rss_limit_mb=rss_limit_mb,
        )

    # ------------------------------------------------------------------
    # Subclass seams
    # ------------------------------------------------------------------

    def _validate_harness(self) -> None:
        """A Python harness is interpreter-run — no executable bit."""
        if not self.harness.is_file():
            msg = f"Atheris harness not found: {self.harness}"
            raise FileNotFoundError(msg)
        if self.harness.suffix != ".py":
            msg = f"Atheris harness must be a .py file: {self.harness}"
            raise ValueError(msg)

    def _build_command(self) -> list[str]:
        # Parent builds ``[harness, corpus, <libFuzzer flags>]``;
        # atheris passes libFuzzer flags straight through Setup(), so
        # only the interpreter prefix differs.
        return [self.python_executable, *super()._build_command()]

    def _campaign_env(self) -> dict:
        env = super()._campaign_env()
        # The harness imports the target package by name. Root the
        # import path at the target tree (plus a src/ layout child
        # when present) — never at ambient PYTHONPATH.
        py_paths: list[str] = []
        if self.target_dir is not None:
            py_paths.append(str(self.target_dir))
            src = self.target_dir / "src"
            if src.is_dir():
                py_paths.append(str(src))
        py_paths.append(str(self.harness.parent))
        env["PYTHONPATH"] = ":".join(py_paths)
        # The target tree is read-only under the sandbox; skip .pyc
        # writes rather than letting every import race a denied write.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def _sandbox_tool_paths(self) -> list[str]:
        # Interpreter runtime roots (venv prefixes, framework installs)
        # that the sandbox read allowlist must include for python to
        # start at all. python_runtime_tool_paths() inspects the
        # RUNNING interpreter — when the operator points the campaign
        # at a different one (a venv that has atheris), that venv's
        # own prefix tree (site-packages with atheris) must be
        # readable too.
        paths = python_runtime_tool_paths()
        # UNRESOLVED path for the venv-root derivation: a venv's
        # python symlinks to the base interpreter, and resolving first
        # would derive the base prefix instead of the venv tree that
        # actually holds atheris.
        exe = Path(self.python_executable).absolute()
        if _is_other_interpreter(self.python_executable) \
                and len(exe.parents) >= 2:
            venv_root = str(exe.parents[1])
            if venv_root not in paths:
                paths.append(venv_root)
        return paths

    def _readable_paths(self) -> list[str]:
        paths = super()._readable_paths()
        if self.target_dir is not None:
            paths.append(str(self.target_dir))
        exe_dir = str(Path(self.python_executable).resolve().parent)
        if exe_dir not in paths:
            paths.append(exe_dir)
        return paths

    def _new_result(self) -> AtherisResult:
        return AtherisResult(
            target=str(self.harness),
            output_dir=self.output_dir,
            corpus_dir=self.corpus_dir,
        )

    def _parse_result(
        self,
        stderr: str,
        _stdout: str,
        elapsed: float,
    ) -> AtherisResult:
        result = super()._parse_result(stderr, _stdout, elapsed)
        assert isinstance(result, AtherisResult)  # _new_result contract
        # Atheris prints the uncaught-exception block on STDOUT while
        # libFuzzer's own crash handling goes to stderr — check both,
        # stdout first (observed placement on real campaigns).
        result.python_exception = (
            parse_python_exception(_stdout)
            or parse_python_exception(stderr)
        )
        result.crash_records = self._normalize_crash_records(result)
        self._persist_crash_records(result.crash_records)
        return result

    # ------------------------------------------------------------------
    # Crash normalization
    # ------------------------------------------------------------------

    def _normalize_crash_records(
        self, result: AtherisResult,
    ) -> list[dict[str, Any]]:
        """One record per crash artifact, in the existing crash-record
        shape (``crash_id`` / ``input_file`` / triage signal). Atheris
        exits on the first crash, so the parsed exception attaches to
        every crash artifact of this run (in practice: the one)."""
        exc = result.python_exception
        records: list[dict[str, Any]] = []
        for artifact in sorted(result.crashes):
            record: dict[str, Any] = {
                "crash_id": artifact.name,
                "input_file": str(artifact),
                "engine": "atheris",
                "harness": str(self.harness),
            }
            if exc is not None:
                record.update(exc.to_dict())
                record["stack_hash"] = exc.stack_key
            records.append(record)
        return records

    def _persist_crash_records(self, records: list[dict[str, Any]]) -> None:
        # ALWAYS write, even an empty list: the output dir is inside
        # the campaign's sandbox write scope, so a hostile harness can
        # plant its own atheris-crashes.json mid-run — an early return
        # on zero records would leave that forged operator-facing
        # sidecar in place after a crash-less campaign.
        try:
            path = self.output_dir / "atheris-crashes.json"
            # Remove any planted entry first: a planted SYMLINK of
            # this name would otherwise turn our own write into an
            # arbitrary-path write outside the run dir.
            path.unlink(missing_ok=True)
            path.write_text(
                json.dumps(records, indent=2), encoding="utf-8",
            )
            if records:
                logger.info("atheris crash records: %s", path)
        except OSError as e:
            logger.warning("could not persist atheris crash records: %s", e)


def parse_python_exception(output: str) -> PythonExceptionInfo | None:
    """Parse the LAST uncaught-Python-exception block from atheris
    output (observed on stdout on real campaigns; callers check both
    streams).

    Atheris prints ``=== Uncaught Python exception: ===`` followed by
    the ``Type: message`` line and the traceback before the libFuzzer
    crash handler writes the artifact. All of it is untrusted target
    output: lines are stripped of terminal control sequences, length-
    bounded, and the frame count is capped.
    """
    idx = output.rfind(_EXC_HEADER)
    if idx < 0:
        return None
    lines = output[idx + len(_EXC_HEADER):].splitlines()

    exc_type = ""
    message = ""
    frames: list[str] = []
    for raw in lines:
        line = strip_terminal_controls(raw)[:_MAX_LINE_CHARS]
        if not exc_type:
            stripped = line.strip()
            if not stripped or stripped.startswith("Traceback"):
                continue
            match = _EXC_TYPE_RE.match(stripped)
            if match:
                exc_type = match.group(1)
                message = (match.group(2) or "").strip()
                continue
            # First non-empty line did not look like an exception —
            # bail rather than mis-attribute arbitrary output.
            return None
        frame = _FRAME_RE.match(line)
        if frame:
            path, lineno, func = frame.groups()
            frames.append(f"{path}:{lineno}:{func or '?'}")
            if len(frames) >= _MAX_TRACEBACK_LINES:
                break
    if not exc_type:
        return None

    digest = hashlib.sha256(
        "\n".join([exc_type, *frames]).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return PythonExceptionInfo(
        exception_type=exc_type,
        message=message,
        frames=frames,
        stack_key=digest,
    )
