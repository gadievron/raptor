"""CLI smoke tests for raptor.py — argparse acceptance and entry-point behavior.

Ported from the now-retired ``test/real_tests_fast.sh``. These tests verify
that the top-level ``raptor.py`` dispatcher and per-mode subparsers reject
invalid input and accept the documented flags, without actually running
any analysis. Slow-path commands (``scan``, ``agentic``) are wrapped with
a short subprocess timeout: argparse rejects unknown flags at startup
(<100 ms), so a genuine "unrecognized argument" error is captured well
before the timeout fires; reaching the timeout means argparse accepted
the flag and the command started doing real work, which is success-
equivalent for these tests.

The fixture-content greps from the original bash script (validating that
``test/data/*.py`` contains specific vulnerable patterns) were dropped
during the port — those tested the fixtures, not the code, and are
tautological. The ``py_compile`` smoke checks were also dropped: they
duplicate the existing ``compileall`` step in ``.github/workflows/tests.yml``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

# parents[3] climbs:
#   [0] core/startup/tests/  (this file's directory)
#   [1] core/startup/
#   [2] core/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_PY = REPO_ROOT / "raptor.py"

# Isolation for the spawned raptor.py children. The timeout-as-success
# pattern below SIGKILLs children mid-startup, and a killed child never
# runs its atexit cleanup, so:
#   - TMPDIR points at a pytest-managed dir — killed-child temp litter
#     (LLM-dispatcher socket dirs, clone scratch) lands there instead of
#     the shared system temp dir, and basetemp rotation removes it.
#   - HOME points at an empty dir — without it, the operator's ACTIVE
#     PROJECT (~/.raptor/projects/.active) overrides the bogus ./repo
#     argument, and a "smoke" invocation starts a real scan of the
#     project target whose detached grandchildren outlive any kill of
#     the direct child, plus junk failed-run dirs in the project's
#     output tree.
_CHILD_TMPDIR: str | None = None
_CHILD_HOME: str | None = None


@pytest.fixture(autouse=True, scope="module")
def _child_isolation(tmp_path_factory):
    global _CHILD_TMPDIR, _CHILD_HOME
    _CHILD_TMPDIR = str(tmp_path_factory.mktemp("raptor-smoke-tmp"))
    _CHILD_HOME = str(tmp_path_factory.mktemp("raptor-smoke-home"))
    yield
    _CHILD_TMPDIR = None
    _CHILD_HOME = None


@pytest.fixture(autouse=True, scope="module")
def _no_tracked_tree_side_effects():
    """Battery-side-effect guard: the spawned raptor.py children must
    never write into the RAPTOR checkout.

    Regression this pins: the --export-seed-corpus smoke test passed a
    RELATIVE path, so the child (cwd = the pytest cwd, i.e. the repo
    root) materialised the built-in corpus into ``<repo>/seeds/`` —
    every battery run regenerated seeds/manifest.json with
    machine-local paths, and one such artifact ended up committed.
    Compares porcelain status before/after the module so a dirty
    developer tree doesn't trip it — only NEW modifications fail.
    """
    def _status() -> set[str] | None:
        try:
            r = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return set(r.stdout.splitlines()) if r.returncode == 0 else None

    before = _status()
    yield
    if before is None:
        return  # not a git checkout — nothing to guard
    after = _status()
    new = (after or set()) - before
    assert not new, (
        "cli-smoke children modified the RAPTOR checkout: "
        f"{sorted(new)}"
    )


def _run_raptor(*args: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Invoke ``python raptor.py <args>`` with stdout+stderr captured.

    Timeout kills the child's whole PROCESS GROUP, not just the direct
    child. ``subprocess.run(timeout=...)`` only kills the immediate
    process — a raptor.py invocation that got past argparse has already
    forked real work (scanner subprocesses, agentic children), and
    those grandchildren survived the kill and kept running full scans
    against the operator's active project after every suite run.
    """
    env = dict(os.environ)
    if _CHILD_TMPDIR:
        env["TMPDIR"] = _CHILD_TMPDIR
    if _CHILD_HOME:
        env["HOME"] = _CHILD_HOME
    cmd = [sys.executable, str(RAPTOR_PY), *args]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()
        # Preserve subprocess.run's contract: callers distinguish
        # timeout (argparse accepted, work started) from completion.
        raise subprocess.TimeoutExpired(
            cmd, timeout, output=out, stderr=err,
        ) from None
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _argparse_accepted(*args: str, timeout: float = 3.0) -> bool:
    """Return True if argparse accepted the given args.

    Either the process completed without an "unrecognized argument" error,
    or it ran past the short timeout (meaning argparse passed and the
    command started doing real work).
    """
    try:
        r = _run_raptor(*args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return True
    return "unrecognized argument" not in (r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# Section 1: entry-point behavior
# ---------------------------------------------------------------------------


def test_no_args_exits_zero():
    """``raptor.py`` with no arguments prints help and exits 0."""
    r = _run_raptor()
    assert r.returncode == 0


def test_help_lists_available_modes():
    """No-args help output mentions ``Available Modes``."""
    r = _run_raptor()
    assert "Available Modes" in (r.stdout + r.stderr)


@pytest.mark.parametrize(
    "mode", ["scan", "binary", "fuzz", "web", "agentic", "codeql", "analyze"]
)
def test_help_lists_each_mode(mode: str):
    """Each documented mode appears somewhere in the help output."""
    r = _run_raptor()
    assert mode in (r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# Section 2: error handling
# ---------------------------------------------------------------------------


def test_invalid_mode_errors():
    """An unknown subcommand exits non-zero with an ``Unknown mode`` message."""
    r = _run_raptor("invalid_mode")
    assert r.returncode != 0
    assert "Unknown mode" in (r.stdout + r.stderr)


@pytest.mark.parametrize(
    "mode,required_keyword",
    [
        ("scan", "repo"),
        ("agentic", "repo"),
        ("fuzz", "binary"),
        ("codeql", "repo"),
    ],
)
def test_missing_required_arg_errors(mode: str, required_keyword: str):
    """Each mode errors when its required argument is missing.

    Some modes (fuzz, codeql) wrap the underlying script in a lifecycle
    helper that may hang briefly on post-scan housekeeping after the
    inner argparse error. The argparse error is still emitted to stderr
    immediately, so we capture stderr on both clean exit and timeout
    paths and check that the required-arg keyword appears.
    """
    # 20 s tolerates the ~6 s python startup + lifecycle-wrapper
    # overhead before the inner script's argparse fires (codeql/fuzz
    # routes spend ~11 s in the wrapper before the missing-arg error
    # is propagated up). Treat TimeoutExpired as a test failure path.
    try:
        r = _run_raptor(mode, timeout=20)
        combined = (r.stdout + r.stderr).lower()
        assert r.returncode != 0
    except subprocess.TimeoutExpired as e:
        def _text(x):
            if isinstance(x, bytes):
                return x.decode("utf-8", errors="replace")
            return x or ""
        combined = (_text(e.stdout) + _text(e.stderr)).lower()

    assert (
        required_keyword in combined
        or "required" in combined
        or "error" in combined
    )


# ---------------------------------------------------------------------------
# Section 3: argument recognition (argparse acceptance only)
# ---------------------------------------------------------------------------


def test_scan_accepts_policy_groups_underscore():
    """``scan --policy_groups`` (underscore) is accepted by argparse."""
    assert _argparse_accepted(
        "scan", "--repo", "./repo", "--policy_groups", "secrets"
    )


def test_agentic_accepts_codeql_flag():
    assert _argparse_accepted("agentic", "--repo", "./repo", "--codeql")


def test_agentic_accepts_no_codeql_flag():
    assert _argparse_accepted("agentic", "--repo", "./repo", "--no-codeql")


def test_agentic_accepts_max_findings():
    assert _argparse_accepted(
        "agentic", "--repo", "./repo", "--max-findings", "10"
    )


def test_agentic_accepts_threat_model_use_stale():
    assert _argparse_accepted(
        "agentic", "--repo", "./repo", "--threat-model-use-stale"
    )


def test_fuzz_accepts_duration():
    assert _argparse_accepted(
        "fuzz", "--binary", "./bin", "--duration", "60"
    )


def test_fuzz_accepts_parallel():
    assert _argparse_accepted(
        "fuzz", "--binary", "./bin", "--parallel", "4"
    )


def test_fuzz_accepts_autonomous():
    assert _argparse_accepted("fuzz", "--binary", "./bin", "--autonomous")


def test_fuzz_accepts_export_seed_corpus_without_binary(tmp_path):
    # Absolute tmp destination: --export-seed-corpus completes fast
    # (it is not timeout-killed like the scan modes), so a relative
    # path would materialise the corpus into the child's cwd — the
    # repo root (see _no_tracked_tree_side_effects).
    assert _argparse_accepted(
        "fuzz", "--export-seed-corpus", str(tmp_path / "seeds"),
    )


# ---------------------------------------------------------------------------
# Section 3b: `<mode> --help` is side-effect-free
# ---------------------------------------------------------------------------
#
# Regression guard: `<mode> --help` used to fall through to the mode handler,
# which wraps the child in the run lifecycle — resolving a target, creating
# AND sealing an output directory, printing the OUTPUT_DIR sentinel + license
# + cost-estimate preamble, and starting the LLM dispatcher, all before the
# child argparse ever processed --help. A help request must do none of that.


# Every recognised mode, with a substring that proves its OWN help rendered.
# (sca/doctor render bespoke usage text, not an argparse "usage:" line.)
_HELP_MARKER = {
    "scan": "usage:",
    "binary": "raptor-binary",
    "fuzz": "usage:",
    "web": "usage:",
    "agentic": "usage:",
    "codeql": "usage:",
    "analyze": "usage:",
    "sca": "raptor-sca",
    "doctor": "raptor doctor",
}


@pytest.mark.parametrize("mode", sorted(_HELP_MARKER))
@pytest.mark.parametrize("help_flag", ["--help", "-h"])
def test_mode_help_is_side_effect_free(mode: str, help_flag: str):
    """`<mode> --help`/`-h` prints only that mode's help and exits 0.

    Asserts no run lifecycle ever engaged (no OUTPUT_DIR sentinel, license,
    or "[*] Starting" preamble), no LLM dispatcher started, and the mode's
    own help DID render. The OUTPUT_DIR sentinel is the lifecycle's first
    observable action (printed right after the run dir is created), so its
    absence also proves no run directory was created.
    """
    r = _run_raptor(mode, help_flag, timeout=20)
    combined = r.stdout + r.stderr
    assert r.returncode == 0, f"{mode} {help_flag} exited {r.returncode}: {combined}"
    assert "OUTPUT_DIR=" not in combined, f"lifecycle ran for {mode} {help_flag}"
    assert "Target license:" not in combined
    assert "[*] Starting" not in combined
    assert "llm-dispatcher server.start" not in combined, "dispatcher started"
    assert _HELP_MARKER[mode].lower() in combined.lower(), "mode help did not render"


# ---------------------------------------------------------------------------
# Section 4: module-import smoke
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module",
    ["raptor", "raptor_agentic", "raptor_fuzzing", "raptor_codeql"],
)
def test_top_level_module_imports(module: str):
    """Top-level dispatcher modules import cleanly with the repo on sys.path."""
    r = subprocess.run(
        [
            sys.executable,
            "-c",
            (f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
             f"import {module}"),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert r.returncode == 0, f"import failed: {r.stderr}"


def test_core_config_imports():
    """``core.config`` imports cleanly."""
    r = subprocess.run(
        [
            sys.executable,
            "-c",
            (f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
             "from core import config"),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert r.returncode == 0, f"import failed: {r.stderr}"
