"""CLI smoke tests for raptor.py — argparse acceptance and entry-point behavior.

Ported from the now-retired ``test/real_tests_fast.sh``. These tests verify
that the top-level ``raptor.py`` dispatcher and per-mode subparsers reject
invalid input and accept the documented flags, without actually running
any analysis. Argument probes use the dispatcher's real mode-script map
and require argparse to reject only a deliberate unknown sentinel. This
proves the requested flags were parsed and stops before analysis begins.
Timeouts and startup crashes are failures. Dispatcher lifecycle behavior
remains covered by the separate entry-point and routing tests.

The fixture-content greps from the original bash script (validating that
``test/data/*.py`` contains specific vulnerable patterns) were dropped
during the port — those tested the fixtures, not the code, and are
tautological. The ``py_compile`` smoke checks were also dropped: they
duplicate the existing ``compileall`` step in ``.github/workflows/tests.yml``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from core.testing.processes import reap_on_exit
from core.testing.standalone_cli import run_standalone_cli, standalone_cli_env

# parents[3] climbs:
#   [0] core/startup/tests/  (this file's directory)
#   [1] core/startup/
#   [2] core/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_PY = REPO_ROOT / "raptor.py"

# Isolation for the spawned raptor.py children. Cold dispatcher checks can
# kill children mid-startup, and a killed child never
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
#   - RAPTOR_CALLER_DIR is stripped — it is the OTHER layer of the
#     default-target chain (resolve_default_target: active project,
#     then $RAPTOR_CALLER_DIR). Launcher sessions export it, so with
#     HOME isolated but the variable inherited, ``raptor.py scan`` /
#     ``agentic`` with no --repo back-fill a real target and start a
#     full scan of the launcher's caller directory. The missing-arg
#     tests then ride their 20 s timeout, and the group SIGKILL cannot
#     reach the scan's sandboxed workers (each is spawned as a new
#     session leader): the orphaned workers run on for hours holding
#     the inherited stdout/stderr — on CI the runner waits for pipe
#     EOF after a green summary, so the suite's step hangs.
#   - RAPTOR_OUT_DIR points into the child TMPDIR — run-lifecycle
#     litter from killed children (failed-run dirs, run ledgers,
#     project output bases) lands under basetemp rotation instead of
#     the checkout's ``out/`` tree (gitignored, so the porcelain guard
#     below never sees it).
_CHILD_TMPDIR: str | None = None
_CHILD_HOME: str | None = None
_CHILD_OUT_DIR: str | None = None


@pytest.fixture(autouse=True, scope="module")
def _child_isolation(tmp_path_factory):
    """Restore borrowed child paths even if a later allocation fails."""
    with pytest.MonkeyPatch.context() as patch:
        for name, prefix in (
            ("_CHILD_TMPDIR", "raptor-smoke-tmp"),
            ("_CHILD_HOME", "raptor-smoke-home"),
            ("_CHILD_OUT_DIR", "raptor-smoke-out"),
        ):
            patch.setitem(globals(), name, str(tmp_path_factory.mktemp(prefix)))
        yield


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


def _child_env() -> dict[str, str]:
    """Give every smoke child the same disposable startup state."""
    env = dict(os.environ)
    if _CHILD_TMPDIR:
        env["TMPDIR"] = _CHILD_TMPDIR
    if _CHILD_HOME:
        env["HOME"] = _CHILD_HOME
    if _CHILD_OUT_DIR:
        env["RAPTOR_OUT_DIR"] = _CHILD_OUT_DIR
    # No default target may reach the children: with the launcher's
    # RAPTOR_CALLER_DIR inherited, a no---repo scan/agentic back-fills
    # a REAL target and starts real analysis work (see the isolation
    # comment at _CHILD_TMPDIR).
    env.pop("RAPTOR_CALLER_DIR", None)
    return env


def _run_smoke_command(cmd, *, env, timeout, cwd=None) -> subprocess.CompletedProcess:
    """Capture and reap the whole owned process group on every exit path."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=cwd,
        start_new_session=True,
    )
    with reap_on_exit(proc, process_group=True):
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            # Publish the observed exit before a second I/O failure can
            # enter the cleanup owner and signal the same group again.
            proc.wait(timeout=5)
            out, err = proc.communicate()
            # Preserve subprocess.run's timeout diagnostics for callers.
            raise subprocess.TimeoutExpired(
                cmd, timeout, output=out, stderr=err,
            ) from None
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _run_raptor(*args: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Invoke the real dispatcher with bounded, group-owned child execution."""
    return _run_smoke_command(
        [sys.executable, str(RAPTOR_PY), *args], env=_child_env(), timeout=timeout,
    )


_PARSER_SENTINEL = "--raptor-smoke-parser-sentinel"
_MODE_BOOTSTRAP = '''
import runpy
import sys
sys.path.insert(0, sys.argv.pop(1))
from raptor import _mode_help_scripts
script = _mode_help_scripts()[sys.argv.pop(1)]
sys.argv[0] = str(script)
runpy.run_path(str(script), run_name="__main__")
'''


def _run_mode_script(*args: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a real mode script with owned state and no dispatcher lifecycle."""
    with standalone_cli_env(env=_child_env()) as env:
        # gettext can prefer LANGUAGE over LC_ALL for argparse diagnostics.
        env.update(LC_ALL="C", LANGUAGE="C")
        return _run_smoke_command(
            [sys.executable, "-I", "-c", _MODE_BOOTSTRAP, str(REPO_ROOT),
             *args],
            env=env, timeout=timeout, cwd=env["HOME"],
        )


def _run_mode_parser(*args: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run the actual mode script, stopping at the unknown sentinel argument."""
    return _run_mode_script(*args, _PARSER_SENTINEL, timeout=timeout)


def _argparse_accepted(*args: str, timeout: float = 10.0) -> bool:
    """Require completed parsing that rejects exactly the sentinel flag."""
    try:
        r = _run_mode_parser(*args, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        print(f"mode parser did not finish: {exc}", file=sys.stderr)
        return False
    accepted = r.returncode == 2 and r.stderr.rstrip().endswith(
        f": error: unrecognized arguments: {_PARSER_SENTINEL}",
    )
    if not accepted:
        print(f"mode parser did not reject only the sentinel (exit {r.returncode}):\n"
              + (r.stdout + r.stderr)[-4000:], file=sys.stderr)
    return accepted


def test_import_child_environment_is_isolated(monkeypatch):
    """Import probes keep the LLM tripwire but cannot discover session targets."""
    monkeypatch.setenv("HOME", "/operator-home")
    monkeypatch.setenv("TMPDIR", "/operator-tmp")
    monkeypatch.setenv("RAPTOR_OUT_DIR", "/operator-output")
    monkeypatch.setenv("RAPTOR_CALLER_DIR", "/operator-target")
    # Preserve arbitrary inherited settings, including tripwire configuration.
    monkeypatch.setenv("RAPTOR_SMOKE_SENTINEL", "retained")
    before = dict(os.environ)
    env = _child_env()
    assert env["HOME"] == _CHILD_HOME
    assert env["TMPDIR"] == _CHILD_TMPDIR
    assert env["RAPTOR_OUT_DIR"] == _CHILD_OUT_DIR
    assert "RAPTOR_CALLER_DIR" not in env
    assert env["RAPTOR_SMOKE_SENTINEL"] == "retained"
    assert dict(os.environ) == before


# ---------------------------------------------------------------------------
# Section 1: entry-point behavior
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dispatcher_help(_child_isolation):
    """Capture the real dispatcher once for its independent help assertions."""
    return _run_raptor()


def test_no_args_exits_zero(dispatcher_help):
    """``raptor.py`` with no arguments prints help and exits 0."""
    r = dispatcher_help
    assert r.returncode == 0


def test_help_lists_available_modes(dispatcher_help):
    """No-args help output mentions ``Available Modes``."""
    r = dispatcher_help
    assert "Available Modes" in (r.stdout + r.stderr)


@pytest.mark.parametrize(
    "mode", ["scan", "binary", "fuzz", "web", "agentic", "codeql", "analyze"]
)
def test_help_lists_each_mode(mode: str, dispatcher_help):
    """Each documented mode appears somewhere in the help output."""
    r = dispatcher_help
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
        # Full dispatcher imports and lifecycle teardown belong in slow CI.
        pytest.param("scan", "repo", marks=pytest.mark.slow),
        pytest.param("agentic", "repo", marks=pytest.mark.slow),
        ("fuzz", "binary"),
        # Cold CodeQL startup plus lifecycle teardown exceeds the fast-tier
        # budget; preserve this full dispatcher path in slow CI.
        pytest.param("codeql", "repo", marks=pytest.mark.slow),
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
    # is propagated up). On timeout, retain captured argparse diagnostics
    # for the assertions below.
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


@pytest.mark.slow  # Preserve full cold dispatcher coverage in the slow tier.
@pytest.mark.parametrize("mode", ["scan", "agentic"])
def test_missing_repo_errors_even_with_caller_dir(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A launcher-exported RAPTOR_CALLER_DIR must not reach the children.

    Regression this pins: the default-target chain (active project,
    then $RAPTOR_CALLER_DIR) back-filled --repo for scan/agentic when
    the suite ran inside a launcher session, so the missing-arg smoke
    invocations started REAL full scans of the caller directory. They
    rode their timeout, and the group SIGKILL could not reach the
    scan's sandboxed workers (new session leaders) — the orphans kept
    scanning for hours and held the suite's stdout/stderr pipe, which
    hung the CI step after a green summary. ``_run_raptor`` now strips
    RAPTOR_CALLER_DIR from the child env; with HOME already isolated,
    no default target can resolve and the child must error out.
    """
    caller_dir = tmp_path / "caller-target"
    caller_dir.mkdir()
    # Non-empty real directory: the volatile-target sanity gate refuses
    # empty/scratch defaults, which would mask the regression by
    # erroring for the wrong reason.
    (caller_dir / "app.py").write_text("x = 1\n")
    monkeypatch.setenv("RAPTOR_CALLER_DIR", str(caller_dir))
    try:
        r = _run_raptor(mode, timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"{mode} with no --repo started real work from "
            "RAPTOR_CALLER_DIR instead of erroring"
        )
    assert r.returncode != 0, (
        f"{mode} with no --repo resolved a default target from "
        f"RAPTOR_CALLER_DIR and ran to completion:\n{r.stdout}{r.stderr}"
    )
    combined = (r.stdout + r.stderr).lower()
    assert "repo" in combined or "required" in combined or "error" in combined


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
    # Exercise the real utility: parser acceptance alone cannot prove that
    # post-parse validation permits exporting without --binary.
    destination = tmp_path / "seeds"
    result = _run_mode_script("fuzz", "--export-seed-corpus", str(destination))
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((destination / "manifest.json").read_text())
    assert manifest["seed_count"] > 0


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


@pytest.mark.slow  # Full cold interpreter + source inventory + mode imports.
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


@pytest.mark.slow  # Genuine cold dependency graph; preserve the complete import.
@pytest.mark.parametrize(
    "module",
    ["raptor", "raptor_agentic", "raptor_fuzzing", "raptor_codeql"],
)
def test_top_level_module_imports(module: str):
    """Top-level dispatcher modules import cleanly with the repo on sys.path."""
    r = run_standalone_cli(
        [
            sys.executable,
            "-c",
            (f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
             f"import {module}"),
        ],
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert r.returncode == 0, f"import failed: {r.stderr}"


def test_core_config_imports():
    """``core.config`` imports cleanly."""
    r = run_standalone_cli(
        [
            sys.executable,
            "-c",
            (f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
             "from core import config"),
        ],
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert r.returncode == 0, f"import failed: {r.stderr}"



def test_timeout_reaps_before_followup_communication(monkeypatch):
    import io
    import sys

    from core.testing import processes
    from core.testing.module_bindings import patch_module_attribute

    class Child:
        pid = 12345
        returncode = None
        stdin = None

        def __init__(self):
            self.stdout = io.StringIO()
            self.stderr = io.StringIO()
            self.calls = 0

        def communicate(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(["owned"], 0.1)
            assert self.returncode == -signal.SIGKILL, "child was not reaped before follow-up I/O"
            return "partial", "diagnostic"

        def wait(self, *, timeout):
            self.returncode = -signal.SIGKILL
            return self.returncode

    child = Child()
    signals = []
    owner = sys.modules[__name__]
    patch_module_attribute(monkeypatch, owner, "subprocess", "Popen", lambda *a, **kw: child)
    signal_group = lambda pid, sig: signals.append((pid, sig))
    # Both cleanup owners are private; a failing regression never signals a PID.
    patch_module_attribute(monkeypatch, owner, "os", "killpg", signal_group)
    patch_module_attribute(monkeypatch, processes, "os", "killpg", signal_group)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        _run_smoke_command(["owned"], env={}, timeout=0.1)
    assert caught.value.output == "partial"
    assert caught.value.stderr == "diagnostic"
    assert signals == [(child.pid, signal.SIGKILL)]
    assert child.stdout.closed and child.stderr.closed
