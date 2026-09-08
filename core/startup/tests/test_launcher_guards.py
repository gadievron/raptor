"""Behavioural tests for ``bin/raptor`` launch-path guards.

Same CLI-smoke shape as ``test_launcher_hardening.py``: the launcher is
a bash script, so each test spawns it with a controlled environment and
asserts on observable effects (stderr messages, exit codes, and — via a
stub ``claude`` on PATH — the state and argv at the final exec
boundary).

Covered guards:

* RAPTOR_CALLER_DIR control-byte refusal — must actually match C0
  bytes (newline, ESC, tab, ...). NUL needs no case: bash variables
  cannot hold NUL, so ``$(pwd)`` can never carry one into the check.
* ``--version`` fast path — must run AFTER the dangerous-env strip so
  the exec'd interpreter cannot be steered by PYTHONPATH et al.
* ``clear`` is best-effort — a TERM-less environment must not abort
  the launcher under ``set -e``.
* Control-stripped TARGET — the trust-check target and the initial
  prompt must name the same (stripped) path.
* ``bin/cve-env`` / ``bin/cve-diff`` — the PYTHON*-family sweep from
  ``bin/raptor-sca`` applies before their interpreters start.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="bash launcher"
)


def _system_path_dirs() -> list[str]:
    dirs = [str(Path(sys.executable).resolve().parent)]
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if os.path.isdir(d):
            dirs.append(d)
    return dirs


def _make_stub_claude(tmp_path: Path) -> Path:
    """A fake ``claude`` that reports its argv and inherited env."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "claude"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "echo STUB_CLAUDE_RAN\n"
        'echo "CALLER_DIR_SEEN=${RAPTOR_CALLER_DIR:-}"\n'
        'echo "AGENT_CLI_SEEN=${RAPTOR_AGENT_CLI:-}"\n'
        'printf \'ARG:%s\\n\' "$@"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub_dir


def _make_stub_copilot(tmp_path: Path) -> Path:
    """A fake ``copilot`` that exposes the required help and final argv."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "copilot"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "${1:-}" = "--help" ]; then\n'
        '  if [ "${STUB_COPILOT_INCOMPLETE_HELP:-}" = "1" ]; then\n'
        "    printf '%s\\n' --model --continue\n"
        "  else\n"
        "    printf '%s\\n' --plugin-dir --model --continue --interactive "
        "--agent --available-tools --allow-tool --deny-tool "
        "--disable-builtin-mcps --no-custom-instructions --no-ask-user "
        "--secret-env-vars --output-format --stream --usage-output-file "
        "--experimental --disallow-temp-dir --no-auto-update "
        "--no-remote-export\n"
        "  fi\n"
        "  exit 0\n"
        "fi\n"
        "echo STUB_COPILOT_RAN\n"
        'echo "CALLER_DIR_SEEN=${RAPTOR_CALLER_DIR:-}"\n'
        'echo "AGENT_CLI_SEEN=${RAPTOR_AGENT_CLI:-}"\n'
        'echo "COPILOT_MODEL_SEEN=${RAPTOR_COPILOT_MODEL:-}"\n'
        'echo "COPILOT_MODEL_EXPLICIT_SEEN=${RAPTOR_COPILOT_MODEL_EXPLICIT:-}"\n'
        'echo "COPILOT_AUTH_SOCKET_SEEN=${RAPTOR_COPILOT_AUTH_SOCKET:-}"\n'
        'printf \'ARG:%s\\n\' "$@"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub_dir


def _launch(
    tmp_path: Path,
    *args: str,
    cwd: Path | None = None,
    term: str | None = "xterm",
    extra_env: dict | None = None,
) -> subprocess.CompletedProcess:
    stub_dir = _make_stub_claude(tmp_path)
    _make_stub_copilot(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(exist_ok=True)
    env = {
        "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        **(extra_env or {}),
    }
    if term is not None:
        env["TERM"] = term
    return subprocess.run(
        ["bash", str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=str(cwd or home),
        check=False,
    )


# ---------------------------------------------------------------------------
# RAPTOR_CALLER_DIR control-byte guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("byte,label", [("\n", "newline"), ("\x1b", "esc")])
def test_caller_dir_with_control_byte_refused(tmp_path, byte, label):
    hostile = tmp_path / f"a{byte}b"
    hostile.mkdir()
    r = _launch(tmp_path, cwd=hostile)
    assert r.returncode == 1, (label, r.stdout, r.stderr)
    assert "control bytes" in r.stderr, (label, r.stderr)
    assert "STUB_CLAUDE_RAN" not in r.stdout, label


def test_caller_dir_plain_path_allowed(tmp_path):
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    r = _launch(tmp_path, cwd=plain)
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    seen = [
        ln.split("CALLER_DIR_SEEN=", 1)[1]
        for ln in r.stdout.splitlines()
        if "CALLER_DIR_SEEN=" in ln
    ]
    assert seen and seen[0] == str(plain), r.stdout


# ---------------------------------------------------------------------------
# Agent CLI selection and argument mapping
# ---------------------------------------------------------------------------


def _args(stdout: str) -> list[str]:
    return [line.removeprefix("ARG:") for line in stdout.splitlines()
            if line.startswith("ARG:")]


def test_launcher_keeps_claude_as_default(tmp_path):
    r = _launch(tmp_path)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "STUB_CLAUDE_RAN" in r.stdout
    assert "STUB_COPILOT_RAN" not in r.stdout
    assert "AGENT_CLI_SEEN=claude" in r.stdout


def test_copilot_launcher_uses_default_model_and_interactive_prompt(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    r = _launch(tmp_path, "--copilot", str(target))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "STUB_COPILOT_RAN" in r.stdout
    assert "STUB_CLAUDE_RAN" not in r.stdout
    assert "AGENT_CLI_SEEN=copilot" in r.stdout
    assert "COPILOT_MODEL_SEEN=gpt-5.6-sol" in r.stdout
    assert "COPILOT_MODEL_EXPLICIT_SEEN=0" in r.stdout
    args = _args(r.stdout)
    assert "--model" in args
    assert args[args.index("--model") + 1] == "gpt-5.6-sol"
    assert "--interactive" in args
    assert args[args.index("--interactive") + 1] == f"/raptor {target}"
    assert "--plugin-dir" in args
    assert str(REPO_ROOT / "plugins" / "coverage") in args
    assert (
        "--secret-env-vars=COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN,"
        "RAPTOR_SESSION_TOKEN"
    ) in args
    assert "--allow-tool=shell(libexec/raptor-agentic:*)" in args
    assert "--allow-tool=shell(libexec/raptor-pid1-shim:*)" not in args
    assert "--allow-tool=shell(libexec/raptor-seatbelt-shim:*)" not in args
    assert "--allow-tool=shell(libexec/raptor-*:*)" not in args


def test_copilot_launcher_honours_explicit_model_and_verbose(tmp_path):
    r = _launch(
        tmp_path,
        "--copilot",
        "--model=claude-fable-5.1",
        "--verbose",
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "COPILOT_MODEL_SEEN=claude-fable-5.1" in r.stdout
    assert "COPILOT_MODEL_EXPLICIT_SEEN=1" in r.stdout
    args = _args(r.stdout)
    assert args.count("--model") == 1
    assert args[args.index("--model") + 1] == "claude-fable-5.1"
    assert args[args.index("--log-level") + 1] == "debug"


def test_copilot_launcher_starts_env_token_broker(tmp_path):
    token = "github_pat_test_only"
    r = _launch(
        tmp_path,
        "--copilot",
        extra_env={"COPILOT_GITHUB_TOKEN": token},
    )

    assert r.returncode == 0, (r.stdout, r.stderr)
    socket_lines = [
        line.removeprefix("COPILOT_AUTH_SOCKET_SEEN=")
        for line in r.stdout.splitlines()
        if line.startswith("COPILOT_AUTH_SOCKET_SEEN=")
    ]
    assert socket_lines and socket_lines[0]
    assert token not in r.stdout
    assert token not in r.stderr


def test_copilot_continue_does_not_override_resumed_model(tmp_path):
    r = _launch(tmp_path, "--copilot", "--continue")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "COPILOT_MODEL_SEEN=auto" in r.stdout
    assert "COPILOT_MODEL_EXPLICIT_SEEN=1" in r.stdout
    args = _args(r.stdout)
    assert "--continue" in args
    assert "--interactive" not in args
    assert "--model" not in args


def test_copilot_launcher_rejects_incompatible_cli(tmp_path):
    r = _launch(
        tmp_path,
        "--copilot",
        extra_env={"STUB_COPILOT_INCOMPLETE_HELP": "1"},
    )
    assert r.returncode == 1
    assert "lacks required flag --plugin-dir" in r.stderr
    assert "copilot update" in r.stderr
    assert "STUB_COPILOT_RAN" not in r.stdout


def test_copilot_launcher_blocks_target_owned_agent_config(tmp_path):
    target = tmp_path / "target-with-agent-config"
    target.mkdir()
    (target / "AGENTS.md").write_text("target instructions", encoding="utf-8")
    r = _launch(tmp_path, "--copilot", str(target))
    assert r.returncode == 2
    assert "target-owned Copilot config" in r.stdout
    assert "STUB_COPILOT_RAN" not in r.stdout


def test_copilot_launcher_trust_override_allows_agent_config(tmp_path):
    target = tmp_path / "trusted-target"
    target.mkdir()
    (target / "AGENTS.md").write_text("trusted instructions", encoding="utf-8")
    r = _launch(tmp_path, "--copilot", "--trust-repo", str(target))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "trust override active" in r.stdout
    assert "STUB_COPILOT_RAN" in r.stdout
    args = _args(r.stdout)
    assert args[args.index("--interactive") + 1] == (
        f"/raptor {target} --trust-repo"
    )
    entries = [
        path
        for path in (
            tmp_path / "home" / ".local" / "share" / "raptor" / "sessions.d"
        ).glob("[0-9]*")
        if path.name.isdigit()
    ]
    assert entries
    assert (
        f"repo_trusted={target}"
        in entries[0].read_text(encoding="utf-8")
    )


# ---------------------------------------------------------------------------
# --version fast path runs after the dangerous-env strip
# ---------------------------------------------------------------------------


def test_version_fast_path_env_stripped(tmp_path):
    """PYTHONPATH must not survive into the --version interpreter.

    Mechanism: a ``sitecustomize.py`` on PYTHONPATH is imported at
    interpreter start and drops a marker file. The control leg proves
    the mechanism fires for a plain python3; the launcher leg proves
    the strip removed PYTHONPATH before exec'ing python3.
    """
    payload = tmp_path / "payload"
    payload.mkdir()
    marker = tmp_path / "marker"
    (payload / "sitecustomize.py").write_text(
        f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n",
        encoding="utf-8",
    )
    env = {
        "PATH": ":".join(_system_path_dirs()),
        "HOME": str(tmp_path / "home"),
        "TERM": "xterm",
        "PYTHONPATH": str(payload),
    }
    (tmp_path / "home").mkdir(exist_ok=True)

    # Control: the payload mechanism works for an unstripped interpreter.
    subprocess.run(
        [sys.executable, "-c", "pass"],
        env=env, capture_output=True, timeout=60, check=False,
    )
    assert marker.exists(), "control leg: sitecustomize never fired"
    marker.unlink()

    r = subprocess.run(
        ["bash", str(LAUNCHER), "--version"],
        env=env, capture_output=True, text=True, timeout=120,
        cwd=str(tmp_path / "home"), check=False,
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not marker.exists(), (
        "PYTHONPATH survived into the --version interpreter"
    )


# ---------------------------------------------------------------------------
# clear is best-effort under set -e
# ---------------------------------------------------------------------------


def test_termless_launch_survives_clear(tmp_path):
    r = _launch(tmp_path, term=None)
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)


# ---------------------------------------------------------------------------
# Control-stripped TARGET: prompt and trust-gate name the same path
# ---------------------------------------------------------------------------


def test_control_byte_target_stripped_consistently(tmp_path):
    stripped = tmp_path / "targetdir"
    stripped.mkdir()
    raw = str(stripped.parent / "target\ndir")
    r = _launch(tmp_path, raw)
    assert "contained control bytes" in r.stderr, r.stderr
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    prompt_args = [
        ln for ln in r.stdout.splitlines() if ln.startswith("ARG:/raptor")
    ]
    assert prompt_args, r.stdout
    # The prompt names the stripped spelling; the raw (unstripped)
    # spelling must not leak into the exec'd argv.
    assert prompt_args[-1] == f"ARG:/raptor {stripped.parent}/targetdir"


# ---------------------------------------------------------------------------
# cve-env / cve-diff: PYTHON*-family sweep before exec python3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("launcher", ["cve-env", "cve-diff"])
def test_cve_launchers_sweep_python_family(tmp_path, launcher):
    """PYTHONWARNINGS et al. must not survive into the interpreter.

    A stub ``python3`` on PATH reports the PYTHON* env it inherits, so
    no real CLI deps are needed. PYTHONPATH is exempt: the launcher
    re-sets it explicitly after the sweep.
    """
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "python3"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "env | grep '^PYTHON' || true\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = {
        "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
        "HOME": str(tmp_path),
        "PYTHONWARNINGS": "error::UserWarning",
        "PYTHONFAULTHANDLER": "1",
    }
    r = subprocess.run(
        ["bash", str(REPO_ROOT / "bin" / launcher)],
        env=env, capture_output=True, text=True, timeout=60,
        cwd=str(tmp_path), check=False,
    )
    assert "PYTHONWARNINGS" not in r.stdout, (r.stdout, r.stderr)
    assert "PYTHONFAULTHANDLER" not in r.stdout, (r.stdout, r.stderr)
    # Two-direction: the launcher still hands the interpreter its own
    # explicit PYTHONPATH (repo root first).
    assert "PYTHONPATH=" in r.stdout, (r.stdout, r.stderr)
