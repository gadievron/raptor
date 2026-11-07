"""Codex startup display and launch-data transport contracts."""
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tomllib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[3]
ADAPTER = ROOT / ".codex/hooks/session_start.py"


def test_hook_is_only_banner_renderer_and_context_does_not_repeat_it(monkeypatch, capsys):
    module = runpy.run_path(str(ADAPTER))
    payload = '{"hook_event_name":"SessionStart","session_id":"native"}'
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with patch("subprocess.run", return_value=SimpleNamespace(
            returncode=0, stdout="exact banner\n", stderr="")) as run:
        assert module["main"]() == 0
    assert run.call_args.kwargs["input"] == payload
    assert run.call_args.args[0] == [sys.executable, "-I", str(ROOT / "libexec/raptor-session-init")]
    output = json.loads(capsys.readouterr().out)
    assert output["systemMessage"] == "\nexact banner\n\n" + module["QUICK_COMMANDS"]
    context = output["hookSpecificOutput"]["additionalContext"]
    assert "exact banner" not in context
    assert "RAPTOR_CODEX_STARTUP_COMPLETE" in context
    assert "reply exactly 'Ready.'" in context
    assert output["hookSpecificOutput"]["hookEventName"] == "SessionStart"


@pytest.mark.parametrize("code,banner", [(1, ""), (2, "partial banner"), (0, "")])
def test_hook_failure_never_claims_banner_was_displayed(monkeypatch, capsys, code, banner):
    module = runpy.run_path(str(ADAPTER))
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    with patch("subprocess.run", return_value=SimpleNamespace(
            returncode=code, stdout=banner, stderr="initialization failed\n")):
        assert module["main"]() != 0
    output = capsys.readouterr()
    assert not output.out
    assert "initialization failed" in output.err


@pytest.mark.parametrize("target", ["", 'relative target; $(false); "quoted"', "emoji-🦖\nnext"])
def test_launch_config_survives_toml_without_shell_interpretation(tmp_path, target):
    import os
    caller = str(tmp_path / "caller with spaces")
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "libexec/raptor-session-init"),
         "--codex-launch-config", caller, target],
        env={**os.environ, "_RAPTOR_TRUSTED": "1", "HOME": str(tmp_path),
             "RAPTOR_CODEX_ENVIRONMENT": "1"},
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    settings = {}
    for line in result.stdout.splitlines():
        settings.update(tomllib.loads(line)["shell_environment_policy"]["set"])
    assert settings == {"RAPTOR_CALLER_DIR": caller, "RAPTOR_LAUNCH_TARGET": target}
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("resume,target,prompt", [
    ("", "", True),
    ("", 'target with spaces; $(false)', True),
    ("1", "relative target", False),
    ("1", 'target with spaces; $(false)', False),
    ("1", "", False),
])
def test_codex_launcher_passes_short_trigger_and_separate_data(tmp_path, resume, target, prompt):
    import os
    import shutil
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "codex"
    stub.write_text("#!" + sys.executable + "\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    stub.chmod(0o755)
    launcher = (ROOT / "bin/raptor").read_text()
    start = launcher.index('if [ -n "$USE_CODEX" ]; then', launcher.index('# Codex has its own config'))
    end = launcher.index('\n# Load coverage tracking plugin', start)
    block = launcher[start:end]
    script = 'CODEX_ARGS=(--model fixture)\n_rp() { "$@"; }\n' + block
    env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
           "USE_CODEX": "1", "RESUME_SESSION": resume, "RAPTOR_LAUNCH_TARGET": target,
           "RAPTOR_CALLER_DIR": str(tmp_path), "RAPTOR_DIR": str(ROOT), "_RAPTOR_TRUSTED": "1"}
    result = subprocess.run([shutil.which("bash"), "-c", script], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout)
    assert args[:2] == (["resume", "--last"] if resume else ["--model", "fixture"])
    if prompt:
        assert args[-1] == "Loading RAPTOR ..."
    else:
        assert "Loading RAPTOR ..." not in args
    # Target/caller transport is independent of whether a chat prompt is sent.
    settings = {}
    for index, arg in enumerate(args):
        if arg == "-c":
            settings.update(tomllib.loads(args[index + 1])["shell_environment_policy"]["set"])
    if not resume or target:
        assert settings == {"RAPTOR_CALLER_DIR": str(tmp_path), "RAPTOR_LAUNCH_TARGET": target}
    else:
        assert settings == {}
    assert "Read .claude/commands/raptor.md" not in " ".join(args)
