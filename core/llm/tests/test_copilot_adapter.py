"""Tests for the GitHub Copilot CLI subprocess adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.llm import copilot_adapter as ca


def _config(**kwargs) -> ca.CopilotDispatchConfig:
    defaults = {
        "copilot_bin": "/usr/bin/copilot",
        "model": "gpt-5.6-sol",
    }
    defaults.update(kwargs)
    return ca.CopilotDispatchConfig(**defaults)


def test_build_command_keeps_prompt_out_of_argv(tmp_path):
    usage = tmp_path / "usage.json"
    cmd = ca.build_copilot_command(
        _config(system_prompt="secret system", tools=()),
        workspace=tmp_path,
        usage_path=usage,
        model="gpt-5.6-sol",
    )
    joined = "\0".join(cmd)
    assert "secret system" not in joined
    assert "--output-format" in cmd
    assert cmd[cmd.index("--output-format") + 1] == "json"
    assert "--available-tools=view" in cmd
    assert "--deny-tool=read" in cmd
    assert (
        "--secret-env-vars=COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN,"
        "RAPTOR_SESSION_TOKEN"
        in cmd
    )
    assert "-p" not in cmd


def test_build_command_maps_tools_and_permissions(tmp_path):
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    cmd = ca.build_copilot_command(
        _config(
            tools="Read,Grep,Glob,Bash,Edit",
            add_dirs=(str(repo), str(out)),
            max_ai_credits=12.5,
            effort="high",
            session_id="session-1",
        ),
        workspace=tmp_path,
        usage_path=tmp_path / "usage.json",
        model="claude-fable-5.1",
    )
    assert "--available-tools=view,rg,glob,bash,apply_patch" in cmd
    for permission in ("read", "grep", "glob", "shell", "write"):
        assert f"--allow-tool={permission}" in cmd
    assert cmd.count("--add-dir") == 2
    assert "--resume=session-1" in cmd
    assert cmd[cmd.index("--max-ai-credits") + 1] == "12.5"
    assert cmd[cmd.index("--effort") + 1] == "high"


def test_build_command_rejects_relative_binary(tmp_path):
    with pytest.raises(FileNotFoundError, match="PATH-dependent"):
        ca.build_copilot_command(
            _config(copilot_bin="copilot"),
            workspace=tmp_path,
            usage_path=tmp_path / "usage.json",
            model="gpt-5.6-sol",
        )


def test_build_command_enables_copilot_sandbox(tmp_path):
    cmd = ca.build_copilot_command(
        _config(sandbox=True),
        workspace=tmp_path,
        usage_path=tmp_path / "usage.json",
        model="gpt-5.6-sol",
    )
    assert "--experimental" in cmd
    assert "--sandbox" in cmd
    assert "--disallow-temp-dir" in cmd


def test_build_command_rejects_invalid_add_dir(tmp_path):
    with pytest.raises((FileNotFoundError, ValueError)):
        ca.build_copilot_command(
            _config(tools="Read", add_dirs=(str(tmp_path / "missing"),)),
            workspace=tmp_path,
            usage_path=tmp_path / "usage.json",
            model="gpt-5.6-sol",
        )


def test_parse_jsonl_and_native_usage():
    stdout = "\n".join([
        json.dumps({
            "type": "assistant.message",
            "data": {
                "model": "gpt-5.3-codex",
                "content": "answer",
                "apiCallId": "must-not-be-retained",
            },
        }),
        json.dumps({
            "type": "result",
            "sessionId": "session-123",
            "exitCode": 0,
        }),
    ])
    usage = {
        "totalPremiumRequestCost": 1,
        "totalUserRequests": 1,
        "totalNanoAiu": 900_000_000,
        "currentModel": "gpt-5.3-codex",
        "modelMetrics": {
            "gpt-5.3-codex": {
                "requests": {"count": 1, "cost": 1},
                "usage": {
                    "inputTokens": 1000,
                    "outputTokens": 100,
                    "cacheReadTokens": 20,
                    "cacheWriteTokens": 30,
                    "reasoningTokens": 40,
                },
            },
        },
    }
    result = ca.parse_copilot_output(
        stdout,
        "",
        returncode=0,
        usage=usage,
        model_hint="gpt-5.6-sol",
        duration_seconds=1.25,
    )
    assert result.content == "answer"
    assert result.model == "gpt-5.3-codex"
    assert result.session_id == "session-123"
    assert result.input_tokens == 1000
    assert result.output_tokens == 100
    assert result.reasoning_tokens == 40
    assert result.cache_read_tokens == 20
    assert result.cache_write_tokens == 30
    assert result.estimated_cost_usd == pytest.approx(0.00371)
    assert result.native_usage["premium_request_cost"] == 1
    assert "apiCallId" not in json.dumps(result.native_usage)


def test_parse_nonzero_redacts_and_escapes_error():
    result = ca.parse_copilot_output(
        "",
        "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456\n\x1b[2J",
        returncode=1,
        usage={},
        model_hint="gpt-5.6-sol",
        duration_seconds=0.1,
    )
    assert result.error
    assert "ghp_" not in result.error
    assert "\x1b" not in result.error


def test_parse_nonzero_keeps_terminal_model_error_for_fallback():
    result = ca.parse_copilot_output(
        "",
        ("sandbox warning\n" * 300)
        + 'Error: Model "gpt-5.6-sol" from --model flag is not available.',
        returncode=1,
        usage={},
        model_hint="gpt-5.6-sol",
        duration_seconds=0.1,
    )
    assert result.error
    assert ca.is_model_unavailable_error(result.error)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("unknown model x", True),
        ('Model "x" from --model flag is not available.', True),
        ("model is not available for this account", True),
        ("no available capacity", True),
        ("permission denied", False),
        ("schema validation failed", False),
        (None, False),
    ],
)
def test_model_unavailable_classifier(message, expected):
    assert ca.is_model_unavailable_error(message) is expected


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("session not found", True),
        ("Unable to resume session abc", True),
        ("permission denied", False),
        (None, False),
    ],
)
def test_session_unavailable_classifier(message, expected):
    assert ca.is_session_unavailable_error(message) is expected


def test_fallback_attempt_usage_is_accumulated():
    first = ca.CopilotPromptResult(
        model="gpt-5.6-sol",
        error="model is not available",
        input_tokens=100,
        output_tokens=5,
        estimated_cost_usd=0.01,
        duration_seconds=1.0,
        native_usage={
            "premium_request_cost": 1,
            "user_requests": 1,
            "nano_aiu": 2,
        },
    )
    second = ca.CopilotPromptResult(
        content="ok",
        model="gpt-5.3-codex",
        input_tokens=50,
        output_tokens=3,
        reasoning_tokens=2,
        estimated_cost_usd=0.02,
        duration_seconds=2.0,
        native_usage={
            "premium_request_cost": 2,
            "user_requests": 1,
            "nano_aiu": 4,
        },
    )
    merged = ca.merge_copilot_attempts(first, second)
    assert merged.content == "ok"
    assert merged.model == "gpt-5.3-codex"
    assert merged.input_tokens == 150
    assert merged.output_tokens == 8
    assert merged.reasoning_tokens == 2
    assert merged.estimated_cost_usd == pytest.approx(0.03)
    assert merged.duration_seconds == pytest.approx(3.0)
    assert merged.native_usage["premium_request_cost"] == 3
    assert merged.native_usage["user_requests"] == 2
    assert merged.native_usage["nano_aiu"] == 6
    assert len(merged.native_usage["attempts"]) == 2


def test_process_uses_stdin_and_parses_large_prompt(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    script = (
        "import json,sys;"
        "data=sys.stdin.read();"
        "print(json.dumps({'type':'assistant.message','data':"
        "{'content':str(len(data)),'model':'gpt-5.6-sol'}}));"
        "print(json.dumps({'type':'result','sessionId':'s','exitCode':0}))"
    )
    prompt = "x" * 200_000
    rc, stdout, stderr, duration = ca._run_process(
        [sys.executable, "-c", script],
        prompt,
        env=dict(os.environ),
        timeout_s=10,
    )
    assert rc == 0
    assert stderr == ""
    assert json.loads(stdout.splitlines()[0])["data"]["content"] \
        == str(len(prompt))
    assert duration >= 0


def test_process_interrupt_kills_detached_child(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    spawned: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    def capture_popen(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        spawned.append(proc)
        return proc

    def interrupt_select(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(ca.subprocess, "Popen", capture_popen)
    monkeypatch.setattr(ca.select, "select", interrupt_select)

    with pytest.raises(KeyboardInterrupt):
        ca._run_process(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            "",
            env=dict(os.environ),
            timeout_s=10,
        )

    assert spawned
    assert spawned[0].poll() is not None


def test_invalid_prompt_encoding_never_spawns(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    monkeypatch.setattr(
        ca.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("child spawned before prompt validation")
        ),
    )

    with pytest.raises(UnicodeEncodeError):
        ca._run_process(
            [sys.executable, "-c", "pass"],
            "\ud800",
            env=dict(os.environ),
            timeout_s=1,
        )


def test_successful_process_reaps_background_descendants(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    script = (
        "import subprocess;"
        "p=subprocess.Popen(['sleep','30']);"
        "print(p.pid, flush=True)"
    )

    rc, stdout, _stderr, _duration = ca._run_process(
        [sys.executable, "-c", script],
        "",
        env=dict(os.environ),
        timeout_s=10,
    )

    assert rc == 0
    child_pid = int(stdout.strip())
    for _ in range(20):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        os.kill(child_pid, 9)
        pytest.fail("background child survived successful transport exit")


def test_run_prompt_falls_back_only_for_model_availability(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    attempted: list[str] = []

    def fake_run(cmd, prompt, *, env, timeout_s):
        model = cmd[cmd.index("--model") + 1]
        attempted.append(model)
        if model != "claude-fable-5.1":
            return 1, "", "unknown model", 0.1
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {"content": "ok", "model": model},
            }),
            json.dumps({
                "type": "result",
                "sessionId": "session-fable",
                "exitCode": 0,
            }),
        ])
        return 0, stdout, "", 0.2

    monkeypatch.setattr(ca, "_run_process", fake_run)
    monkeypatch.setattr(ca, "_load_usage", lambda path: {})
    result = ca.run_copilot_prompt(
        _config(
            fallback_models=(
                "gpt-5.3-codex",
                "claude-fable-5.1",
                "claude-fable-5",
            ),
        ),
        "prompt",
    )
    assert result.content == "ok"
    assert attempted == [
        "gpt-5.6-sol",
        "gpt-5.3-codex",
        "claude-fable-5.1",
    ]
    assert result.attempted_models == tuple(attempted)


def test_run_prompt_does_not_fallback_on_arbitrary_error(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    attempted: list[str] = []

    def fake_run(cmd, prompt, *, env, timeout_s):
        attempted.append(cmd[cmd.index("--model") + 1])
        return 1, "", "permission denied", 0.1

    monkeypatch.setattr(ca, "_run_process", fake_run)
    monkeypatch.setattr(ca, "_load_usage", lambda path: {})
    result = ca.run_copilot_prompt(
        _config(fallback_models=("gpt-5.3-codex",)),
        "prompt",
    )
    assert result.error == "permission denied"
    assert attempted == ["gpt-5.6-sol"]


def test_transport_kill_switch_refuses_spawn(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "1")
    with pytest.raises(RuntimeError, match="transport disabled"):
        ca._run_process(
            [sys.executable, "-c", "pass"],
            "",
            env=dict(os.environ),
            timeout_s=1,
        )


def test_copilot_env_consolidates_parent_token(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "parent-token")
    monkeypatch.setenv("GITHUB_TOKEN", "other-token")
    env = ca.copilot_subprocess_env()
    assert env["COPILOT_GITHUB_TOKEN"] == "parent-token"
    assert "GH_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env


def test_token_resolution_uses_launcher_broker(monkeypatch):
    for name in ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "RAPTOR_COPILOT_AUTH_SOCKET",
        "/tmp/test-copilot-auth.sock",
    )
    monkeypatch.setattr(
        "core.llm.copilot_auth_broker.request_token",
        lambda path: "broker-token",
    )
    monkeypatch.setattr(
        ca,
        "_github_token_from_copilot_keyring",
        lambda: (_ for _ in ()).throw(
            AssertionError("keyring lookup should not run")
        ),
    )

    assert ca.resolve_copilot_github_token(mint=True) == "broker-token"


def test_private_copilot_home_redirects_xdg_state(monkeypatch, tmp_path):
    private = tmp_path / "copilot-home"
    cache = tmp_path / "runtime-cache"
    env = ca.copilot_subprocess_env(
        copilot_home=private,
        runtime_cache=cache,
    )
    assert env["HOME"] == str(private.resolve())
    assert env["COPILOT_HOME"] == str(private.resolve())
    assert env["XDG_CACHE_HOME"] == str(cache.resolve())
    assert env["XDG_CONFIG_HOME"] == str(private.resolve().parent)
    assert env["XDG_DATA_HOME"] == str(private.resolve().parent)
    assert env["NODE_COMPILE_CACHE"] == str(
        cache.resolve() / "node-compile-cache"
    )
    assert cache.stat().st_mode & 0o777 == 0o700


def test_configured_fallback_models_override_catalog(monkeypatch):
    monkeypatch.setenv(
        "RAPTOR_COPILOT_FALLBACK_MODELS",
        "gpt-5.3-codex, claude-fable-5.1, gpt-5.3-codex",
    )
    assert ca.configured_copilot_fallback_models("gpt-5.6-sol") == (
        "gpt-5.3-codex",
        "claude-fable-5.1",
    )


def test_copilot_env_mints_token_from_gh(monkeypatch):
    monkeypatch.delenv("COPILOT_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        ca,
        "_github_token_from_copilot_keyring",
        lambda: None,
    )
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(
        ca.subprocess,
        "run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": "minted-token\n"},
        )(),
    )
    env = ca.copilot_subprocess_env(mint_github_token=True)
    assert env["COPILOT_GITHUB_TOKEN"] == "minted-token"


def test_copilot_env_prefers_copilot_keyring(monkeypatch):
    monkeypatch.delenv("COPILOT_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        ca,
        "_github_token_from_copilot_keyring",
        lambda: "copilot-oauth-token",
    )
    monkeypatch.setattr(
        ca,
        "_github_token_from_gh",
        lambda: (_ for _ in ()).throw(AssertionError("gh fallback used")),
    )
    env = ca.copilot_subprocess_env(mint_github_token=True)
    assert env["COPILOT_GITHUB_TOKEN"] == "copilot-oauth-token"


def test_private_agent_file_contains_system_prompt(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    observed: dict[str, str] = {}

    def fake_run(cmd, prompt, *, env, timeout_s):
        workspace = Path(cmd[cmd.index("-C") + 1])
        agent = workspace / ".github" / "agents" / "raptor-subprocess.agent.md"
        observed["agent"] = agent.read_text(encoding="utf-8")
        observed["prompt"] = prompt
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {"content": "ok", "model": "gpt-5.6-sol"},
            }),
            json.dumps({"type": "result", "exitCode": 0}),
        ])
        return 0, stdout, "", 0.1

    monkeypatch.setattr(ca, "_run_process", fake_run)
    monkeypatch.setattr(ca, "_load_usage", lambda path: {})
    result = ca.run_copilot_prompt(
        _config(system_prompt="trusted system instruction"),
        "untrusted user content",
    )
    assert result.content == "ok"
    assert "trusted system instruction" in observed["agent"]
    assert "untrusted user content" not in observed["agent"]
    assert observed["prompt"] == "untrusted user content"


def test_stage_copilot_agent_is_private(tmp_path):
    path = ca.stage_copilot_agent(
        tmp_path,
        system_prompt="system",
        tools="Read,Grep",
    )
    assert path.stat().st_mode & 0o777 == 0o600
    text = path.read_text(encoding="utf-8")
    assert '"view"' in text
    assert '"rg"' in text
    assert "system" in text


def test_stage_copilot_sandbox_settings_is_no_bypass(tmp_path):
    workspace = tmp_path / "workspace"
    target = tmp_path / "target"
    home = workspace / "home"
    workspace.mkdir()
    target.mkdir()
    path = ca.stage_copilot_sandbox_settings(
        home,
        workspace=workspace,
        readonly_paths=(str(target),),
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    sandbox = data["sandbox"]
    assert sandbox["enabled"] is True
    assert sandbox["allowBypass"] is False
    assert sandbox["allowDevToolAccess"] is False
    assert sandbox["auth"] == {"git": False, "gh": False}
    assert sandbox["userPolicy"]["network"] == {
        "allowOutbound": False,
        "allowLocalNetwork": False,
    }
    assert sandbox["userPolicy"]["filesystem"]["readwritePaths"] \
        == [str(workspace.resolve())]
    assert sandbox["userPolicy"]["filesystem"]["readonlyPaths"] \
        == [str(target.resolve())]
    assert path.stat().st_mode & 0o777 == 0o600


def test_disposable_workspace_is_removed(tmp_path):
    with ca.disposable_copilot_workspace(tmp_path) as workspace:
        assert workspace.is_dir()
        (workspace / "state").write_text("x", encoding="utf-8")
    assert not workspace.exists()


def test_stage_raptor_workspace_links_uses_fixed_view(tmp_path):
    root = tmp_path / "raptor"
    workspace = tmp_path / "workspace"
    (root / "libexec").mkdir(parents=True)
    (root / "core").mkdir()
    (root / "raptor.py").write_text("pass\n", encoding="utf-8")
    workspace.mkdir()
    ca.stage_raptor_workspace_links(workspace, root)
    assert (workspace / "libexec").resolve() == (root / "libexec").resolve()
    assert (workspace / "core").resolve() == (root / "core").resolve()
    assert (workspace / "raptor.py").resolve() == (root / "raptor.py").resolve()
    assert not (workspace / "README.md").exists()
