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
            persist_session=True,
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


def test_dispatch_config_requires_explicit_persistent_session():
    with pytest.raises(ValueError, match="persist_session"):
        _config(session_id="session-1")


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


def test_parse_nonzero_process_with_content_has_nonempty_error():
    stdout = json.dumps({
        "type": "assistant.message",
        "data": {"content": "partial answer", "model": "gpt-5.6-sol"},
    })
    result = ca.parse_copilot_output(
        stdout,
        "",
        returncode=9,
        usage={},
        model_hint="gpt-5.6-sol",
        duration_seconds=0.1,
    )
    assert result.content == "partial answer"
    assert result.error == "Copilot process exited with status 9"


def test_parse_nonzero_json_result_with_content_has_nonempty_error():
    stdout = "\n".join([
        json.dumps({
            "type": "assistant.message",
            "data": {"content": "partial answer", "model": "gpt-5.6-sol"},
        }),
        json.dumps({"type": "result", "exitCode": 7}),
    ])
    result = ca.parse_copilot_output(
        stdout,
        "",
        returncode=0,
        usage={},
        model_hint="gpt-5.6-sol",
        duration_seconds=0.1,
    )
    assert result.content == "partial answer"
    assert result.error == "Copilot result reported exitCode 7"


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


def test_execute_normalizes_nonzero_json_result_exit(monkeypatch):
    stdout = "\n".join([
        json.dumps({
            "type": "assistant.message",
            "data": {"content": "partial answer", "model": "gpt-5.6-sol"},
        }),
        json.dumps({"type": "result", "exitCode": 11}),
    ])
    monkeypatch.setattr(
        ca,
        "_run_process",
        lambda *args, **kwargs: (0, stdout, "", 0.25),
    )

    proc, duration = ca.execute_copilot_command(
        ["/usr/bin/copilot"],
        "prompt",
        env={},
        timeout_s=30,
    )

    assert proc.returncode == 11
    assert proc.stdout == stdout
    assert duration == pytest.approx(0.25)


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
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "test-token")
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
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "test-token")
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
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "test-token")
    private = tmp_path / "copilot-home"
    cache = tmp_path / "runtime-cache"
    env = ca.copilot_subprocess_env(
        copilot_home=private,
        runtime_cache=cache,
    )
    assert env["HOME"] == str(private.resolve())
    assert env["COPILOT_HOME"] == str(private.resolve())
    assert env["XDG_CACHE_HOME"] == str(cache.resolve())
    assert env["XDG_CONFIG_HOME"] == str(private.resolve())
    assert env["XDG_DATA_HOME"] == str(private.resolve())
    assert env["NODE_COMPILE_CACHE"] == str(
        cache.resolve() / "node-compile-cache"
    )
    assert cache.stat().st_mode & 0o777 == 0o700
    assert private.stat().st_mode & 0o777 == 0o700


def test_private_home_stages_only_validated_auth_state(
    monkeypatch, tmp_path,
):
    operator_home = tmp_path / "operator"
    source_home = operator_home / ".copilot"
    source_home.mkdir(parents=True)
    (source_home / "config.json").write_text(
        """
        // Operator UI and plugin state must not cross the boundary.
        {
          "copilotTokens": {"account-key": "token-value"},
          "loggedInUsers": [
            {"host": "github.com", "login": "octocat"},
          ],
          "lastLoggedInUser": {
            "host": "github.com",
            "login": "octocat",
          },
          "installedPlugins": ["operator-plugin"],
          "trustedFolders": ["/operator/private"]
        }
        """,
        encoding="utf-8",
    )
    (source_home / "settings.json").write_text(
        '{"model": "operator-setting"}',
        encoding="utf-8",
    )
    (source_home / "session-store.db").write_bytes(b"operator-session")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    for name in ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        ca,
        "resolve_copilot_github_token",
        lambda *, mint=False: None,
    )
    private = tmp_path / "private"

    env = ca.copilot_subprocess_env(copilot_home=private)

    staged = json.loads(
        (private / "config.json").read_text(encoding="utf-8")
    )
    assert staged == {
        "copilotTokens": {"account-key": "token-value"},
        "loggedInUsers": [
            {"host": "github.com", "login": "octocat"},
        ],
        "lastLoggedInUser": {
            "host": "github.com",
            "login": "octocat",
        },
    }
    assert env["HOME"] == str(private.resolve())
    assert env["COPILOT_HOME"] == str(private.resolve())
    assert (private / "config.json").stat().st_mode & 0o777 == 0o600
    assert private.stat().st_mode & 0o777 == 0o700
    assert not (private / "settings.json").exists()
    assert not (private / "session-store.db").exists()
    assert not (private / "installed-plugins.lock").exists()


def test_private_home_prefers_parent_token_over_operator_config(
    monkeypatch, tmp_path,
):
    private = tmp_path / "private"
    monkeypatch.setattr(
        ca,
        "resolve_copilot_github_token",
        lambda *, mint=False: "parent-token",
    )
    monkeypatch.setattr(
        ca,
        "stage_copilot_auth_config",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("auth config should not be staged")
        ),
    )

    env = ca.copilot_subprocess_env(copilot_home=private)

    assert env["COPILOT_GITHUB_TOKEN"] == "parent-token"
    assert not (private / "config.json").exists()


def test_private_home_auth_staging_failure_is_fail_closed(
    monkeypatch, tmp_path,
):
    operator_home = tmp_path / "operator"
    source_home = operator_home / ".copilot"
    source_home.mkdir(parents=True)
    (source_home / "config.json").write_text(
        json.dumps({
            "copilotTokens": {"account-key": "x" * 20_000},
            "loggedInUsers": [
                {"host": "github.com", "login": "octocat"},
            ],
            "lastLoggedInUser": {
                "host": "github.com",
                "login": "octocat",
            },
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    monkeypatch.setattr(
        ca,
        "resolve_copilot_github_token",
        lambda *, mint=False: None,
    )
    private = tmp_path / "private"

    with pytest.raises(RuntimeError, match="isolated subprocess"):
        ca.copilot_subprocess_env(copilot_home=private)

    assert private.is_dir()
    assert private.stat().st_mode & 0o777 == 0o700
    assert not (private / "config.json").exists()


def test_auth_staging_rejects_invalid_field_types(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text(
        json.dumps({
            "copilotTokens": {"account-key": {"token": "nested"}},
            "loggedInUsers": [
                {"host": "github.com", "login": "octocat"},
            ],
            "lastLoggedInUser": {
                "host": "github.com",
                "login": "octocat",
            },
        }),
        encoding="utf-8",
    )
    private = tmp_path / "private"

    with pytest.raises(RuntimeError, match="validated"):
        ca.stage_copilot_auth_config(private, source_home=source)

    assert not (private / "config.json").exists()


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
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "test-token")
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


def test_stateless_prompt_uses_disposable_private_home(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    observed: dict[str, Path] = {}

    def fake_env(**kwargs):
        home = Path(kwargs["copilot_home"])
        observed["home"] = home
        observed["cache"] = Path(kwargs["runtime_cache"])
        assert home.is_dir()
        assert home.stat().st_mode & 0o777 == 0o700
        assert observed["cache"].is_relative_to(home)
        observed["cache"].mkdir(mode=0o700)
        (home / "config.json").write_text(
            '{"copilotTokens":{"test":"secret"}}',
            encoding="utf-8",
        )
        return {}

    def fake_run(cmd, prompt, *, env, timeout_s):
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {"content": "ok", "model": "gpt-5.6-sol"},
            }),
            json.dumps({"type": "result", "exitCode": 0}),
        ])
        return 0, stdout, "", 0.1

    monkeypatch.setattr(ca, "copilot_subprocess_env", fake_env)
    monkeypatch.setattr(ca, "_run_process", fake_run)
    monkeypatch.setattr(ca, "_load_usage", lambda path: {})

    result = ca.run_copilot_prompt(_config(), "prompt")

    assert result.error is None
    assert not observed["home"].exists()
    assert not observed["cache"].exists()


def test_stateless_prompt_cleans_secret_state_on_auth_error(monkeypatch):
    observed: dict[str, Path] = {}

    def fake_env(**kwargs):
        home = Path(kwargs["copilot_home"])
        observed["home"] = home
        (home / "config.json").write_text("secret", encoding="utf-8")
        raise RuntimeError("auth staging failed")

    monkeypatch.setattr(ca, "copilot_subprocess_env", fake_env)

    with pytest.raises(RuntimeError, match="auth staging failed"):
        ca.run_copilot_prompt(_config(), "prompt")

    assert not observed["home"].exists()


def test_stateless_prompt_cleans_secret_state_on_timeout(monkeypatch):
    observed: dict[str, Path] = {}

    def fake_env(**kwargs):
        home = Path(kwargs["copilot_home"])
        observed["home"] = home
        (home / "config.json").write_text("secret", encoding="utf-8")
        return {}

    def fake_run(cmd, prompt, *, env, timeout_s):
        raise subprocess.TimeoutExpired(cmd, timeout_s)

    monkeypatch.setattr(ca, "copilot_subprocess_env", fake_env)
    monkeypatch.setattr(ca, "_run_process", fake_run)

    with pytest.raises(subprocess.TimeoutExpired):
        ca.run_copilot_prompt(_config(), "prompt")

    assert not observed["home"].exists()


def test_disposable_auth_state_is_outside_model_visible_roots(
    monkeypatch, tmp_path,
):
    operator_home = tmp_path / "operator"
    operator_config = operator_home / ".copilot"
    operator_config.mkdir(parents=True)
    (operator_config / "config.json").write_text(
        json.dumps({
            "copilotTokens": {"account-key": "token-value"},
            "loggedInUsers": [
                {"host": "github.com", "login": "octocat"},
            ],
            "lastLoggedInUser": {
                "host": "github.com",
                "login": "octocat",
            },
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    monkeypatch.setattr(
        ca,
        "resolve_copilot_github_token",
        lambda *, mint=False: None,
    )

    run_dir = tmp_path / "run"
    workspace = run_dir / ".copilot-workspace-test"
    raptor_root = tmp_path / "raptor"
    target = tmp_path / "target"
    context = tmp_path / "context"
    for path in (workspace, raptor_root, target, context):
        path.mkdir(parents=True)
    model_roots = (
        workspace,
        run_dir,
        raptor_root,
        target,
        context,
    )

    with ca.disposable_copilot_state(
        forbidden_roots=model_roots,
    ) as private_home:
        env = ca.copilot_subprocess_env(copilot_home=private_home)
        settings_path = ca.stage_copilot_sandbox_settings(
            private_home,
            workspace=run_dir,
            readonly_paths=(
                str(raptor_root),
                str(target),
                str(context),
            ),
        )
        config_path = private_home / "config.json"
        assert "token-value" in config_path.read_text(encoding="utf-8")
        for root in model_roots:
            assert not config_path.resolve().is_relative_to(root.resolve())

        policy = json.loads(
            settings_path.read_text(encoding="utf-8")
        )["sandbox"]["userPolicy"]["filesystem"]
        granted_roots = (
            *policy["readwritePaths"],
            *policy["readonlyPaths"],
        )
        assert str(private_home.resolve()) not in granted_roots
        for raw_root in granted_roots:
            assert not config_path.resolve().is_relative_to(
                Path(raw_root).resolve()
            )
        for name in (
            "HOME",
            "COPILOT_HOME",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        ):
            assert Path(env[name]).resolve().is_relative_to(
                private_home.resolve()
            )
        captured_home = private_home

    assert not captured_home.exists()


def test_disposable_auth_state_fails_closed_on_overlapping_root(
    monkeypatch, tmp_path,
):
    model_root = tmp_path / "model-root"
    model_root.mkdir()
    planted = model_root / "raptor-copilot-state-test"

    def fake_mkdtemp(*, prefix):
        planted.mkdir(mode=0o700)
        return str(planted)

    monkeypatch.setattr(ca.tempfile, "mkdtemp", fake_mkdtemp)

    with pytest.raises(RuntimeError, match="model-readable root"):
        with ca.disposable_copilot_state(
            forbidden_roots=(model_root,),
        ):
            pytest.fail("overlapping secret state was yielded")

    assert not planted.exists()


def test_persistent_prompt_keeps_operator_home_available(monkeypatch):
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    observed: dict[str, object] = {}

    def fake_env(**kwargs):
        observed.update(kwargs)
        return {}

    def fake_run(cmd, prompt, *, env, timeout_s):
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {"content": "ok", "model": "gpt-5.6-sol"},
            }),
            json.dumps({
                "type": "result",
                "sessionId": "session-1",
                "exitCode": 0,
            }),
        ])
        return 0, stdout, "", 0.1

    monkeypatch.setattr(ca, "copilot_subprocess_env", fake_env)
    monkeypatch.setattr(ca, "_run_process", fake_run)
    monkeypatch.setattr(ca, "_load_usage", lambda path: {})

    result = ca.run_copilot_prompt(
        _config(persist_session=True),
        "prompt",
    )

    assert result.session_id == "session-1"
    assert observed == {"mint_github_token": False}


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
