"""Copilot-specific regression tests for the shared skill dispatcher."""

from __future__ import annotations

import json
from pathlib import Path

from core.orchestration import skill_dispatch as sd


def test_copilot_skill_child_uses_private_mxc_policy(
    tmp_path, monkeypatch,
):
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    context = tmp_path / "context"
    target.mkdir()
    run_dir.mkdir()
    context.mkdir()
    captured: dict = {}

    def fake_env(**kwargs):
        captured["env_kwargs"] = kwargs
        home = Path(kwargs["copilot_home"])
        captured["home_mode"] = home.stat().st_mode & 0o777
        return {
            "HOME": str(home),
            "COPILOT_HOME": str(home),
            "PATH": "/usr/bin",
        }

    def fake_execute(cmd, prompt, **kwargs):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        captured["execute_kwargs"] = kwargs
        private_home = Path(kwargs["env"]["COPILOT_HOME"])
        captured["settings"] = json.loads(
            (private_home / "settings.json").read_text(encoding="utf-8")
        )["sandbox"]
        usage_path = Path(cmd[cmd.index("--usage-output-file") + 1])
        usage_path.write_text(
            json.dumps({
                "currentModel": "gpt-5.6-sol",
                "totalPremiumRequestCost": 1,
                "modelMetrics": {
                    "gpt-5.6-sol": {
                        "requests": {"count": 1, "cost": 1},
                        "usage": {
                            "inputTokens": 10,
                            "outputTokens": 2,
                            "cacheReadTokens": 0,
                            "cacheWriteTokens": 0,
                        },
                    },
                },
            }),
            encoding="utf-8",
        )
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {
                    "content": "done",
                    "model": "gpt-5.6-sol",
                },
            }),
            json.dumps({
                "type": "result",
                "sessionId": "session-1",
                "exitCode": 0,
            }),
        ])
        from subprocess import CompletedProcess
        return CompletedProcess(cmd, 0, stdout, ""), 0.2

    monkeypatch.setenv("RAPTOR_COPILOT_MODEL", "gpt-5.6-sol")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    monkeypatch.setattr(
        "core.llm.copilot_adapter.copilot_subprocess_env",
        fake_env,
    )
    monkeypatch.setattr(
        "core.llm.copilot_adapter.execute_copilot_command",
        fake_execute,
    )

    result = sd._run_copilot_skill_child(
        copilot_bin="/usr/bin/true",
        prompt="run the skill",
        tools="Read,Bash",
        target=target,
        run_dir=run_dir,
        context_dirs=(context,),
        timeout_s=60,
        caller_label="test-skill",
    )

    assert result.returncode == 0
    assert "--sandbox" in captured["cmd"]
    assert "--no-custom-instructions" in captured["cmd"]
    assert captured["prompt"] == "run the skill"
    workspace = Path(captured["execute_kwargs"]["cwd"])
    assert workspace.parent == run_dir
    assert workspace.name.startswith(".copilot-workspace-")
    assert not workspace.exists()
    assert captured["env_kwargs"]["mint_github_token"] is True
    private_home = Path(captured["env_kwargs"]["copilot_home"])
    settings = captured["settings"]
    model_roots = [
        workspace,
        *(
            Path(captured["cmd"][index + 1])
            for index, arg in enumerate(captured["cmd"])
            if arg == "--add-dir"
        ),
        *(
            Path(path)
            for path in settings["userPolicy"]["filesystem"][
                "readwritePaths"
            ]
        ),
        *(
            Path(path)
            for path in settings["userPolicy"]["filesystem"][
                "readonlyPaths"
            ]
        ),
    ]
    for root in model_roots:
        assert not private_home.resolve().is_relative_to(root.resolve())
    assert captured["home_mode"] == 0o700
    assert not private_home.exists()
    assert settings["allowBypass"] is False
    assert settings["allowDevToolAccess"] is False
    assert settings["auth"] == {"git": False, "gh": False}
    readonly = settings["userPolicy"]["filesystem"]["readonlyPaths"]
    assert str(target.resolve()) in readonly
    assert str(context.resolve()) in readonly
    assert (run_dir / "copilot-transport-usage.json").exists()


def test_copilot_skill_child_rejects_nonzero_json_result(
    tmp_path, monkeypatch,
):
    import core.llm.copilot_adapter as ca

    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    target.mkdir()
    run_dir.mkdir()

    def fake_env(**kwargs):
        home = Path(kwargs["copilot_home"])
        return {
            "HOME": str(home),
            "COPILOT_HOME": str(home),
            "PATH": "/usr/bin",
        }

    def fake_run(cmd, prompt, *, env, timeout_s, cwd=None):
        stdout = "\n".join([
            json.dumps({
                "type": "assistant.message",
                "data": {
                    "content": "partial",
                    "model": "gpt-5.6-sol",
                },
            }),
            json.dumps({"type": "result", "exitCode": 12}),
        ])
        return 0, stdout, "", 0.2

    monkeypatch.setenv("RAPTOR_COPILOT_MODEL", "gpt-5.6-sol")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    monkeypatch.setattr(ca, "copilot_subprocess_env", fake_env)
    monkeypatch.setattr(ca, "_run_process", fake_run)

    result = sd._run_copilot_skill_child(
        copilot_bin="/usr/bin/true",
        prompt="run the skill",
        tools="Read",
        target=target,
        run_dir=run_dir,
        context_dirs=(),
        timeout_s=60,
        caller_label="test-skill",
    )

    usage = json.loads(
        (run_dir / "copilot-transport-usage.json").read_text(
            encoding="utf-8",
        )
    )
    assert result.returncode == 12
    assert usage["error"] == "Copilot result reported exitCode 12"


def test_copilot_skill_child_omits_url_from_filesystem_policy(
    tmp_path, monkeypatch,
):
    target = "HTTPS://Example.Test:443/app/"
    run_dir = tmp_path / "run"
    context = tmp_path / "context"
    run_dir.mkdir()
    context.mkdir()
    captured: dict = {}

    def fake_env(**kwargs):
        captured["env_kwargs"] = kwargs
        home = Path(kwargs["copilot_home"])
        return {
            "HOME": str(home),
            "COPILOT_HOME": str(home),
            "PATH": "/usr/bin",
        }

    def fake_execute(cmd, prompt, **kwargs):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        private_home = Path(kwargs["env"]["COPILOT_HOME"])
        captured["settings"] = json.loads(
            (private_home / "settings.json").read_text(encoding="utf-8")
        )["sandbox"]
        usage_path = Path(cmd[cmd.index("--usage-output-file") + 1])
        usage_path.write_text(
            json.dumps({
                "currentModel": "gpt-5.6-sol",
                "totalPremiumRequestCost": 1,
                "modelMetrics": {},
            }),
            encoding="utf-8",
        )
        from subprocess import CompletedProcess
        stdout = json.dumps({
            "type": "result",
            "sessionId": "session-url",
            "exitCode": 0,
        })
        return CompletedProcess(cmd, 0, stdout, ""), 0.1

    monkeypatch.setenv("RAPTOR_COPILOT_MODEL", "gpt-5.6-sol")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    monkeypatch.setattr(
        "core.llm.copilot_adapter.copilot_subprocess_env",
        fake_env,
    )
    monkeypatch.setattr(
        "core.llm.copilot_adapter.execute_copilot_command",
        fake_execute,
    )

    result = sd._run_copilot_skill_child(
        copilot_bin="/usr/bin/true",
        prompt=f"validate {target}",
        tools="Read,Bash",
        target=target,
        run_dir=run_dir,
        context_dirs=(context,),
        timeout_s=60,
        caller_label="test-url-skill",
    )

    assert result.returncode == 0
    add_dirs = [
        captured["cmd"][index + 1]
        for index, arg in enumerate(captured["cmd"])
        if arg == "--add-dir"
    ]
    readonly = captured["settings"]["userPolicy"]["filesystem"][
        "readonlyPaths"
    ]
    assert target in captured["prompt"]
    assert target not in add_dirs
    assert target not in readonly
    assert all("Example.Test" not in directory for directory in add_dirs)
    assert all("Example.Test" not in directory for directory in readonly)
    assert str(context.resolve()) in add_dirs
    assert str(context.resolve()) in readonly
