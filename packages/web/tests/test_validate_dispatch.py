"""URL-target regression tests for the web /validate handoff."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

import pytest

from core.orchestration.agentic_passes import run_validate_postpass
from packages.web.scanner import WebScanner


pytestmark = pytest.mark.usefixtures("cc_spawn_machinery_enabled")

_FIRST_PARTY_PROVIDER_ENV = {
    "CLAUDE_CODE_USE_BEDROCK": "",
    "CLAUDE_CODE_USE_VERTEX": "",
    "CLAUDE_CODE_USE_FOUNDRY": "",
}


def _validation_scanner(tmp_path: Path, target: str) -> WebScanner:
    scanner = WebScanner(
        target,
        out_dir=tmp_path,
        block_private_ips=False,
    )
    scanner._maybe_rank = lambda findings, *_args, **_kwargs: findings
    scanner._web_finding_to_agentic_result = lambda _finding: {
        "finding_id": "WEB-0001",
        "is_exploitable": True,
    }
    return scanner


def test_scanner_passes_exact_url_string_to_validate(tmp_path, monkeypatch):
    target = "HTTPS://Example.Test:443/app/"
    scanner = _validation_scanner(tmp_path, target)
    captured = {}

    monkeypatch.setenv("RAPTOR_AGENT_CLI", "claude")
    monkeypatch.setattr(
        "core.security.rule_of_two.is_interactive",
        lambda: True,
    )
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")

    def fake_validate(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(ran=True)

    monkeypatch.setattr(
        "core.orchestration.agentic_passes.run_validate_postpass",
        fake_validate,
    )
    finding = SimpleNamespace(status="needs_review")
    try:
        scanner._phase_validate([finding])
    finally:
        scanner.close()

    assert captured["target"] == target
    assert isinstance(captured["target"], str)
    assert scanner.execution_policy.receipt.target == target
    assert scanner._empty_result("test")["target"] == target


@pytest.mark.parametrize(
    ("selected_agent", "expected_binary"),
    [("claude", "claude"), ("copilot", "copilot")],
)
def test_scanner_skips_validate_when_selected_cli_is_missing(
    tmp_path,
    monkeypatch,
    selected_agent,
    expected_binary,
):
    scanner = _validation_scanner(tmp_path, "https://example.test/app")
    looked_up = []

    monkeypatch.setenv("RAPTOR_AGENT_CLI", selected_agent)
    monkeypatch.setattr(
        "core.security.rule_of_two.is_interactive",
        lambda: True,
    )

    def missing(name):
        looked_up.append(name)
        return None

    monkeypatch.setattr(shutil, "which", missing)
    monkeypatch.setattr(
        "core.orchestration.agentic_passes.run_validate_postpass",
        lambda **_kwargs: pytest.fail("validate dispatch should be skipped"),
    )
    monkeypatch.setattr(
        scanner,
        "_build_validation_replay_artifact",
        lambda _findings: pytest.fail(
            "replay should not run when the selected CLI is unavailable"
        ),
    )
    finding = SimpleNamespace(status="needs_review")
    try:
        result = scanner._phase_validate([finding])
    finally:
        scanner.close()

    assert result == [finding]
    assert looked_up == [expected_binary]
    assert "validate" not in scanner._phases_completed


def test_url_validate_keeps_identity_out_of_filesystem_dispatch(
    tmp_path,
    monkeypatch,
):
    target = "HTTPS://Example.Test:443/app/?mode=validate"
    agentic_out = tmp_path / "web-run"
    validate_dir = tmp_path / "validate-run"
    agentic_out.mkdir()
    (agentic_out / "checklist.json").write_text(
        json.dumps({"target_path": target, "files": []}),
        encoding="utf-8",
    )
    analysis_report = agentic_out / "web-findings.json"
    analysis_report.write_text(
        json.dumps({
            "results": [{
                "finding_id": "WEB-0001",
                "is_exploitable": True,
            }],
        }),
        encoding="utf-8",
    )
    captured = {}

    def lifecycle(cmd, *args, **kwargs):
        if Path(cmd[0]).name != "raptor-run-lifecycle":
            raise AssertionError(f"unexpected subprocess: {cmd!r}")
        if cmd[1] == "start":
            captured["lifecycle_start"] = list(cmd)
            validate_dir.mkdir()
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=f"OUTPUT_DIR={validate_dir}\n",
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def sandbox(cmd, *args, **kwargs):
        captured["command"] = list(cmd)
        captured["sandbox"] = dict(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "core.security.rule_of_two."
        "require_human_or_sandbox_for_agentic_pass",
        lambda _command: None,
    )
    monkeypatch.setattr(
        "core.llm.cc_adapter.resolve_claude_cli",
        lambda _binary: "/fake/claude",
    )
    monkeypatch.setattr(
        "core.threat_model.threat_model_prompt_block",
        lambda _target: pytest.fail(
            "URL target must not reach filesystem threat-model lookup"
        ),
    )

    with patch.dict(os.environ, _FIRST_PARTY_PROVIDER_ENV), \
         patch(
             "core.orchestration.skill_dispatch.subprocess.run",
             side_effect=lifecycle,
         ), \
         patch(
             "core.orchestration.skill_dispatch.run_untrusted_networked",
             side_effect=sandbox,
         ):
        result = run_validate_postpass(
            target=target,
            agentic_out_dir=agentic_out,
            analysis_report=analysis_report,
            claude_bin="/fake/claude",
        )

    assert result.ran, result.skipped_reason
    start = captured["lifecycle_start"]
    assert start[start.index("--target") + 1] == target

    selection = json.loads(
        (validate_dir / "selected-findings.json").read_text(encoding="utf-8")
    )
    assert selection["target_path"] == target
    assert not (validate_dir / "parent-checklist-pointer.json").exists()

    prompt = captured["sandbox"]["input"]
    assert target in prompt
    assert "target" not in captured["sandbox"]
    assert captured["sandbox"]["output"] == str(validate_dir.resolve())
    assert str(agentic_out.resolve()) in captured["sandbox"]["readable_paths"]
    assert (urlparse(target).hostname or "").lower() not in " ".join(
        captured["sandbox"].get("proxy_hosts") or (),
    ).lower()

    add_dirs = [
        captured["command"][index + 1]
        for index, arg in enumerate(captured["command"])
        if arg == "--add-dir"
    ]
    assert target not in add_dirs
    assert all("Example.Test" not in directory for directory in add_dirs)
    assert str(agentic_out.resolve()) in add_dirs


def test_copilot_validate_sandbox_keeps_target_network_disabled(tmp_path):
    from core.llm.copilot_adapter import stage_copilot_sandbox_settings

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings_path = stage_copilot_sandbox_settings(
        tmp_path / "copilot-home",
        workspace=workspace,
    )
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    network = settings["sandbox"]["userPolicy"]["network"]

    assert network == {
        "allowOutbound": False,
        "allowLocalNetwork": False,
    }
    assert settings["sandbox"]["allowBypass"] is False


def test_web_validation_profile_requires_artifact_only_replay():
    profile = (
        Path(__file__).resolve().parents[3]
        / ".claude"
        / "skills"
        / "exploitability-validation"
        / "web-profile.md"
    ).read_text(encoding="utf-8")

    assert "web-validation-replay.json" in profile
    assert "This artifact is the ONLY freshness source" in profile
    assert "Do not use Bash, curl, wget" in profile
    assert "child sandboxes intentionally have no target-network route" in profile
