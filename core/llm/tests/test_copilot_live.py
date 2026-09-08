"""Opt-in live Copilot CLI integration tests.

Run with ``RAPTOR_TEST_LIVE_LLM=1``. These tests consume Copilot usage.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RAPTOR_TEST_LIVE_LLM") != "1",
        reason="live Copilot tests require RAPTOR_TEST_LIVE_LLM=1",
    ),
    pytest.mark.skipif(
        shutil.which("copilot") is None,
        reason="copilot CLI not installed",
    ),
]


def test_live_copilot_provider_freeform(monkeypatch):
    from core.llm.config import ModelConfig
    from core.llm.providers import create_provider

    monkeypatch.setenv("RAPTOR_AGENT_CLI", "copilot")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    config = ModelConfig(
        provider="copilotcli",
        model_name="gpt-5.6-sol",
        max_context=1_050_000,
        max_tokens=128_000,
        timeout=120,
    )
    response = create_provider(config).generate(
        "Reply with exactly LIVE_PROVIDER_OK",
        system_prompt="Return only the requested text.",
    )
    assert response.content == "LIVE_PROVIDER_OK"
    assert response.provider == "copilotcli"
    assert response.native_usage.get("premium_request_cost", 0) > 0
    assert response.attempted_models == ("gpt-5.6-sol",)


def test_live_copilot_mxc_hides_token_and_host_files(
    monkeypatch, tmp_path,
):
    from core.json import load_json
    from core.llm.copilot_adapter import (
        parse_copilot_output,
        resolve_copilot_cli,
    )
    from core.orchestration.skill_dispatch import _run_copilot_skill_child

    monkeypatch.setenv("RAPTOR_AGENT_CLI", "copilot")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL", "gpt-5.6-sol")
    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    target.mkdir()
    run_dir.mkdir()
    prompt = (
        "Use Bash to run exactly: "
        "if [ -r /etc/passwd ]; then echo HOST_READABLE; "
        "else echo HOST_DENIED; fi; "
        "if [ -z \"$COPILOT_GITHUB_TOKEN\" ]; then echo TOKEN_HIDDEN; "
        "else echo TOKEN_VISIBLE; fi. "
        "Then report only the two output lines."
    )
    proc = _run_copilot_skill_child(
        copilot_bin=resolve_copilot_cli(),
        prompt=prompt,
        tools="Bash",
        target=target,
        run_dir=run_dir,
        context_dirs=(),
        timeout_s=120,
        caller_label="copilot-live-mxc",
    )
    usage = load_json(run_dir / "copilot-usage.json") or {}
    parsed = parse_copilot_output(
        proc.stdout or "",
        proc.stderr or "",
        returncode=proc.returncode,
        usage=usage,
        model_hint="gpt-5.6-sol",
        duration_seconds=0.0,
    )
    assert proc.returncode == 0
    assert "HOST_DENIED" in parsed.content
    assert "HOST_READABLE" not in parsed.content
    assert "TOKEN_HIDDEN" in parsed.content
    assert "TOKEN_VISIBLE" not in parsed.content
    assert not any(
        path.name.startswith(".copilot-workspace-")
        for path in Path(run_dir).iterdir()
    )
