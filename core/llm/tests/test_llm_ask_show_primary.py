"""``raptor-llm-ask --show-primary`` probes the run's own resolution.

An explicit ``--model`` probe resolves through the override path and
can succeed while a run (which resolves the default primary) routes
somewhere else entirely. ``--show-primary`` answers the question the
operator actually has before a run: "what will the default primary
be?" — through the same LLMClient → config.primary_model path a
pipeline run uses — and exits without sending anything.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from core.testing.standalone_cli import run_standalone_cli

REPO_ROOT = Path(__file__).resolve().parents[3]
LLM_ASK = REPO_ROOT / "libexec" / "raptor-llm-ask"

# Env vars whose ambient values would change what the subprocess
# resolves (provider keys beat nothing; the dispatcher socket beats
# direct SDK routes; RAPTOR_BEDROCK_* is a Bedrock opt-in signal).
_AMBIENT_SIGNALS = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
    "MISTRAL_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "RAPTOR_LLM_SOCKET",
    "RAPTOR_BEDROCK_MODEL", "RAPTOR_BEDROCK_PROFILE", "AWS_PROFILE",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SHARED_CREDENTIALS_FILE", "OLLAMA_HOST",
)


@pytest.fixture(autouse=True)
def _isolate_scorecard(tmp_path):
    """Only child processes construct clients; keep the parent SDK-free."""
    with pytest.MonkeyPatch.context() as state:
        state.setenv("RAPTOR_SCORECARD_PATH", str(tmp_path / "scorecard.json"))
        yield


def _run(args, tmp_path, models=None, timeout=120, **kwargs):
    """Run raptor-llm-ask hermetically against a temp models config."""
    import os
    env = {k: v for k, v in os.environ.items() if k not in _AMBIENT_SIGNALS}
    env["_RAPTOR_TRUSTED"] = "1"
    env["RAPTOR_SCORECARD_PATH"] = str(tmp_path / "scorecard.json")
    cfg = tmp_path / "models.json"
    if models is not None:
        cfg.write_text(json.dumps({"models": models}))
    env["RAPTOR_CONFIG"] = str(cfg)
    return run_standalone_cli(
        [sys.executable, str(LLM_ASK), *args],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=str(tmp_path), **kwargs,
    )


def test_show_primary_prints_default_resolution_and_exits_zero(tmp_path):
    # A keyed gemini entry wins default-primary resolution (config file
    # beats env autodetect); the probe must report it without sending
    # any prompt — and without requiring one. stdout is exactly one
    # machine-parseable line; anything diagnostic belongs on stderr.
    proc = _run(["--show-primary"], tmp_path, models=[
        {"provider": "gemini", "model": "gemini-2.5-pro",
         "api_key": "test-key"},
    ])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "gemini/gemini-2.5-pro\n"
    # A probe must not litter the operator's cwd with cache dirs.
    assert not (tmp_path / "out").exists()


def test_show_primary_surfaces_config_warnings_on_stderr(tmp_path):
    # The probe exists to diagnose misrouted resolution, so config
    # warnings (here: an unknown role) must stay visible by default
    # while stdout stays a single parseable line.
    proc = _run(["--show-primary"], tmp_path, models=[
        {"provider": "gemini", "model": "gemini-2.5-pro",
         "api_key": "test-key"},
        {"provider": "gemini", "model": "gemini-2.5-flash",
         "api_key": "test-key", "role": "primary"},
    ])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "gemini/gemini-2.5-pro\n"
    assert "unknown role" in proc.stderr, proc.stderr


def test_show_primary_rejects_explicit_model(tmp_path):
    # --model resolves through the override path; combining it with the
    # default-resolution probe would answer the wrong question.
    proc = _run(
        ["--show-primary", "--model", "gemini-2.5-pro"], tmp_path,
        models=[],
    )
    assert proc.returncode == 2
    assert "--show-primary" in proc.stderr
    assert "omit --model" in proc.stderr


def test_show_primary_ignores_piped_stdin(tmp_path):
    # Scripted probes commonly run with stdin attached to a pipe; the
    # probe must not block on (or consume) it as a prompt.
    proc = _run(["--show-primary"], tmp_path, models=[
        {"provider": "gemini", "model": "gemini-2.5-pro",
         "api_key": "test-key"},
    ], input="not a prompt\n")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "gemini/gemini-2.5-pro\n"
