"""Banner LLM line — transport resolution through the shared seam.

The banner's ``llm:`` line must report the transport a run would
actually resolve (the same decision ``raptor-resolve-mode`` and
``raptor-llm-ask --show-primary`` print), not a parallel env-key
scan: key-less transports — Bedrock signing via the AWS credential
chain — carry no API key in env or config, and the scan alone
reported "no external LLM configured" for a working orchestrator.

Hermetic: the resolution seam and the credential-chain classifier
are monkeypatched (no AWS access, no HTTP), and HOME is pinned to a
tmp dir so no operator models.json leaks in.
"""

from __future__ import annotations

import pytest

from core.llm import config as llm_config
from core.startup import init as startup_init


@pytest.fixture
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    # check_llm honours RAPTOR_CONFIG (conftest pins it at a
    # nonexistent path); these tests exercise the HOME-default
    # location, so route the override at the isolated home's config.
    monkeypatch.setenv(
        "RAPTOR_CONFIG",
        str(tmp_path / ".config" / "raptor" / "models.json"),
    )
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                "MISTRAL_API_KEY", "AWS_BEARER_TOKEN_BEDROCK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("shutil.which", lambda _bin: None)
    return tmp_path


# ---------------------------------------------------------------------------
# _resolve_primary_transport — the seam adapter
# ---------------------------------------------------------------------------

def test_delegates_to_shared_seam_offline(isolated_home, monkeypatch) -> None:
    seen: dict[str, bool] = {}

    def fake_resolve(
        prefer: list[str] | None = None, *, offline: bool = False,
    ) -> llm_config.ModelConfig:
        seen["offline"] = offline
        return llm_config.ModelConfig(
            provider="bedrock", model_name="anthropic.claude-x",
        )

    monkeypatch.setattr(
        llm_config, "_get_default_primary_model", fake_resolve,
    )
    monkeypatch.setattr(
        startup_init, "_bedrock_auth_source", lambda has_bearer: "iam-role",
    )
    assert startup_init._resolve_primary_transport() == (
        "bedrock", "anthropic.claude-x", "iam-role",
    )
    assert seen == {"offline": True}


def test_none_when_seam_resolves_nothing(isolated_home, monkeypatch) -> None:
    monkeypatch.setattr(
        llm_config, "_get_default_primary_model",
        lambda prefer=None, *, offline=False: None,
    )
    assert startup_init._resolve_primary_transport() is None


def test_claudecode_providers_map_to_none(isolated_home, monkeypatch) -> None:
    for provider in ("claudecode", "claudecode-resumable"):
        monkeypatch.setattr(
            llm_config, "_get_default_primary_model",
            lambda prefer=None, *, offline=False, _p=provider:
                llm_config.ModelConfig(provider=_p, model_name="m"),
        )
        assert startup_init._resolve_primary_transport() is None


def test_seam_errors_are_swallowed(isolated_home, monkeypatch) -> None:
    def boom(prefer: list[str] | None = None, *, offline: bool = False):
        raise RuntimeError("resolution broke")

    monkeypatch.setattr(llm_config, "_get_default_primary_model", boom)
    assert startup_init._resolve_primary_transport() is None


def test_keyed_provider_uses_key_source_vocabulary(
    isolated_home, monkeypatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(
        llm_config, "_get_default_primary_model",
        lambda prefer=None, *, offline=False: llm_config.ModelConfig(
            provider="anthropic", model_name="claude-opus-4", api_key="k",
        ),
    )
    assert startup_init._resolve_primary_transport() == (
        "anthropic", "claude-opus-4", "via ANTHROPIC_API_KEY",
    )


# ---------------------------------------------------------------------------
# _bedrock_auth_source — label only, never a secret or host detail
# ---------------------------------------------------------------------------

def _patch_chain(monkeypatch, status: str) -> None:
    monkeypatch.setattr(
        "core.startup.aws_imds._classify_chain",
        lambda env: (status, "default", "detail"),
    )


def test_bearer_label(isolated_home, monkeypatch) -> None:
    assert startup_init._bedrock_auth_source(True) == "bearer token"
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    assert startup_init._bedrock_auth_source(False) == "bearer token"


@pytest.mark.parametrize(
    ("status", "label"),
    [
        ("imds", "iam-role"),
        ("non-imds", "aws credentials"),
        ("unknown", "aws credential chain"),
        ("unparseable", "aws credential chain"),
    ],
)
def test_chain_status_labels(
    isolated_home, monkeypatch, status: str, label: str,
) -> None:
    _patch_chain(monkeypatch, status)
    assert startup_init._bedrock_auth_source(False) == label


def test_chain_classifier_errors_degrade_to_generic_label(
    isolated_home, monkeypatch,
) -> None:
    def boom(env):
        raise OSError("unreadable config")

    monkeypatch.setattr("core.startup.aws_imds._classify_chain", boom)
    assert startup_init._bedrock_auth_source(False) == "aws credential chain"


# ---------------------------------------------------------------------------
# check_llm — banner integration
# ---------------------------------------------------------------------------

def test_check_llm_prints_seam_resolved_primary(
    isolated_home, monkeypatch,
) -> None:
    monkeypatch.setattr(
        startup_init, "_resolve_primary_transport",
        lambda: ("bedrock", "anthropic.claude-x", "iam-role"),
    )
    lines, warnings = startup_init.check_llm()
    assert lines[0] == "   llm: bedrock/anthropic.claude-x (primary, iam-role)"
    assert warnings == []


def test_check_llm_keeps_no_external_when_seam_empty(
    isolated_home, monkeypatch,
) -> None:
    monkeypatch.setattr(
        startup_init, "_resolve_primary_transport", lambda: None,
    )
    lines, _warnings = startup_init.check_llm()
    assert lines == ["   llm: no external LLM configured"]


def test_check_llm_parses_commented_models_json(
    isolated_home, monkeypatch,
) -> None:
    cfg_dir = isolated_home / ".config" / "raptor"
    cfg_dir.mkdir(parents=True)
    cfg = cfg_dir / "models.json"
    cfg.write_text(
        '{\n'
        '  // primary for API work\n'
        '  "models": [\n'
        '    {"provider": "bedrock", "model": "anthropic.claude-x"},\n'
        '    {"provider": "gemini", "model": "gemini-x",'
        ' "role": "fallback", "api_key": "k"}\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    cfg.chmod(0o600)
    monkeypatch.setattr(
        startup_init, "_resolve_primary_transport",
        lambda: ("bedrock", "anthropic.claude-x", "iam-role"),
    )
    monkeypatch.setattr(startup_init, "_validator_available", lambda: False)
    lines, _warnings = startup_init.check_llm()
    assert lines[0] == "   llm: bedrock/anthropic.claude-x (primary, iam-role)"
    assert "        gemini/gemini-x (fallback, via models.json)" in lines


def test_check_llm_env_key_primary_not_listed_twice(
    isolated_home, monkeypatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(
        startup_init, "_resolve_primary_transport",
        lambda: ("anthropic", "claude-opus-4", "via ANTHROPIC_API_KEY"),
    )
    monkeypatch.setattr(startup_init, "_validator_available", lambda: False)
    lines, _warnings = startup_init.check_llm()
    assert lines[0] == (
        "   llm: anthropic/claude-opus-4 (primary, via ANTHROPIC_API_KEY)"
    )
    assert sum("anthropic" in line for line in lines) == 1


def test_check_llm_defaulted_config_entry_not_listed_twice(
    isolated_home, monkeypatch,
) -> None:
    # Config entry with no explicit "model": the seam fills in the
    # concrete model name for the primary line; the raw entry must
    # not surface again as an "unknown" fallback.
    cfg_dir = isolated_home / ".config" / "raptor"
    cfg_dir.mkdir(parents=True)
    cfg = cfg_dir / "models.json"
    cfg.write_text(
        '{"models": [{"provider": "anthropic", "api_key": "k"}]}\n',
        encoding="utf-8",
    )
    cfg.chmod(0o600)
    monkeypatch.setattr(
        startup_init, "_resolve_primary_transport",
        lambda: ("anthropic", "claude-opus-4-6", "via models.json"),
    )
    monkeypatch.setattr(startup_init, "_validator_available", lambda: False)
    lines, _warnings = startup_init.check_llm()
    assert lines[0] == (
        "   llm: anthropic/claude-opus-4-6 (primary, via models.json)"
    )
    assert sum("anthropic" in line for line in lines) == 1
    assert not any("unknown" in line for line in lines)
