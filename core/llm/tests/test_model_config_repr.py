"""ModelConfig repr/str must never leak the API key.

ModelConfig instances travel through debug logs, error messages and
exception args; the auto-generated dataclass repr printed ``api_key``
verbatim. The custom ``__repr__`` masks it at the chokepoint so no
format site can leak the credential.
"""

from __future__ import annotations

from core.llm.config import ModelConfig


def _mc(api_key: str | None) -> ModelConfig:
    return ModelConfig(
        provider="anthropic",
        model_name="claude-test",
        api_key=api_key,
    )


def test_repr_and_str_never_contain_key_value() -> None:
    secret = "sk-live-EXTREMELY-SECRET-0123456789"
    mc = _mc(secret)
    for rendered in (repr(mc), str(mc), f"{mc}", f"{mc!r}"):
        assert secret not in rendered
        assert "api_key='***'" in rendered
        # Non-secret fields stay visible — the repr must remain useful.
        assert "claude-test" in rendered
        assert "anthropic" in rendered


def test_repr_without_key_shows_none_unmasked() -> None:
    # Two-direction guard: masking only fires on a present key — a
    # None key renders as None so "no credential configured" stays
    # distinguishable from "credential redacted" when debugging.
    rendered = repr(_mc(None))
    assert "api_key=None" in rendered
    assert "***" not in rendered
