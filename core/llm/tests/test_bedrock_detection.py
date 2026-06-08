"""Tests for the Bedrock-detection opt-in gate.

PR #696's review identified that an earlier draft treated bare
``AWS_REGION`` as Bedrock intent, FP-firing detection on any AWS
user whose shell happened to export AWS_REGION (a common case).
The shipped detection gates on the EXPLICIT opt-in signal
(``AWS_BEARER_TOKEN_BEDROCK``) AND requires a usable path
(dispatcher or boto3 SDK).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _clear_availability_cache():
    """Each test sees a fresh availability calculation."""
    import core.llm.detection as det
    det._cached_llm_availability = None
    yield
    det._cached_llm_availability = None


def test_bare_aws_region_is_not_bedrock_intent(monkeypatch):
    """Setting only ``AWS_REGION`` (or ``AWS_DEFAULT_REGION``) without
    the explicit Bedrock signal must NOT mark the operator as a
    Bedrock user.  AWS_REGION is set for countless unrelated reasons."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    with patch("core.llm.detection.shutil.which", return_value=None), \
         patch("core.llm.detection._get_available_ollama_models",
               return_value=[]), \
         patch("core.llm.detection._config_has_keyed_models",
               return_value=False):
        from core.llm.detection import detect_llm_availability
        av = detect_llm_availability()
        # Bare AWS_REGION → no LLM detected
        assert av.external_llm is False
        assert av.llm_available is False


def test_bedrock_bearer_with_dispatcher_marks_external_llm(monkeypatch):
    """The supported deployment: bearer token + dispatcher route.
    No SDK required in this process; dispatcher signs in the parent."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-bearer-token")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/raptor.sock")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    with patch("core.llm.detection.shutil.which", return_value=None), \
         patch("core.llm.detection._get_available_ollama_models",
               return_value=[]):
        from core.llm.detection import detect_llm_availability
        av = detect_llm_availability()
        assert av.external_llm is True


def test_bedrock_bearer_with_boto3_marks_external_llm(monkeypatch):
    """Direct (non-dispatcher) Bedrock — requires boto3 in this
    process for SigV4 signing."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-bearer-token")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    with patch("core.llm.detection.BOTO3_SDK_AVAILABLE", True), \
         patch("core.llm.detection.shutil.which", return_value=None), \
         patch("core.llm.detection._get_available_ollama_models",
               return_value=[]), \
         patch("core.llm.detection._config_has_keyed_models",
               return_value=False):
        from core.llm.detection import detect_llm_availability
        av = detect_llm_availability()
        assert av.external_llm is True


def test_bedrock_bearer_without_path_does_not_mark_external_llm(
    monkeypatch,
):
    """Bearer set but neither dispatcher nor boto3 — no usable path,
    so external_llm stays False (operator gets the warning)."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-bearer-token")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    with patch("core.llm.detection.BOTO3_SDK_AVAILABLE", False), \
         patch("core.llm.detection.shutil.which", return_value=None), \
         patch("core.llm.detection._get_available_ollama_models",
               return_value=[]), \
         patch("core.llm.detection._config_has_keyed_models",
               return_value=False):
        from core.llm.detection import detect_llm_availability
        av = detect_llm_availability()
        assert av.external_llm is False


def test_warn_fires_when_bearer_set_but_no_path(monkeypatch):
    """Operator-facing warning when Bedrock opt-in is set but no
    usable path exists.  Verifies the hint message references both
    boto3 and the dispatcher."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-bearer-token")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    seen: list = []
    fake_logger = type("L", (), {
        "warning": lambda self, msg, *a, **kw: seen.append(str(msg)),
        "debug":   lambda self, msg, *a, **kw: None,
        "info":    lambda self, msg, *a, **kw: None,
        "error":   lambda self, msg, *a, **kw: None,
    })()
    with patch("core.llm.detection.BOTO3_SDK_AVAILABLE", False), \
         patch("core.llm.detection.logger", fake_logger):
        from core.llm.detection import _warn_unusable_keys
        _warn_unusable_keys()
    bedrock_warnings = [m for m in seen if "AWS_BEARER_TOKEN_BEDROCK" in m]
    assert bedrock_warnings, (
        f"expected Bedrock warning; got {seen!r}"
    )
    msg = bedrock_warnings[0]
    assert "boto3" in msg
    assert "dispatcher" in msg or "RAPTOR_LLM_SOCKET" in msg


def test_no_warning_when_only_aws_region_set(monkeypatch):
    """A user with bare AWS_REGION (no Bedrock signal) must NOT get
    spurious Bedrock warnings."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    seen: list = []
    fake_logger = type("L", (), {
        "warning": lambda self, msg, *a, **kw: seen.append(str(msg)),
        "debug":   lambda self, msg, *a, **kw: None,
        "info":    lambda self, msg, *a, **kw: None,
        "error":   lambda self, msg, *a, **kw: None,
    })()
    with patch("core.llm.detection.logger", fake_logger):
        from core.llm.detection import _warn_unusable_keys
        _warn_unusable_keys()
    bedrock_warnings = [
        m for m in seen
        if "AWS_BEARER_TOKEN_BEDROCK" in m or "Bedrock" in m
    ]
    assert not bedrock_warnings, (
        f"AWS_REGION alone must not produce Bedrock warnings; got {seen!r}"
    )


# ---------------------------------------------------------------------------
# _build_bedrock_config — default-model surface (P1.5)
# ---------------------------------------------------------------------------

def test_bedrock_builder_returns_none_without_bearer(monkeypatch):
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    from core.llm.config import _build_bedrock_config
    assert _build_bedrock_config() is None


def test_bedrock_builder_emits_bare_id_in_us_region(monkeypatch):
    """Mantle accepts BARE model IDs only — regional routing happens via
    the hostname (``bedrock-mantle.<region>.api.aws``), not via a model-id
    prefix.  The builder must NOT prepend ``us.``/``eu.``/``apac.``."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None
    assert cfg.provider == "bedrock"
    assert cfg.model_name.startswith("anthropic.")
    assert not cfg.model_name.startswith(("us.", "eu.", "apac.", "au.", "global."))


def test_bedrock_builder_emits_bare_id_in_eu_region(monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.model_name.startswith("anthropic.")
    assert not cfg.model_name.startswith(("us.", "eu.", "apac.", "au.", "global."))


def test_bedrock_builder_emits_bare_id_in_apac_region(monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.model_name.startswith("anthropic.")
    assert not cfg.model_name.startswith(("us.", "eu.", "apac.", "au.", "global."))


def test_bedrock_builder_works_without_region(monkeypatch):
    """The builder no longer needs a region to synthesise a model id —
    Mantle's host carries the region at request time, the builder only
    needs a bearer + the bare model name to return a config.  Region
    resolution happens later (in the dispatcher) when the request is
    actually made."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.model_name.startswith("anthropic.")


def test_bedrock_builder_carries_bearer_in_api_key(monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-token-abc")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.api_key == "bedrock-token-abc"


def test_bedrock_builder_default_api_is_mantle(monkeypatch):
    """Default behaviour when ``RAPTOR_BEDROCK_API`` is unset: mantle.
    Mantle has full feature support (streaming, tool use, prompt caching,
    computer use); operators only opt out for models not yet on it."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.delenv("RAPTOR_BEDROCK_API", raising=False)
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.bedrock_api == "mantle"


def test_bedrock_builder_respects_raptor_bedrock_api_env(monkeypatch):
    """``RAPTOR_BEDROCK_API=runtime`` flips the default to legacy
    InvokeModel for the run."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("RAPTOR_BEDROCK_API", "runtime")
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.bedrock_api == "runtime"


def test_bedrock_builder_invalid_api_value_falls_back_to_mantle(monkeypatch):
    """A typo in ``RAPTOR_BEDROCK_API`` (e.g. ``"bedrock-mantle"``)
    must not hard-fail at import time — the builder snaps back to
    mantle so the run starts and the operator can fix the typo without
    blocking on a traceback."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("RAPTOR_BEDROCK_API", "bedrock-mantle")  # typo
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None and cfg.bedrock_api == "mantle"


def test_model_config_from_entry_models_json_overrides_env(monkeypatch):
    """Per-model ``bedrock_api`` in models.json wins over the
    ``RAPTOR_BEDROCK_API`` env var.  Lets operators run hybrid setups
    (most models on Mantle, one model on runtime because Mantle doesn't
    host it yet)."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("RAPTOR_BEDROCK_API", "mantle")
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "provider": "bedrock",
        "model": "anthropic.claude-haiku-3-5-20241022-v1:0",
        "bedrock_api": "runtime",
    })
    assert cfg.bedrock_api == "runtime"


def test_model_config_from_entry_inherits_env_when_unset(monkeypatch):
    """No ``bedrock_api`` field in the entry → use env default."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setenv("RAPTOR_BEDROCK_API", "runtime")
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "provider": "bedrock",
        "model": "anthropic.claude-haiku-4-5",
    })
    assert cfg.bedrock_api == "runtime"


def test_model_config_from_entry_invalid_per_model_falls_back(monkeypatch):
    """Per-model typo snaps to mantle (same defensive shape as the env
    fallback above)."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "provider": "bedrock",
        "model": "anthropic.claude-haiku-4-5",
        "bedrock_api": "MANTEL",  # typo
    })
    assert cfg.bedrock_api == "mantle"


def test_bedrock_appears_in_default_provider_order():
    """The default-order resolver must try Bedrock so an operator
    who's set only AWS_BEARER_TOKEN_BEDROCK gets a config back from
    ``_get_default_primary_model()``."""
    from core.llm.config import _DEFAULT_PROVIDER_ORDER
    assert "bedrock" in _DEFAULT_PROVIDER_ORDER


def test_credential_isolation_builder_returns_none_after_env_pop(
    monkeypatch,
):
    """The supported flow: CredentialStore.__init__ pops
    AWS_BEARER_TOKEN_BEDROCK from env BEFORE LLMConfig() is
    constructed.  The builder must then return None and the worker
    falls back to has_dispatcher_route for detection.  This test
    verifies the contract documented in ``_build_bedrock_config``."""
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    from core.llm.config import _build_bedrock_config
    # Bearer not in env (popped by CredentialStore) → builder returns
    # None so the resolver continues to the next provider.
    assert _build_bedrock_config() is None


def test_model_config_from_entry_derives_bedrock_provider(monkeypatch):
    """Operator config without an explicit ``provider`` field but
    with a Bedrock-shaped model id derives ``provider="bedrock"``
    via provider_of() — so the dispatcher routes correctly."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-token-xyz")
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "model": "us.anthropic.claude-opus-4-7",
    })
    assert cfg.provider == "bedrock"
    assert cfg.api_key == "bedrock-token-xyz"


def test_model_config_from_entry_preserves_explicit_provider():
    """Explicit ``provider`` wins over derived provider."""
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "provider": "anthropic",
        "model": "us.anthropic.claude-opus-4-7",
        "api_key": "sk-ant-test",
    })
    # Operator's explicit provider preserved — they may want to use
    # the raw model ID through the direct-Anthropic provider for
    # some reason (edge case but should be respected).
    assert cfg.provider == "anthropic"
    assert cfg.api_key == "sk-ant-test"


def test_model_config_from_entry_direct_api_unchanged():
    """Existing direct-API behaviour preserved."""
    from core.llm.config import _model_config_from_entry
    cfg = _model_config_from_entry({
        "model": "claude-opus-4-7",
        "api_key": "sk-ant-direct",
    })
    # provider_of("claude-opus-4-7") returns "anthropic"
    assert cfg.provider == "anthropic"
    assert cfg.api_key == "sk-ant-direct"


# ---------------------------------------------------------------------------
# Direct-SigV4 detection gap (Issue B from adversarial review).
# Co-authored with owen10380 — surfaced via the May 28 review point
# "gate has_bedrock (and the warning) on the same opt-in signal
# selection uses, not bare AWS_REGION".
# ---------------------------------------------------------------------------

def test_config_has_keyed_models_recognises_bedrock_with_aws_keys(
    monkeypatch,
):
    """Operator with AWS access keys + a config-file Bedrock model
    (no explicit provider field) + boto3 installed gets detected
    even without the bearer token.  This was the direct-SigV4 gap."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    fake_entries = [{"model": "us.anthropic.claude-opus-4-7"}]
    with patch("core.llm.detection._read_config_models",
               return_value=fake_entries), \
         patch("core.llm.detection.BOTO3_SDK_AVAILABLE", True):
        from core.llm.detection import _config_has_keyed_models
        assert _config_has_keyed_models() is True


def test_config_has_keyed_models_bedrock_via_dispatcher(monkeypatch):
    """Bedrock config-file entry + dispatcher route → usable even
    without boto3 in this process (dispatcher signs in the parent)."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-token")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/raptor.sock")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fake_entries = [{"model": "global.anthropic.claude-haiku-4-5"}]
    with patch("core.llm.detection._read_config_models",
               return_value=fake_entries), \
         patch("core.llm.detection.BOTO3_SDK_AVAILABLE", False):
        from core.llm.detection import _config_has_keyed_models
        assert _config_has_keyed_models() is True


def test_config_has_keyed_models_bedrock_without_path_skipped(
    monkeypatch,
):
    """Bedrock config entry but neither dispatcher nor boto3 → no
    usable path → skipped (operator gets the warning via
    _warn_unusable_keys)."""
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-token")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    fake_entries = [{"model": "us.anthropic.claude-opus-4-7"}]
    with patch("core.llm.detection._read_config_models",
               return_value=fake_entries), \
         patch("core.llm.detection.BOTO3_SDK_AVAILABLE", False):
        from core.llm.detection import _config_has_keyed_models
        assert _config_has_keyed_models() is False


def test_config_has_keyed_models_bare_aws_region_no_fire(monkeypatch):
    """Bedrock config entry but only AWS_REGION (no bearer, no keys)
    → no signal.  AWS_REGION alone is set for countless unrelated
    reasons and must not FP-fire detection."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    fake_entries = [{"model": "us.anthropic.claude-opus-4-7"}]
    with patch("core.llm.detection._read_config_models",
               return_value=fake_entries), \
         patch("core.llm.detection.BOTO3_SDK_AVAILABLE", True):
        from core.llm.detection import _config_has_keyed_models
        # Path exists (boto3) but no auth signal → not usable
        assert _config_has_keyed_models() is False
