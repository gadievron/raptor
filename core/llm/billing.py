"""Conservative, offline billing classification for pre-spend estimates."""

from collections.abc import Sequence
import logging
import os

from .client import _pinned_llm_config
from .config import ModelConfig, _entry_auth_resolvable, _get_default_primary_model

logger = logging.getLogger(__name__)


def model_uses_metered_api(model: ModelConfig | None) -> bool:
    """Require an API route, not a catalog price or CLI token valuation.

    A subscription-authenticated CLI and local inference do not have a
    per-call USD estimate. Cloud-backed CLI sessions and credentials held
    by a broker remain metered even without a local API-key environment
    variable. Authentication is inspected, never probed over the network.
    """
    if model is None or model.provider == "ollama":
        return False
    if model.provider in {"claudecode", "claudecode-resumable"}:
        return bool(model.api_key or os.getenv("ANTHROPIC_API_KEY") or any(
            os.getenv(name) for name in (
                "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
                "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE",
            )
        ))
    if model.provider == "bedrock" and model.aws_profile:
        return True
    return _entry_auth_resolvable(model)


def can_estimate_api_spend(model_names: Sequence[str] = ()) -> bool:
    """True only when every requested primary route has metered billing.

    Match audit's pinned-model resolution without constructing an LLM client
    or making availability probes. Unknown or mixed billing suppresses the
    dollar projection; it does not claim the eventual run is free.
    """
    try:
        for name in model_names or ("default",):
            model = (_get_default_primary_model(offline=True)
                     if name == "default" else
                     _pinned_llm_config(name, offline=True).primary_model)
            if not model_uses_metered_api(model):
                return False
        return True
    except Exception:
        logger.debug("billing route unavailable for pre-spend estimate", exc_info=True)
        return False
