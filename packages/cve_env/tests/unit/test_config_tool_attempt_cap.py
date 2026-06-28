"""Phase 12.5 surgical fix (2026-05-23): per-tool default caps for
spiral-prone tools.

bench50-20260523-015025 forensic surfaced CVE-2022-26352 (dotCMS) burning
$0.67 over 6× image_resolve calls before Phase 54-deep.2 caught the
end_turn pattern. Cross-bench evidence: 55 instances / 36 distinct CVEs
across 24 historical benches match the cost-spiral pattern (n >> M-class
3-bench threshold).

Pre-flight (2026-05-23) sampled 145 successful CVEs:
  image_resolve max=5, p95=3, p50=1

Setting `image_resolve` default cap to 5 catches the 6-call spiral
without regressing any historical success (max-successful = 5 ≤ cap = 5;
cap fires at the 6th attempt). Other tools retain default 0 (unbounded)
pending evidence — verify spiral (CVE-2024-56145) needs a different
mechanism (consecutive-error counter, not total-call counter) and is
deferred to its own /spec.

Env var override still works: `CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS=10`
re-enables permissive behavior if needed.
"""

from __future__ import annotations

import os
from unittest.mock import patch

from cve_env.config import get_tool_attempt_cap


def test_image_resolve_default_cap_is_5() -> None:
    """Phase 12.5 surgical default: image_resolve cap = 5 when no env var set."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS", None)
        assert get_tool_attempt_cap("image_resolve") == 5


def test_image_resolve_env_var_overrides_default() -> None:
    """Env var CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS overrides the default."""
    with patch.dict(os.environ, {"CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS": "10"}):
        assert get_tool_attempt_cap("image_resolve") == 10


def test_research_tool_cap_knob_works_generically() -> None:
    """Intervention #2 (2026-05-31): the per-tool cap is GENERIC, so the
    research-spiral tools (WebSearch / web_fetch) already honor
    CVE_ENV_MAX_<TOOL>_ATTEMPTS — no code needed, just the operator dial.
    Default stays 0 (unbounded): a default cap needs the 3-bench M-evidence
    this module enforces, deferred to a bench A/B."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CVE_ENV_MAX_WEBSEARCH_ATTEMPTS", None)
        os.environ.pop("CVE_ENV_MAX_WEB_FETCH_ATTEMPTS", None)
        assert get_tool_attempt_cap("WebSearch") == 0  # unbounded by default
        assert get_tool_attempt_cap("web_fetch") == 0
    with patch.dict(os.environ, {"CVE_ENV_MAX_WEBSEARCH_ATTEMPTS": "8"}):
        assert get_tool_attempt_cap("WebSearch") == 8
    with patch.dict(os.environ, {"CVE_ENV_MAX_WEB_FETCH_ATTEMPTS": "10"}):
        assert get_tool_attempt_cap("web_fetch") == 10


def test_other_tools_remain_unbounded_default() -> None:
    """Other tools (nvd_lookup, verify, docker_run, etc.) keep default 0
    until M-class evidence supports their own defaults."""
    with patch.dict(os.environ, {}, clear=False):
        for tool in [
            "nvd_lookup",
            "github_fetch",
            "verify",
            "docker_run",
            "dockerfile_gen",
            "docker_build",
            "source_build",
            "docker_compose_up",
            "bash",
        ]:
            os.environ.pop(f"CVE_ENV_MAX_{tool.upper()}_ATTEMPTS", None)
            assert get_tool_attempt_cap(tool) == 0, (
                f"{tool} default should be 0 (unbounded); "
                f"got {get_tool_attempt_cap(tool)}"
            )


def test_env_var_invalid_falls_back_to_default() -> None:
    """Invalid env-var value falls back to the per-tool default (not 0)."""
    with patch.dict(os.environ, {"CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS": "not_a_number"}):
        assert get_tool_attempt_cap("image_resolve") == 5
