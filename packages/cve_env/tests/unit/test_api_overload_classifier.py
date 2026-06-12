"""Phase 33.T.3 → Phase 34.1 GREEN — API-Overload classifier tests.

Phase 33.3 Cat 1 B4 + 33.2a Anomaly 4: 28 Phase 31 CVEs hit Anthropic
API 529 Overload during the 03:00–03:43 UTC outage window. All 28 had:

- status == "error"
- give_up_reason == "" (empty)
- final_text starts with "API Error: Repeated 529 Overloaded errors"

Phase 33.T.3 (commit f496a14) shipped RED via xfail(strict=True);
Phase 34.1 shipped GREEN by adding the `_classify_api_overload` helper
in `src/cve_env/agent/loop.py`. xfail markers removed atomically with
helper landing.

Reference: 33.3 reconciled-final artifact-final.md Cat 2 E1 +
            33.2a-RECONCILE Anomaly 4 +
            closeout-corrections-phase33-2026-05-15.md DRIFT #5.
"""
from __future__ import annotations

import pytest


def _try_import_classifier():
    """Try to import the api_overload classifier.

    Returns None until a future engine phase ships the classifier.
    """
    try:
        from cve_env.agent.loop import _classify_api_overload  # type: ignore
        return _classify_api_overload
    except ImportError:
        return None


def test_classify_api_overload_helper_exists() -> None:
    """The classifier function should exist when shipped."""
    classifier = _try_import_classifier()
    assert classifier is not None


def test_classify_api_overload_matches_529_pattern() -> None:
    """When final_text matches '529 Overloaded' pattern, classify as
    api_overload.

    Sample final_text values from Phase 31 014156 28 API-Overload CVEs:
    - "API Error: Repeated 529 Overloaded errors. The API is at capacity..."
    """
    classifier = _try_import_classifier()
    assert classifier is not None

    sample = (
        "API Error: Repeated 529 Overloaded errors. The API is at capacity "
        "— this is usually temporary. Try again in a moment."
    )
    assert classifier(sample) == "api_overload"


def test_classify_api_overload_negative_cases() -> None:
    """Non-529-Overload final_text should NOT classify as api_overload."""
    classifier = _try_import_classifier()
    assert classifier is not None

    # Empty
    assert classifier("") != "api_overload"
    # Normal completion text
    assert classifier("Build successful.") != "api_overload"
    # Other API errors (rate-limit but not 529 overload)
    assert classifier("API Error: rate_limit_exceeded") != "api_overload"
    # Refusal text
    assert classifier("API Error: Claude Code is unable to respond...") != "api_overload"
