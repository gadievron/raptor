"""
Live NVD integration tests. Hit services.nvd.nist.gov for a well-known CVE
and assert `NvdDiscoverer.fetch` extracts the signals the cascade depends on.

Skipped by default (addopts `-m 'not integration'`). Run explicitly with
`.venv/bin/pytest tests/integration -m integration -q`.
"""

from __future__ import annotations

import pytest

from cve_diff.discovery.nvd import NvdDiscoverer


@pytest.mark.integration
def test_nvd_live_fetch_returns_none_when_no_patch_tagged_github_commits() -> None:
    """For CVE-2021-44228, NVD's references[] carry Apache advisory /
    release-note URLs, not github `/commit/<sha>` URLs with `Patch` tag.
    `fetch` must return None in that case — the cascade then falls
    through to github_api, which is the intended behavior.

    This test pins the "no Patch-tagged github commit → None" contract:
    if NVD silently adds a Patch commit URL later, this test will flip
    to surface that (and should be updated / paired with a passing
    fixture).
    """
    result = NvdDiscoverer().fetch("CVE-2021-44228")
    # None is the correct outcome here; if NVD adds a Patch-tag github
    # commit URL in the future, tighten this to assert the DiscoveryResult
    # shape instead.
    assert result is None
