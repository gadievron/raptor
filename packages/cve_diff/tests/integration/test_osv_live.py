"""
Live OSV integration test. Hits api.osv.dev for a well-known CVE and asserts
the discoverer returns a canonical-scored result.

Skipped by default (addopts `-m 'not integration'`). Run explicitly with
`.venv/bin/pytest tests/integration -m integration -q`.
"""

from __future__ import annotations

import pytest

from cve_diff.discovery.osv import OSVDiscoverer


@pytest.mark.integration
def test_osv_live_discovers_curl_cve_2023_38545() -> None:
    """CVE-2023-38545 (SOCKS5 heap buffer overflow, curl).

    Chosen because it has a canonical GitHub upstream (curl/curl), a
    well-populated OSV record with fix commits, and has been stable for
    over a year — so this test shouldn't start failing because OSV retired
    or rewrote the record.
    """
    result = OSVDiscoverer().fetch("CVE-2023-38545")
    assert result is not None, "OSV returned None — network or rate-limit?"
    assert result.confidence > 0, f"low confidence from OSV: {result.confidence}"
    assert result.tuples, "no patch tuples extracted"
    urls = [t.repository_url.lower() for t in result.tuples]
    assert any("curl/curl" in u for u in urls), f"curl/curl missing from {urls}"
    assert all(t.fix_commit for t in result.tuples), "a tuple lacks fix_commit"
