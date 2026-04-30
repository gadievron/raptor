from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests
import responses

from cve_diff.discovery.osv import OSVDiscoverer

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "osv"


def _fixture(cve: str) -> dict:
    return json.loads((FIXTURES / f"{cve}.json").read_text())


class TestOSVParsing:
    """Parser tests against real OSV fixture snapshots (captured from api.osv.dev)."""

    def test_curl_extracts_fix_and_introduced(self) -> None:
        """
        CVE-2023-38545 is the golden anchor — single range with both `fixed` and
        `introduced` as real commit SHAs.
        """
        result = OSVDiscoverer.parse(_fixture("CVE-2023-38545"))
        assert len(result.tuples) == 1
        tup = result.tuples[0]
        assert tup.repository_url == "https://github.com/curl/curl"
        assert tup.fix_commit == "172e54cda18412da73fd8eb4e444e8a5b371ca59"
        assert tup.introduced == "b8d1366852fd0034374c5de1e4968c7a224f77cc"

    def test_xz_yields_nothing_when_only_last_affected(self) -> None:
        """
        CVE-2024-3094 has no `fixed` event — only `last_affected` and
        `introduced: '0'` markers. The reference OSV parser declines to return
        these; we match that behaviour so the cascade can fall through.
        """
        result = OSVDiscoverer.parse(_fixture("CVE-2024-3094"))
        assert result.tuples == ()

    def test_openssh_extracts_real_fix_commit(self) -> None:
        """CVE-2024-6387 has many ranges; exactly one range carries a real `fixed` event."""
        result = OSVDiscoverer.parse(_fixture("CVE-2024-6387"))
        assert len(result.tuples) >= 1
        fix_commits = {t.fix_commit for t in result.tuples}
        assert "e1f438970e5a337a17070a637c1b9e19697cad09" in fix_commits

    def test_introduced_zero_marker_is_dropped(self) -> None:
        """OSV uses 'introduced: 0' to mean 'from the beginning of history'."""
        result = OSVDiscoverer.parse(_fixture("CVE-2024-6387"))
        for tup in result.tuples:
            assert tup.introduced != "0"


class TestOSVCommitRefPreference:
    """
    When OSV carries *both* a range `fixed` event and a reference `/commit/`
    URL for the same repo, the reference commit should win. Rationale: the
    range `fixed` is typically the release-tag commit (``VERSION: 1.1.12``)
    while the reference ``/commit/...`` is the actual bug-fix commit.
    """

    def test_ref_commit_emitted_before_range_fixed_same_repo(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/opencontainers/runc",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "51d5e94601ceffbbd85688df1c928ecccbfa4685"},
                    ],
                }],
            }],
            "references": [
                {"type": "WEB", "url": "https://github.com/opencontainers/runc/commit/02120488a4c0fc487d1ed2867e901eeed7ce8ecf"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        fixes = [t.fix_commit for t in result.tuples]
        assert fixes == ["02120488a4c0fc487d1ed2867e901eeed7ce8ecf"]

    def test_range_used_when_no_ref_commit(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/curl/curl",
                    "events": [{"fixed": "172e54cda18412da73fd8eb4e444e8a5b371ca59"}],
                }],
            }],
        }
        result = OSVDiscoverer.parse(vuln)
        assert len(result.tuples) == 1
        assert result.tuples[0].fix_commit == "172e54cda18412da73fd8eb4e444e8a5b371ca59"

    def test_ref_and_range_for_different_repos_both_kept(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/rapier1/hpn-ssh",
                    "events": [{"fixed": "6518797401f2ea05e4e5cc9e38a26221c7e1f3ca"}],
                }],
            }],
            "references": [
                {"type": "WEB", "url": "https://github.com/openssh/openssh-portable/commit/81c1099d22b81ebfd20a334ce986c4f753b0db29"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        repos = {t.repository_url for t in result.tuples}
        assert "https://github.com/rapier1/hpn-ssh" in repos
        assert "https://github.com/openssh/openssh-portable" in repos


class TestKernelShortLinkRefs:
    """
    `kernel.dance/<sha>` and `git.kernel.org/{linus,stable}/c/<sha>` URLs
    appear in OSV FIX/WEB references for kernel CVEs that would otherwise
    have no github-shaped fix link. Both carry mainline SHAs; they map to
    torvalds/linux.
    """

    def test_kernel_dance_url_maps_to_torvalds_linux(self) -> None:
        vuln = {
            "references": [
                {"type": "FIX", "url": "https://kernel.dance/f342de4e2f33e0e39165d8639387aa6c19dff660"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        assert len(result.tuples) == 1
        tup = result.tuples[0]
        assert tup.repository_url == "https://github.com/torvalds/linux"
        assert tup.fix_commit == "f342de4e2f33e0e39165d8639387aa6c19dff660"

    def test_git_kernel_org_stable_c_url_maps_to_torvalds_linux(self) -> None:
        vuln = {
            "references": [
                {"type": "WEB", "url": "https://git.kernel.org/stable/c/c60d252949caf9aba537525195edae6bbabc35eb"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        assert any(t.repository_url == "https://github.com/torvalds/linux" for t in result.tuples)
        assert any(t.fix_commit == "c60d252949caf9aba537525195edae6bbabc35eb" for t in result.tuples)

    def test_git_kernel_org_linus_c_url_maps_to_torvalds_linux(self) -> None:
        vuln = {
            "references": [
                {"type": "FIX", "url": "https://git.kernel.org/linus/c/abcdef1234567890abcdef1234567890abcdef12"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        assert len(result.tuples) == 1
        assert result.tuples[0].repository_url == "https://github.com/torvalds/linux"
        assert result.tuples[0].fix_commit == "abcdef1234567890abcdef1234567890abcdef12"

    def test_kernel_short_link_dedup_within_refs(self) -> None:
        """Two refs that reduce to the same (repo, sha) emit one tuple."""
        sha = "deadbeef1234567890deadbeef1234567890dead"
        vuln = {
            "references": [
                {"type": "WEB", "url": f"https://kernel.dance/{sha}"},
                {"type": "FIX", "url": f"https://git.kernel.org/stable/c/{sha}"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        assert len(result.tuples) == 1

    def test_unrelated_url_does_not_produce_kernel_tuple(self) -> None:
        vuln = {
            "references": [
                {"type": "WEB", "url": "https://www.openwall.com/lists/oss-security/2024/04/10/22"},
                {"type": "WEB", "url": "https://example.com/path/abc123def456/more"},
            ],
        }
        result = OSVDiscoverer.parse(vuln)
        assert result.tuples == ()


class TestOSVFetch:
    """HTTP behaviour — mocked via `responses` so CI doesn't need network."""

    @responses.activate
    def test_fetches_direct_endpoint(self) -> None:
        responses.get(
            "https://api.osv.dev/v1/vulns/CVE-2023-38545",
            json=_fixture("CVE-2023-38545"),
            status=200,
        )
        result = OSVDiscoverer().fetch("CVE-2023-38545")
        assert result is not None
        assert len(result.tuples) == 1

    @responses.activate
    def test_404_falls_through_to_batch(self) -> None:
        responses.get(
            "https://api.osv.dev/v1/vulns/CVE-2024-9999",
            json={"code": 5, "message": "not found"},
            status=404,
        )
        responses.post(
            "https://api.osv.dev/v1/query",
            json={"results": [{"vulns": [_fixture("CVE-2023-38545")]}]},
            status=200,
        )
        result = OSVDiscoverer().fetch("CVE-2024-9999")
        assert result is not None
        assert len(result.tuples) == 1

    @responses.activate
    def test_returns_none_when_both_endpoints_miss(self) -> None:
        responses.get(
            "https://api.osv.dev/v1/vulns/CVE-2024-9999",
            json={}, status=404,
        )
        responses.post(
            "https://api.osv.dev/v1/query",
            json={"results": [{}]},
            status=200,
        )
        assert OSVDiscoverer().fetch("CVE-2024-9999") is None

    @responses.activate
    def test_network_error_returns_none(self) -> None:
        responses.get(
            "https://api.osv.dev/v1/vulns/CVE-2024-9999",
            body=requests.ConnectionError("boom"),
        )
        assert OSVDiscoverer().fetch("CVE-2024-9999") is None


@pytest.mark.integration
class TestOSVLive:
    """Live OSV hit — marked `integration`, skipped by default."""

    def test_live_curl(self) -> None:
        result = OSVDiscoverer().fetch("CVE-2023-38545")
        assert result is not None
        assert any(t.repository_url == "https://github.com/curl/curl" for t in result.tuples)
