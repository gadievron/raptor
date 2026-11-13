"""Commit reference association requires the documented GitHub hostname."""

import pytest

from core.dataflow.ghsa_harvester import _first_commit_ref


_SHA = "a" * 40
_PATH = f"owned/inert/commit/{_SHA}"


@pytest.mark.parametrize("url", [
    f"https://notgithub.com/{_PATH}",
    f"https://example.invalid/path/github.com/{_PATH}",
    f"https://example.invalid/#https://github.com/{_PATH}",
    f"https://github.com@example.invalid/path/github.com/{_PATH}",
    f"https://github.com/not-a-commit?next=https://github.com/{_PATH}",
    f"https://github.com/not-a-commit#https://github.com/{_PATH}",
    f"https://github.com/nested/github.com/{_PATH}",
], ids=["host-suffix", "path-substring", "fragment", "userinfo",
        "same-host-query", "same-host-fragment", "nested-path"])
def test_other_hosts_cannot_supply_github_commit_identity(url):
    assert _first_commit_ref({"references": [{"url": url}]}) is None


@pytest.mark.parametrize("scheme", ["https", "http"])
def test_canonical_host_retains_commit_identity(scheme):
    assert _first_commit_ref({"references": [{"url": f"{scheme}://github.com/{_PATH}"}]}) == (
        "owned", "inert", _SHA,
    )


def test_unrelated_reference_does_not_hide_later_canonical_commit():
    references = [
        {"url": f"https://example.invalid/github.com/{_PATH}"},
        {"url": "https://github.com/owned/second/commit/abcdef1"},
    ]
    assert _first_commit_ref({"references": references}) == ("owned", "second", "abcdef1")


def test_malformed_url_does_not_hide_later_canonical_commit():
    references = [{"url": "https://[broken"}, {"url": f"https://github.com/{_PATH}"}]
    assert _first_commit_ref({"references": references}) == ("owned", "inert", _SHA)
