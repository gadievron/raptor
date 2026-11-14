"""Advisory hash length bounds must not manufacture shorter identities."""

import pytest

from core.dataflow.ghsa_harvester import _first_commit_ref


@pytest.mark.parametrize("token", ["a" * 41, "a" * 80, "a" * 40 + "F"], ids=["forty-one", "eighty", "uppercase-hex-tail"])
def test_overlong_hex_token_cannot_supply_shorter_commit(token):
    adv = {"references": [{"url": f"https://github.com/owned/inert/commit/{token}"}]}
    assert _first_commit_ref(adv) is None


@pytest.mark.parametrize("suffix", ["", ".patch", ".diff", "/", "?view=split", "#diff-owned"], ids=["bare", "patch", "diff", "slash", "query", "fragment"])
@pytest.mark.parametrize("sha", ["abcdef1", "a" * 40], ids=["short", "full"])
def test_existing_commit_reference_suffixes_preserved(sha, suffix):
    adv = {"references": [{"url": f"https://github.com/owned/inert/commit/{sha}{suffix}"}]}
    assert _first_commit_ref(adv) == ("owned", "inert", sha)


def test_overlong_reference_does_not_hide_later_valid_reference():
    adv = {"references": [
        {"url": "https://github.com/owned/inert/commit/" + "a" * 41},
        {"url": "https://github.com/owned/second/commit/abcdef1"},
    ]}
    assert _first_commit_ref(adv) == ("owned", "second", "abcdef1")
