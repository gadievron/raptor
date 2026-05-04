"""Tests for packages.osv.verify — OSV oracle verification."""
from __future__ import annotations

from typing import Any

import pytest

from packages.osv.parser import parse_record
from packages.osv.types import OsvRecord
from packages.osv.verify import verify
from packages.osv.verdicts import Verdict

from packages.osv.client import OsvClient


class _FakeOsvClient:
    """Registry-based mock that returns parsed OsvRecords."""

    def __init__(self) -> None:
        self._registry: dict[str, dict[str, Any]] = {}

    def add(self, vuln_id: str, payload: dict[str, Any]) -> None:
        self._registry[vuln_id] = payload

    def get_vuln(self, vuln_id: str) -> OsvRecord | None:
        raw = self._registry.get(vuln_id)
        if raw is None:
            return None
        return parse_record(raw)

    # Satisfy type checks — unused in tests
    def query_batch(self, queries):
        return [[] for _ in queries]


def _payload(
    references: list[dict] | None = None,
    affected: list[dict] | None = None,
    aliases: list[str] | None = None,
) -> dict:
    d: dict[str, Any] = {"id": "CVE-2023-38545"}
    if references is not None:
        d["references"] = references
    if affected is not None:
        d["affected"] = affected
    if aliases is not None:
        d["aliases"] = aliases
    return d


@pytest.fixture
def fake() -> _FakeOsvClient:
    return _FakeOsvClient()


_CVE = "CVE-2023-38545"
_SHA = "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"


def test_match_exact_on_references(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "FIX", "url": f"https://github.com/curl/curl/commit/{_SHA}"},
    ]))
    v = verify(_CVE, "curl/curl", _SHA, fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.MATCH_EXACT
    assert v.source == "osv"


def test_match_range_on_affected_events(fake) -> None:
    fake.add(_CVE, _payload(affected=[
        {"ranges": [{"type": "GIT", "repo": "https://github.com/curl/curl",
                     "events": [{"fixed": _SHA}]}]},
    ]))
    v = verify(_CVE, "curl/curl", _SHA, fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.MATCH_RANGE


def test_mirror_different_slug(fake) -> None:
    fake.add(_CVE, _payload(affected=[
        {"ranges": [{"type": "GIT", "repo": "https://github.com/sourceware/glibc",
                     "events": [{"fixed": "d5dd6189d506968ed10339b4bd5412e95f1ad2bf"}]}]},
    ]))
    v = verify(_CVE, "bminor/glibc", "d5dd6189d506968ed10339b4bd5412e95f1ad2bf", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.MIRROR_DIFFERENT_SLUG
    assert v.verdict.is_pass


def test_likely_hallucination(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "FIX", "url": f"https://github.com/curl/curl/commit/{_SHA}"},
    ]))
    v = verify(_CVE, "somerando/curl", "deadbeefcafebabe1234567890abcdef12345678", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.LIKELY_HALLUCINATION


def test_dispute_same_slug_different_sha(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "FIX", "url": f"https://github.com/curl/curl/commit/{_SHA}"},
    ]))
    v = verify(_CVE, "curl/curl", "deadbeefcafebabe1234567890abcdef12345678", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.DISPUTE


def test_orphan_on_missing_record(fake) -> None:
    v = verify(_CVE, "curl/curl", "abc123", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "none"


def test_orphan_no_commit_data(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "ADVISORY", "url": "https://example.com/advisory"},
    ]))
    v = verify(_CVE, "curl/curl", "abc123", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "osv"


def test_dispute_when_bench_refused(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "FIX", "url": f"https://github.com/curl/curl/commit/{_SHA}"},
    ]))
    v = verify(_CVE, "", "", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.DISPUTE
    assert "bench refused" in v.notes


def test_kernel_shortlink_maps_to_torvalds_linux(fake) -> None:
    fake.add(_CVE, _payload(references=[
        {"type": "FIX", "url": "https://git.kernel.org/linus/c/e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c"},
    ]))
    v = verify(_CVE, "torvalds/linux", "e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c", fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.MATCH_EXACT


def test_alias_following_recovers_ghsa_ref(fake) -> None:
    fake.add(_CVE, _payload(
        references=[{"type": "ADVISORY", "url": "https://example.com/a"}],
        aliases=["GHSA-abcd-1234-wxyz"],
    ))
    fake.add("GHSA-abcd-1234-wxyz", {
        "id": "GHSA-abcd-1234-wxyz",
        "references": [{"url": f"https://github.com/curl/curl/commit/{_SHA}"}],
    })
    v = verify(_CVE, "curl/curl", _SHA, fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.MATCH_EXACT
    assert "GHSA-" in v.source


def test_alias_following_skips_non_ghsa(fake) -> None:
    fake.add(_CVE, _payload(
        references=[{"type": "ADVISORY", "url": "https://example.com/a"}],
        aliases=["DSA-5000-1", "USN-1234-1"],
    ))
    v = verify(_CVE, "curl/curl", _SHA, fake)  # type: ignore[arg-type]
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "osv"
