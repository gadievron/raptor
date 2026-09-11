"""Offline OSV DB: distro release-suffix handling, bucket coverage,
and GIT-range exclusion.

OSV suffixes release streams onto distro ecosystems ("Debian:11",
"Alpine:v3.18") — both the ingest and query sides must compare on the
base identifier or a distro bucket ingests and matches nothing. GIT
ranges carry commit SHAs, which are not version-comparable and must
never reach a version comparator.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from typing import Any

import pytest

from packages.sca.osv_offline import (
    _BUCKET_NAME,
    OsvOfflineDB,
    _record_matches_version,
)


class _ZipServingHttp:
    """Fake HttpClient returning canned zip bytes per URL substring."""

    def __init__(self, zips: dict[str, bytes]) -> None:
        self.zips = zips
        self.calls: list[str] = []

    def get_bytes(self, url: str, timeout: int = 30,
                  max_bytes: int = 0) -> bytes:
        self.calls.append(url)
        for key, blob in self.zips.items():
            if key in url:
                return blob
        raise FileNotFoundError(url)


def _make_zip(records: list[dict[str, Any]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for record in records:
            zf.writestr(f"{record['id']}.json", json.dumps(record))
    return buf.getvalue()


def _record(
    osv_id: str, ecosystem: str, name: str, *,
    introduced: str = "0", fixed: str | None = None,
    range_type: str = "ECOSYSTEM",
) -> dict[str, Any]:
    events: list[dict[str, str]] = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return {
        "id": osv_id,
        "summary": f"advisory {osv_id}",
        "details": "details",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": range_type, "events": events}],
        }],
        "references": [],
    }


# ---------------------------------------------------------------------------
# Release-suffixed ecosystems: ingest + match
# ---------------------------------------------------------------------------

def test_suffixed_debian_record_ingests_and_matches(tmp_path) -> None:
    """A 'Debian:11' affected block ingests into the Debian bucket and
    matches a vulnerable Debian dep — and stops matching at the fix."""
    rec = _record(
        "DSA-TEST-1", "Debian:11", "openssl",
        introduced="0", fixed="1.1.1n-0+deb11u1",
    )
    http = _ZipServingHttp({"Debian": _make_zip([rec])})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["Debian"])

    assert len(stats) == 1
    assert stats[0].advisories == 1

    vulnerable = db.query("Debian", "openssl", "1.1.1k-1+deb11u1")
    assert [a.osv_id for a in vulnerable] == ["DSA-TEST-1"]
    fixed = db.query("Debian", "openssl", "1.1.1n-0+deb11u1")
    assert fixed == []


def test_wrong_ecosystem_record_still_rejected(tmp_path) -> None:
    """An npm block inside the Debian dump must not be indexed under
    Debian (base-identifier comparison stays an actual filter)."""
    rec = _record("GHSA-WRONG-1", "npm", "lodash", fixed="4.17.21")
    http = _ZipServingHttp({"Debian": _make_zip([rec])})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["Debian"])

    assert len(stats) == 1
    assert stats[0].advisories == 0
    assert db.query("Debian", "lodash", "4.17.20") == []


def test_suffixed_query_ecosystem_reads_base_bucket(tmp_path) -> None:
    """Image-derived deps carry 'Alpine:v3.18'; the ingest downloads
    the base Alpine dump and the query narrows by release stream."""
    match_release = _record(
        "ALPINE-1", "Alpine:v3.18", "busybox", fixed="1.36.1-r1",
    )
    other_release = _record(
        "ALPINE-2", "Alpine:v3.17", "busybox", fixed="1.36.1-r1",
    )
    http = _ZipServingHttp(
        {"Alpine": _make_zip([match_release, other_release])})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["Alpine:v3.18"])

    assert any("/Alpine/all.zip" in url for url in http.calls)
    hits = db.query("Alpine:v3.18", "busybox", "1.36.0-r0")
    # Same release stream matches; a different release stream does not.
    assert [a.osv_id for a in hits] == ["ALPINE-1"]


def test_release_agnostic_block_matches_suffixed_query() -> None:
    """A bare-'Alpine' block applies to every release stream."""
    rec = _record("ALPINE-3", "Alpine", "zlib", fixed="1.2.12-r0")
    assert _record_matches_version(rec, "Alpine:v3.18", "1.2.11-r3")
    assert not _record_matches_version(rec, "Alpine:v3.18", "1.2.12-r0")


# ---------------------------------------------------------------------------
# Bucket map coverage
# ---------------------------------------------------------------------------

def test_online_ecosystems_have_bucket_mappings() -> None:
    """Every ecosystem the online client can query resolves to a
    deliberate bucket decision (a folder name or an explicit None)."""
    from packages.sca.ecosystems import (
        DISTRO_ECOSYSTEM_BASES,
        KNOWN_ECOSYSTEMS,
    )
    covered = (set(KNOWN_ECOSYSTEMS) | set(DISTRO_ECOSYSTEM_BASES)) - {
        # Online-only fallback ecosystem — never a dep's own ecosystem.
        "OSS-Fuzz",
    }
    missing = covered - set(_BUCKET_NAME)
    assert not missing, f"no offline bucket decision for: {sorted(missing)}"
    # Spot-check the folder spellings OSV actually publishes.
    assert _BUCKET_NAME["Ubuntu"] == "Ubuntu"
    assert _BUCKET_NAME["Red Hat"] == "Red Hat"
    assert _BUCKET_NAME["GitHub Actions"] == "GitHub Actions"
    assert _BUCKET_NAME["ConanCenter"] == "ConanCenter"
    assert _BUCKET_NAME["vcpkg"] is None


def test_ubuntu_and_gha_ingest_from_their_buckets(tmp_path) -> None:
    rec_ubuntu = _record(
        "USN-1", "Ubuntu:22.04", "curl", fixed="7.81.0-1ubuntu1.10")
    rec_gha = _record(
        "GHSA-GHA-1", "GitHub Actions", "actions/checkout", fixed="4.1.7")
    http = _ZipServingHttp({
        "Ubuntu": _make_zip([rec_ubuntu]),
        "GitHub%20Actions": _make_zip([rec_gha]),
    })
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["Ubuntu:22.04", "GitHub Actions"])

    assert sorted(s.ecosystem for s in stats) == ["GitHub Actions", "Ubuntu"]
    assert all(s.advisories == 1 for s in stats)
    assert db.query("Ubuntu:22.04", "curl", "7.81.0-1ubuntu1.4")
    assert db.query("GitHub Actions", "actions/checkout", "v4.1.0")
    assert not db.query("GitHub Actions", "actions/checkout", "v4.1.7")


def test_unmapped_ecosystem_warns_visibly(tmp_path, caplog) -> None:
    """An ecosystem the bucket map hasn't been taught about must warn,
    not silently return zero advisories."""
    db = OsvOfflineDB(
        tmp_path / "osv.sqlite", http=_ZipServingHttp({}))
    with caplog.at_level(logging.WARNING, logger="packages.sca.osv_offline"):
        stats = db.ensure_fresh(["SomeFutureRegistry"])
    assert stats == []
    assert any(
        "unsupported ecosystem" in r.message and "SomeFutureRegistry" in r.message
        for r in caplog.records
    )


def test_known_no_coverage_ecosystem_stays_silent(tmp_path, caplog) -> None:
    """vcpkg is a deliberate no-OSV-bucket decision — debug skip, no
    operator-facing warning, no download attempt."""
    http = _ZipServingHttp({})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    with caplog.at_level(logging.WARNING, logger="packages.sca.osv_offline"):
        stats = db.ensure_fresh(["vcpkg"])
    assert stats == []
    assert http.calls == []
    assert not [r for r in caplog.records if "vcpkg" in r.message]


# ---------------------------------------------------------------------------
# GIT ranges are not version-comparable
# ---------------------------------------------------------------------------

_SHA_A = "9f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"
_SHA_B = "ffee2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"


def test_git_only_range_never_matches() -> None:
    """Commit-SHA events through a version comparator yield arbitrary
    verdicts (Debian's comparator accepts hex strings without raising)
    — a record with only a GIT range must not match any version."""
    rec = _record(
        "GIT-ONLY-1", "Debian:11", "openssl",
        introduced=_SHA_A, fixed=_SHA_B, range_type="GIT",
    )
    assert not _record_matches_version(rec, "Debian", "1.1.1k-1")
    assert not _record_matches_version(rec, "Debian", "9a")


def test_git_range_skip_keeps_ecosystem_range_matching() -> None:
    """Skipping the GIT range must not lose the sibling ECOSYSTEM
    range: vulnerable versions still match, fixed ones still don't."""
    rec = {
        "id": "GIT-PLUS-ECO-1",
        "affected": [{
            "package": {"ecosystem": "Debian:11", "name": "openssl"},
            "ranges": [
                {"type": "GIT", "events": [
                    {"introduced": _SHA_A}, {"fixed": _SHA_B}]},
                {"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "1.1.1n-1"}]},
            ],
        }],
    }
    assert _record_matches_version(rec, "Debian", "1.1.1k-1")
    assert not _record_matches_version(rec, "Debian", "1.1.1n-1")


def test_explicit_versions_array_still_matches() -> None:
    """The versions[] equality surface is unaffected by the GIT skip."""
    rec = {
        "id": "GIT-PLUS-VERSIONS-1",
        "affected": [{
            "package": {"ecosystem": "Debian:11", "name": "openssl"},
            "ranges": [
                {"type": "GIT", "events": [{"introduced": _SHA_A}]},
            ],
            "versions": ["1.1.1k-1"],
        }],
    }
    assert _record_matches_version(rec, "Debian", "1.1.1k-1")
    assert not _record_matches_version(rec, "Debian", "1.1.1m-1")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
