"""Tests for the offline OSV advisory DB.

Builds tiny synthetic OSV-bucket zips, ingests them, and asserts the
resulting sqlite-backed lookups return the right advisories with
correct version-range filtering.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from packages.sca.osv_offline import OsvOfflineDB


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _ZipServingHttp:
    """Fake HttpClient that returns canned zip bytes per URL."""

    def __init__(self, zips: Dict[str, bytes]) -> None:
        self.zips = zips
        self.calls: List[str] = []

    def get_bytes(self, url: str, timeout: int = 30,
                   max_bytes: int = 0) -> bytes:
        self.calls.append(url)
        for key, blob in self.zips.items():
            if key in url:
                return blob
        raise FileNotFoundError(url)

    def get_json(self, url, timeout=30):  # pragma: no cover
        raise NotImplementedError

    def post_json(self, url, body, timeout=30):  # pragma: no cover
        raise NotImplementedError


def _make_zip(records: List[Dict[str, Any]]) -> bytes:
    """Encode a list of OSV records into a zip blob (one JSON file each)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for record in records:
            zf.writestr(f"{record['id']}.json", json.dumps(record))
    return buf.getvalue()


def _osv(
    osv_id: str, ecosystem: str, name: str, *,
    introduced: str = "0", fixed: str = None,
    severity: str = "MEDIUM",
) -> Dict[str, Any]:
    """Make a minimal OSV record."""
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return {
        "id": osv_id,
        "summary": f"Test advisory {osv_id}",
        "details": "details",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": events}],
        }],
        "references": [],
    }


# ---------------------------------------------------------------------------
# Ingest + lookup
# ---------------------------------------------------------------------------

def test_ingest_and_query_pypi(tmp_path: Path) -> None:
    """Pure ingest + lookup round-trip."""
    blob = _make_zip([
        _osv("PYSEC-1", "PyPI", "django",
              introduced="0", fixed="4.2.7"),
        _osv("PYSEC-2", "PyPI", "django",
              introduced="3.0", fixed="3.2.20"),
    ])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["PyPI"])
    assert len(stats) == 1
    assert stats[0].ecosystem == "PyPI"
    assert stats[0].advisories == 2

    # Lookup at a vulnerable version → both apply.
    advs = db.query("PyPI", "django", "4.2.0")
    assert {a.osv_id for a in advs} == {"PYSEC-1"}
    advs = db.query("PyPI", "django", "3.1.0")
    assert {a.osv_id for a in advs} == {"PYSEC-1", "PYSEC-2"}
    # Lookup at fixed version → none apply.
    advs = db.query("PyPI", "django", "4.2.7")
    assert advs == []


def test_pypi_name_normalisation(tmp_path: Path) -> None:
    """``Python-DateUtil`` / ``python_dateutil`` / ``python.dateutil``
    should all find the same advisory (PEP 503 collapse:
    ``[-_.]+`` → ``-`` then lowercase)."""
    blob = _make_zip([
        _osv("X", "PyPI", "python-dateutil",
              introduced="0", fixed="3.0"),
    ])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["PyPI"])
    assert db.query("PyPI", "Python-DateUtil", "2.8.0")
    assert db.query("PyPI", "python_dateutil", "2.8.0")
    assert db.query("PyPI", "python.dateutil", "2.8.0")


def test_no_data_for_unknown_pkg(tmp_path: Path) -> None:
    blob = _make_zip([
        _osv("X", "PyPI", "django", introduced="0", fixed="4.2.7"),
    ])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["PyPI"])
    assert db.query("PyPI", "no-such-pkg", "1.0") == []


def test_freshness_skips_re_download(tmp_path: Path) -> None:
    blob = _make_zip([_osv("X", "PyPI", "django", fixed="4.2.7")])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http, ttl_seconds=3600)
    db.ensure_fresh(["PyPI"])
    db.ensure_fresh(["PyPI"])      # second call should hit freshness check
    assert len(http.calls) == 1


def test_force_redownloads(tmp_path: Path) -> None:
    blob = _make_zip([_osv("X", "PyPI", "django", fixed="4.2.7")])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["PyPI"])
    db.ensure_fresh(["PyPI"], force=True)
    assert len(http.calls) == 2


def test_unknown_ecosystem_silently_skipped(tmp_path: Path) -> None:
    """Homebrew / etc. have no OSV bucket — silently skip."""
    http = _ZipServingHttp({})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["Homebrew"])
    assert stats == []
    assert http.calls == []


def test_cargo_bucket_name_remap(tmp_path: Path) -> None:
    """Our ``Cargo`` ecosystem maps to OSV's ``crates.io`` bucket."""
    blob = _make_zip([
        # The OSV record's ecosystem field uses the bucket-spelling.
        _osv("RUSTSEC-1", "crates.io", "tokio",
              introduced="0", fixed="1.30"),
    ])
    http = _ZipServingHttp({"crates.io/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["Cargo"])
    advs = db.query("Cargo", "tokio", "1.20")
    assert {a.osv_id for a in advs} == {"RUSTSEC-1"}


def test_ingest_skips_zip_slip_paths(tmp_path: Path) -> None:
    """Zip entries with ``..`` segments are dropped (zip-slip protection).

    Both fixture entries end in ``.json`` so they pass the
    extension filter and reach the path-safety check.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.json",
                     json.dumps(_osv("EVIL", "PyPI", "x", fixed="1.0")))
        zf.writestr("nested/../../escape2.json",
                     json.dumps(_osv("EVIL2", "PyPI", "x", fixed="1.0")))
        zf.writestr("ok.json",
                     json.dumps(_osv("OK", "PyPI", "x", fixed="1.0")))
    blob = buf.getvalue()
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    stats = db.ensure_fresh(["PyPI"])
    assert stats[0].advisories == 1
    assert stats[0].skipped == 2


def test_query_without_version_returns_all(tmp_path: Path) -> None:
    """``version=None`` returns every advisory for the name (caller can't
    filter by range without a version)."""
    blob = _make_zip([
        _osv("A", "PyPI", "django", fixed="4.2.7"),
        _osv("B", "PyPI", "django", fixed="3.2.20"),
    ])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["PyPI"])
    advs = db.query("PyPI", "django", None)
    assert {a.osv_id for a in advs} == {"A", "B"}


def test_close_releases_connection(tmp_path: Path) -> None:
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=_ZipServingHttp({}))
    db.ensure_fresh(["Homebrew"])
    db.close()
    # Subsequent operations must still work (lazy reconnect).
    assert db.query("PyPI", "x", "1.0") == []


# ---------------------------------------------------------------------------
# Integration with OsvClient
# ---------------------------------------------------------------------------

def test_osv_client_uses_offline_db_when_set(tmp_path: Path) -> None:
    """``OsvClient(offline=True, offline_db=...)`` returns advisories
    from the offline DB without hitting the network."""
    from core.json import JsonCache
    from packages.sca.models import (
        Confidence, Dependency, PinStyle,
    )
    from packages.sca.osv import OsvClient

    blob = _make_zip([
        _osv("PYSEC-1", "PyPI", "django",
              introduced="0", fixed="4.2.7"),
    ])
    http = _ZipServingHttp({"PyPI/all.zip": blob})
    db = OsvOfflineDB(tmp_path / "osv.sqlite", http=http)
    db.ensure_fresh(["PyPI"])

    cache = JsonCache(root=tmp_path / "cache")
    client = OsvClient(http, cache, offline=True, offline_db=db)

    dep = Dependency(
        ecosystem="PyPI", name="django", version="4.2.0",
        declared_in=Path("/x/req.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:pypi/django@4.2.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    results = client.query_batch([dep])
    assert len(results) == 1
    assert {a.osv_id for a in results[0].advisories} == {"PYSEC-1"}
