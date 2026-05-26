"""Tests for the calibration corpus build pipeline."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any, Dict

import pytest

from packages.sca.calibration import build
from packages.sca.calibration.build import (
    _bytes_equal_excluding_timestamp,
    _build_exploitdb,
    _build_kev,
    _build_epss,
    _build_metasploit,
    _build_osv_evidence,
    _build_vulnrichment,
    _is_exploit_host_url,
    _msf_ref_to_cve,
    _write_if_changed,
    build_corpus,
)

_VULNRICHMENT_URL = (
    "https://codeload.github.com/cisagov/vulnrichment/tar.gz/HEAD"
)


def _make_targz(members: Dict[str, bytes]) -> bytes:
    """Build an in-memory ``.tar.gz`` from ``{member_name: bytes}``."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _ssvc_record(cve_id: str, exploitation: str, **extra: Any) -> bytes:
    """Serialise a minimal CVE-JSON-5 record carrying a CISA-ADP
    SSVC scorecard with the given ``Exploitation`` value."""
    record: Dict[str, Any] = {
        "cveMetadata": {"cveId": cve_id},
        "containers": {
            "adp": [{
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [{
                    "other": {"content": {"options": [
                        {"Exploitation": exploitation},
                        {"Automatable": "no"},
                        {"Technical Impact": "partial"},
                    ]}},
                }],
            }],
        },
    }
    record.update(extra)
    return json.dumps(record).encode("utf-8")


class _StubHttp:
    """Returns canned responses for known URLs; raises for unknown.

    ``responses`` keys are URLs. Each value can be:
      * a dict → returned by ``get_json``
      * bytes → returned by ``get_bytes`` (max_bytes ignored in stub)
    """

    def __init__(self, responses: Dict[str, Any]) -> None:
        self._responses = responses

    def get_json(self, url: str) -> Any:
        if url not in self._responses:
            raise AssertionError(f"unexpected URL: {url}")
        v = self._responses[url]
        if isinstance(v, (dict, list)):
            return v
        raise AssertionError(f"non-JSON response staged for {url}")

    def get_bytes(self, url: str, *, max_bytes: int = 0) -> bytes:
        if url not in self._responses:
            raise AssertionError(f"unexpected URL: {url}")
        v = self._responses[url]
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return v.encode("utf-8")
        raise AssertionError(f"non-bytes response staged for {url}")


# ---------------------------------------------------------------------------
# KEV builder
# ---------------------------------------------------------------------------


def test_build_kev_writes_signal_file(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-12345",
                    "dateAdded": "2024-08-01",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2024-99999",
                    "dateAdded": "2024-09-15",
                    "vendorProject": "Foo",
                    "product": "Bar",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        },
    })
    result = _build_kev(tmp_path, http)
    assert result.source == "kev"
    assert result.written is True
    assert result.record_count == 2
    data = json.loads((tmp_path / "kev_signals.json").read_text())
    assert "_source" in data
    assert data["_source"]["license"] == \
        "Public Domain (US Government work)"
    assert data["signals"]["CVE-2024-12345"]["kev"] is True
    assert data["signals"]["CVE-2024-12345"]["ransomware_use"] is True
    assert data["signals"]["CVE-2024-99999"]["ransomware_use"] is False


def test_build_kev_skips_entries_without_cveid(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {
            "vulnerabilities": [
                {"cveID": "CVE-2024-X"},
                {"vendorProject": "Foo"},  # no cveID
                {"cveID": ""},
            ],
        },
    })
    result = _build_kev(tmp_path, http)
    assert result.record_count == 1


def test_build_kev_idempotent_on_second_run(tmp_path: Path) -> None:
    """Running twice with the same upstream content produces no
    second write — the diff-friendly guard works."""
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-X", "dateAdded": "2024-01-01",
             "vendorProject": "A", "product": "B"},
        ],
    }
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": payload,
    })
    r1 = _build_kev(tmp_path, http)
    r2 = _build_kev(tmp_path, http)
    assert r1.written is True
    assert r2.written is False


# ---------------------------------------------------------------------------
# EPSS builder
# ---------------------------------------------------------------------------


def test_build_epss_writes_signal_file(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000&offset=0": {
            "data": [
                {"cve": "CVE-2024-1", "epss": "0.85",
                 "percentile": "0.99", "date": "2024-09-01"},
                {"cve": "CVE-2024-2", "epss": "0.10",
                 "percentile": "0.5", "date": "2024-09-01"},
            ],
        },
    })
    result = _build_epss(tmp_path, http)
    assert result.record_count == 2
    data = json.loads((tmp_path / "epss_signals.json").read_text())
    assert data["_source"]["license"].startswith("Free")
    assert data["signals"]["CVE-2024-1"]["epss"] == 0.85


def test_build_epss_skips_malformed_scores(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000&offset=0": {
            "data": [
                {"cve": "CVE-2024-OK", "epss": "0.5", "percentile": "0.9"},
                {"cve": "CVE-2024-BAD", "epss": "not-a-number"},
                {"cve": "CVE-2024-NO-EPSS"},
            ],
        },
    })
    result = _build_epss(tmp_path, http)
    assert result.record_count == 1


def test_build_epss_paginates_to_completeness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Small page size so two staged pages exercise the offset/total
    # loop. Only offset=0 and offset=2 are staged — if the loop made a
    # wasteful third fetch (offset=4) the stub would raise on the
    # unexpected URL, so a passing test also proves it stops at total.
    monkeypatch.setattr(build, "_EPSS_PAGE_SIZE", 2)
    base = "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=2"
    http = _StubHttp({
        f"{base}&offset=0": {"total": 4, "data": [
            {"cve": "CVE-2024-1", "epss": "0.9", "percentile": "0.99"},
            {"cve": "CVE-2024-2", "epss": "0.8", "percentile": "0.98"},
        ]},
        f"{base}&offset=2": {"total": 4, "data": [
            {"cve": "CVE-2024-3", "epss": "0.7", "percentile": "0.97"},
            {"cve": "CVE-2024-4", "epss": "0.6", "percentile": "0.96"},
        ]},
    })
    result = _build_epss(tmp_path, http)
    data = json.loads((tmp_path / "epss_signals.json").read_text())
    assert set(data["signals"]) == {
        "CVE-2024-1", "CVE-2024-2", "CVE-2024-3", "CVE-2024-4",
    }
    assert result.record_count == 4


# ---------------------------------------------------------------------------
# build_corpus orchestrator
# ---------------------------------------------------------------------------


def test_build_corpus_filters_by_sources(tmp_path: Path) -> None:
    """``sources=["kev"]`` runs KEV only; EPSS not attempted."""
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {"vulnerabilities": []},
    })
    results = build_corpus(out_dir=tmp_path, http=http, sources=["kev"])
    assert [r.source for r in results] == ["kev"]


def test_build_corpus_unknown_source_returns_error(tmp_path: Path) -> None:
    results = build_corpus(
        out_dir=tmp_path, http=_StubHttp({}),
        sources=["bogus"],
    )
    assert len(results) == 1
    assert results[0].source == "bogus"
    assert results[0].error is not None
    assert "unknown source" in results[0].error


def test_build_corpus_one_source_failing_doesnt_abort_others(
    tmp_path: Path,
) -> None:
    """A network failure on KEV doesn't prevent EPSS from running."""
    class _OneFailHttp:
        def get_json(self, url: str):
            if "cisa.gov" in url:
                raise RuntimeError("KEV simulated outage")
            if "first.org" in url:
                return {"data": [
                    {"cve": "CVE-2024-X", "epss": "0.5",
                     "percentile": "0.9", "date": "2024-09-01"},
                ]}
            raise AssertionError(f"unexpected URL: {url}")

    results = build_corpus(
        out_dir=tmp_path, http=_OneFailHttp(),
        sources=["kev", "epss"],
    )
    by_src = {r.source: r for r in results}
    assert by_src["kev"].error is not None
    assert by_src["epss"].written is True
    # EPSS file landed even though KEV blew up.
    assert (tmp_path / "epss_signals.json").exists()


def test_build_corpus_parallel_preserves_input_order(
    tmp_path: Path, monkeypatch,
) -> None:
    """With jobs>1 the sources run on a thread pool; results must still come
    back in INPUT order (not completion order), and all sources must run."""
    import packages.sca.calibration.build as build

    def _fake(source, out_dir, http):
        return build.BuildResult(
            source=source, written=True, error=None, record_count=1,
        )

    monkeypatch.setattr(build, "_build_one_source", _fake)
    sources = ["kev", "epss", "exploitdb", "metasploit", "github_poc"]
    results = build.build_corpus(
        out_dir=tmp_path, http=object(), sources=sources, jobs=4,
    )
    assert [r.source for r in results] == sources
    assert all(r.written for r in results)


# ---------------------------------------------------------------------------
# Diff-friendliness
# ---------------------------------------------------------------------------


def test_bytes_equal_excluding_timestamp_ignores_fetched_at() -> None:
    a = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    b = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-09-01T12:34:56Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    assert _bytes_equal_excluding_timestamp(a, b)


def test_bytes_equal_excluding_timestamp_detects_real_change() -> None:
    a = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    b = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}, "CVE-2024-2": {"kev": True}},
    }, sort_keys=True).encode()
    assert not _bytes_equal_excluding_timestamp(a, b)


# ---------------------------------------------------------------------------
# Exploit-DB builder
# ---------------------------------------------------------------------------


_EDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,"
    "date_added,date_updated,verified,codes,tags,aliases,screenshot_url,"
    "application_url,source_url\n"
    "12345,exploits/x.py,Foo,2024-01-01,jdoe,remote,windows,80,"
    "2024-01-02,2024-01-02,1,CVE-2024-1111;OSVDB-9999,,,,,\n"
    "12346,exploits/y.py,Bar,2024-02-01,jdoe,remote,linux,443,"
    "2024-02-02,2024-02-02,1,CVE-2024-1111;CVE-2024-2222,,,,,\n"
    "99999,exploits/z.py,No-CVE,2024-03-01,jdoe,local,linux,,"
    "2024-03-02,2024-03-02,0,OSVDB-12345,,,,,\n"
)


def test_build_exploitdb_extracts_cve_to_edb_id_mapping(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://gitlab.com/exploit-database/exploitdb/-/raw/HEAD/"
        "files_exploits.csv": _EDB_CSV,
    })
    result = _build_exploitdb(tmp_path, http)
    assert result.source == "exploitdb"
    assert result.written is True
    data = json.loads((tmp_path / "exploitdb_signals.json").read_text())
    # CVE-2024-1111 has TWO EDB entries (12345, 12346); deduped + sorted.
    assert data["signals"]["CVE-2024-1111"]["edb_ids"] == [12345, 12346]
    assert data["signals"]["CVE-2024-1111"]["has_exploitdb_entry"] is True
    # CVE-2024-2222 has one entry (12346).
    assert data["signals"]["CVE-2024-2222"]["edb_ids"] == [12346]
    # Non-CVE codes (OSVDB-) don't produce signals.
    assert "OSVDB-9999" not in data["signals"]
    # Source block carries the strict-licensing note.
    assert "research/personal-use" in data["_source"]["license"]


def test_build_exploitdb_no_exploit_content_emitted(tmp_path: Path) -> None:
    """The output must NOT contain any of the forbidden field
    names that would indicate exploit content."""
    http = _StubHttp({
        "https://gitlab.com/exploit-database/exploitdb/-/raw/HEAD/"
        "files_exploits.csv": _EDB_CSV,
    })
    _build_exploitdb(tmp_path, http)
    text = (tmp_path / "exploitdb_signals.json").read_text().lower()
    for forbidden in ("body", "payload", "shellcode", "exploit_code",
                       "poc_code"):
        assert forbidden not in text, (
            f"forbidden field {forbidden!r} appears in exploitdb_signals"
        )


def test_build_exploitdb_idempotent(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://gitlab.com/exploit-database/exploitdb/-/raw/HEAD/"
        "files_exploits.csv": _EDB_CSV,
    })
    r1 = _build_exploitdb(tmp_path, http)
    r2 = _build_exploitdb(tmp_path, http)
    assert r1.written is True
    assert r2.written is False


# ---------------------------------------------------------------------------
# Metasploit builder
# ---------------------------------------------------------------------------


_MSF_INDEX = {
    "exploits/multi/http/log4shell": {
        "name": "Log4Shell",
        "references": [
            {"type": "CVE", "ref": "2021-44228"},
            {"type": "URL", "ref": "https://example.com"},
        ],
    },
    "exploits/windows/smb/ms17_010": {
        "name": "EternalBlue",
        "references": [
            "CVE-2017-0144",
            "CVE-2017-0143",
            "MSB-MS17-010",
        ],
    },
    "auxiliary/scanner/foo": {
        # Module with no CVE references — produces no signal.
        "name": "Foo scanner",
        "references": ["URL: https://example.com"],
    },
}


def test_build_metasploit_extracts_cve_to_module_mapping(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
        "HEAD/db/modules_metadata_base.json": _MSF_INDEX,
    })
    result = _build_metasploit(tmp_path, http)
    assert result.source == "metasploit"
    assert result.written is True
    data = json.loads(
        (tmp_path / "metasploit_signals.json").read_text(),
    )
    sigs = data["signals"]
    assert "CVE-2021-44228" in sigs
    assert sigs["CVE-2021-44228"]["module_paths"] == [
        "exploits/multi/http/log4shell",
    ]
    assert sigs["CVE-2017-0144"]["module_paths"] == [
        "exploits/windows/smb/ms17_010",
    ]
    # Modules with no CVE refs don't emit a signal.
    assert all(
        cve.startswith("CVE-") for cve in sigs.keys()
    )


def test_build_metasploit_no_module_code_emitted(tmp_path: Path) -> None:
    """Output is paths + booleans only — no module code / payload."""
    http = _StubHttp({
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
        "HEAD/db/modules_metadata_base.json": _MSF_INDEX,
    })
    _build_metasploit(tmp_path, http)
    text = (tmp_path / "metasploit_signals.json").read_text().lower()
    for forbidden in ("body", "payload", "shellcode", "exploit_code"):
        assert forbidden not in text


def test_msf_ref_to_cve_handles_string_form():
    assert _msf_ref_to_cve("CVE-2021-44228") == "CVE-2021-44228"


def test_msf_ref_to_cve_handles_object_form():
    assert _msf_ref_to_cve(
        {"type": "CVE", "ref": "2021-44228"},
    ) == "CVE-2021-44228"


def test_msf_ref_to_cve_normalises_unprefixed_object_ref():
    """Some MSF entries omit the ``CVE-`` prefix in the object
    form. Normalise so downstream comparisons work."""
    assert _msf_ref_to_cve(
        {"type": "CVE", "ref": "2017-0144"},
    ) == "CVE-2017-0144"


def test_msf_ref_to_cve_rejects_non_cve():
    assert _msf_ref_to_cve("OSVDB-12345") is None
    assert _msf_ref_to_cve(
        {"type": "URL", "ref": "https://example.com"},
    ) is None
    assert _msf_ref_to_cve(None) is None


def test_write_if_changed_skips_unchanged(tmp_path: Path) -> None:
    payload = {
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }
    r1 = _write_if_changed(
        tmp_path / "x.json", payload, source="x", record_count=1,
    )
    assert r1.written is True
    # Re-write with a different fetched_at — should be a no-op.
    payload2 = json.loads(json.dumps(payload))  # deep copy
    payload2["_source"]["fetched_at"] = "2024-12-31T23:59:59Z"
    r2 = _write_if_changed(
        tmp_path / "x.json", payload2, source="x", record_count=1,
    )
    assert r2.written is False


# ---------------------------------------------------------------------------
# OSV EVIDENCE-host signal builder
# ---------------------------------------------------------------------------


def test_is_exploit_host_url_allowlist():
    # Exploit-publication hosts → True
    for url in [
        "https://exploit-db.com/exploits/41614",
        "https://www.exploit-db.com/exploits/41614",
        "http://packetstormsecurity.com/files/165270/Apache.html",
        "https://0day.today/exploit/12345",
        "https://huntr.dev/bounties/abc-123",
        "https://gist.github.com/foo/abc123",
        "https://seclists.org/fulldisclosure/2022/Dec/2",
    ]:
        assert _is_exploit_host_url(url), url
    # Advisory / blog / vendor hosts → False (knowledge ≠ exploit)
    for url in [
        "https://snyk.io/vuln/SNYK-PHP-FOO",
        "https://hackerone.com/reports/12345",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://github.com/torvalds/linux",
        "https://lists.apache.org/foo",
        "https://blog.example.com/cve-2024-X",
        "",
        None,
    ]:
        assert not _is_exploit_host_url(url), url


def test_build_osv_evidence_extracts_only_exploit_host_urls(
    tmp_path: Path,
) -> None:
    """Builder should walk corpus CVEs, query OSV, and accept ONLY
    refs whose host is in the exploit-publication allowlist."""
    samples_dir = tmp_path / "project_samples" / "PyPI"
    samples_dir.mkdir(parents=True)
    (samples_dir / "x.json").write_text(json.dumps({
        "_source": {"name": "x"},
        "findings": [
            {"advisory": {"aliases": ["CVE-2024-1"]}},
            {"advisory": {"cve_id": "CVE-2024-2"}},
            {"advisory": {"cves": ["CVE-2024-3"]}},
        ],
    }), encoding="utf-8")

    osv_responses = {
        "https://api.osv.dev/v1/vulns/CVE-2024-1": {
            "id": "GHSA-x", "references": [
                {"type": "EVIDENCE",
                 "url": "https://exploit-db.com/exploits/99"},
                {"type": "EVIDENCE",
                 "url": "https://snyk.io/vuln/SNYK-X"},
                {"type": "ADVISORY", "url": "https://nvd/x"},
            ],
        },
        "https://api.osv.dev/v1/vulns/CVE-2024-2": {
            # Has EVIDENCE refs but NONE on the exploit-host allowlist.
            "id": "GHSA-y", "references": [
                {"type": "EVIDENCE",
                 "url": "https://hackerone.com/reports/123"},
                {"type": "EVIDENCE",
                 "url": "https://twitter.com/foo/status/x"},
            ],
        },
        "https://api.osv.dev/v1/vulns/CVE-2024-3": {
            # No EVIDENCE refs at all — only WEB.
            "id": "GHSA-z", "references": [
                {"type": "WEB", "url": "https://example.com"},
            ],
        },
    }
    http = _StubHttp(osv_responses)
    result = _build_osv_evidence(tmp_path, http)
    assert result.source == "osv_evidence"
    data = json.loads(
        (tmp_path / "osv_evidence_signals.json").read_text(),
    )
    sigs = data["signals"]
    # Only CVE-2024-1 makes the cut: it has an exploit-host URL.
    assert list(sigs.keys()) == ["CVE-2024-1"]
    assert sigs["CVE-2024-1"]["evidence_urls"] == [
        "https://exploit-db.com/exploits/99",
    ]
    # Diagnostics in _source: verify all 3 CVEs were queried, 2 had
    # ANY evidence, only 1 had an exploit-host URL.
    src = data["_source"]
    assert src["cves_in_corpus"] == 3
    assert src["cves_queried"] == 3
    assert src["cves_with_any_evidence_ref"] == 2
    assert src["cves_with_exploit_host_url"] == 1


def test_build_osv_evidence_handles_missing_corpus_dir(
    tmp_path: Path,
) -> None:
    """No project_samples/ → empty signal file, no errors."""
    http = _StubHttp({})  # no calls expected
    result = _build_osv_evidence(tmp_path, http)
    assert result.source == "osv_evidence"
    assert result.written is True
    data = json.loads(
        (tmp_path / "osv_evidence_signals.json").read_text(),
    )
    assert data["signals"] == {}
    assert data["_source"]["cves_in_corpus"] == 0


def test_build_osv_evidence_swallows_per_cve_404s(
    tmp_path: Path,
) -> None:
    """Per-CVE OSV failures (404 / timeout) shouldn't abort the
    build — those CVEs simply don't get an EVIDENCE signal."""
    samples_dir = tmp_path / "project_samples" / "Cargo"
    samples_dir.mkdir(parents=True)
    (samples_dir / "x.json").write_text(json.dumps({
        "_source": {"name": "x"},
        "findings": [
            {"advisory": {"aliases": ["CVE-2024-A", "CVE-2024-B"]}},
        ],
    }), encoding="utf-8")

    class _FailingHttp:
        def get_json(self, url):
            if url.endswith("CVE-2024-A"):
                raise RuntimeError("404")
            return {
                "id": "GHSA-b", "references": [
                    {"type": "EVIDENCE",
                     "url": "https://exploit-db.com/exploits/x"},
                ],
            }
    result = _build_osv_evidence(tmp_path, _FailingHttp())
    data = json.loads(
        (tmp_path / "osv_evidence_signals.json").read_text(),
    )
    # CVE-A swallowed; CVE-B got its signal.
    assert "CVE-2024-A" not in data["signals"]
    assert "CVE-2024-B" in data["signals"]
    assert result.record_count == 1


# ---------------------------------------------------------------------------
# Vulnrichment builder
# ---------------------------------------------------------------------------


def test_build_vulnrichment_extracts_poc_and_active_skips_none(
    tmp_path: Path,
) -> None:
    tarball = _make_targz({
        "vulnrichment/2024/0xxx/CVE-2024-0001.json": _ssvc_record(
            "CVE-2024-0001", "poc",
        ),
        "vulnrichment/2024/0xxx/CVE-2024-0002.json": _ssvc_record(
            "CVE-2024-0002", "active",
        ),
        # ``none`` carries no exploit signal — must be dropped.
        "vulnrichment/2024/0xxx/CVE-2024-0003.json": _ssvc_record(
            "CVE-2024-0003", "none",
        ),
        # Non-CVE / non-JSON members must be ignored by the filters.
        "vulnrichment/README.md": b"not a record",
    })
    result = _build_vulnrichment(tmp_path, _StubHttp({
        _VULNRICHMENT_URL: tarball,
    }))
    data = json.loads(
        (tmp_path / "vulnrichment_signals.json").read_text(),
    )
    assert set(data["signals"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert data["signals"]["CVE-2024-0001"]["ssvc_exploitation"] == "poc"
    assert result.record_count == 2


def test_build_vulnrichment_trips_on_decompression_bomb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A highly compressible member in a member we *filter out* (not a
    # CVE .json) — proving the stream-level guard catches a bomb hidden
    # anywhere, not just in extracted records. Lower the threshold so we
    # trip the mechanism without materialising a 64 MB fixture.
    monkeypatch.setattr(build, "_DECOMP_FLOOR", 0)
    monkeypatch.setattr(build, "_DECOMP_RATIO", 1)
    tarball = _make_targz({"junk.bin": b"\x00" * (256 * 1024)})
    # Sanity: the fixture really is high-ratio (decompresses to >> its
    # compressed size), so cap = len(raw) * 1 is far below it.
    assert len(tarball) * 1 < 256 * 1024
    with pytest.raises(RuntimeError, match="decompression bomb"):
        _build_vulnrichment(tmp_path, _StubHttp({
            _VULNRICHMENT_URL: tarball,
        }))


def test_build_vulnrichment_skips_oversized_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Per-member read cap: a CVE-named .json whose body exceeds the cap
    # is skipped (not parsed), while a normal-sized record survives.
    monkeypatch.setattr(build, "_PER_RECORD_CAP", 2000)
    tarball = _make_targz({
        "vulnrichment/2024/0xxx/CVE-2024-0001.json": _ssvc_record(
            "CVE-2024-0001", "poc",
        ),
        # Oversized member sits BETWEEN two valid ones: proves the
        # stream recovers from the bounded partial read and still
        # parses the member that follows it.
        "vulnrichment/2024/0xxx/CVE-2024-9999.json": _ssvc_record(
            "CVE-2024-9999", "poc", _pad="x" * 8000,
        ),
        "vulnrichment/2024/0xxx/CVE-2024-0002.json": _ssvc_record(
            "CVE-2024-0002", "active",
        ),
    })
    result = _build_vulnrichment(tmp_path, _StubHttp({
        _VULNRICHMENT_URL: tarball,
    }))
    data = json.loads(
        (tmp_path / "vulnrichment_signals.json").read_text(),
    )
    assert set(data["signals"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert result.record_count == 2
