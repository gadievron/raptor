"""Release/source regression cases from the public devcontainer dogfood run."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from core.json import JsonCache
from core.oci.distro import release_ecosystem
from packages.sca.findings import build_vuln_findings, _vuln_finding_to_row
from packages.sca.osv import OsvClient
from packages.sca.osv_offline import OsvOfflineDB
from packages.sca.tests.test_osv import FakeHttp, _dep


def record(name, fixes, identifier="DEBIAN-TEST"):
    return {"id": identifier, "modified": "2026-11-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": eco, "name": name},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix}]}]}
        for eco, fix in fixes.items()]}


def client(tmp_path, data):
    http = FakeHttp(batch_results=[[data["id"]]], vuln_records={data["id"]: data})
    return OsvClient(http, JsonCache(root=tmp_path / "cache")), http


@pytest.mark.parametrize("name, version, fixes", [
    ("git", "1:2.39.5-0+deb12u3", {"Debian:12": "1:2.39.5-0+deb12u3", "Debian:13": "1:2.47.3-0+deb13u1"}),
    ("sudo", "1.9.13p3-1+deb12u4", {"Debian:13": "1.9.16p2-3"}),
])
def test_real_fixed_or_unaffected_bookworm_packages_are_not_flagged(tmp_path, name, version, fixes):
    data = record(name, fixes)
    osv, http = client(tmp_path, data)
    dep = _dep(name, version, ecosystem="Debian:12")
    # Deliberately return a stale/overbroad server match. Local validation must
    # reject it rather than trusting an ID returned by a different release.
    result = osv.query_batch([dep])
    assert result[0].advisories == []
    assert http.posts[0][1]["queries"][0]["package"]["ecosystem"] == "Debian:12"
    assert not osv.degraded


def test_vulnerable_bookworm_version_uses_only_bookworm_fix(tmp_path):
    data = record("git", {"Debian:12": "1:2.39.5-0+deb12u3", "Debian:13": "1:2.47.3-0+deb13u1"})
    osv, _ = client(tmp_path, data)
    dep = _dep("git", "1:2.39.5-0+deb12u2", ecosystem="Debian:12")
    results = osv.query_batch([dep])
    assert results[0].advisories[0].fixed_versions == ["1:2.39.5-0+deb12u3"]
    findings = build_vuln_findings([dep], results)
    assert findings[0].fixed_version == "1:2.39.5-0+deb12u3"


def test_source_query_preserves_binary_identity_and_compares_source_version(tmp_path):
    data = record("source", {"Debian:12": "1.2", "Debian:13": "9.0"})
    data["affected"][0]["ranges"][0]["events"] += [{"introduced": "1.2.5"}, {"fixed": "1.4"}]
    osv, http = client(tmp_path, data)
    dep = replace(_dep("binary", "9.9", ecosystem="Debian:12"),
                  purl="pkg:deb/debian/binary@9.9?arch=amd64&distro=debian-12.15&upstream=source%401.3")
    original = replace(dep)
    results = osv.query_batch([dep])
    assert dep == original
    query = http.posts[0][1]["queries"][0]
    assert query == {"package": {"ecosystem": "Debian:12", "name": "source"}, "version": "1.3"}
    assert results[0].dep_key == dep.key()
    finding = build_vuln_findings([dep], results)[0]
    assert finding.dependency == original
    assert finding.fixed_version == "1.4"
    row = _vuln_finding_to_row(finding)
    assert row["sca"]["purl"] == original.purl
    assert row["sca"]["advisory_match_scope"] == "source_package"
    assert row["title"].endswith("source package advisory")
    assert row["sca"]["advisory_package"] == {"ecosystem": "Debian:12", "name": "source", "version": "1.3"}
    from packages.sca.report import _render_one_vuln
    from packages.sca.report_html import render_html_report
    from packages.sca.render import _render_markdown
    assert "source fix: 1.4" in _render_one_vuln(finding)
    html = render_html_report(target=tmp_path, deps_analysed=1, vuln_findings=[finding], hygiene_findings=[])
    assert "source fix:</em>" in html
    assert "source source 1.4" in _render_markdown([row], target=tmp_path)


@pytest.mark.parametrize("ecosystem, purl", [
    ("Debian", "pkg:deb/debian/git@1"),
    ("Debian", "pkg:deb/debian/git@1#ignored?distro=debian-12"),
    ("Ubuntu", "pkg:deb/ubuntu/git@1"),
    ("Debian:12", "pkg:deb/debian/nodejs@24.21.0-1nodesource1?distro=debian-12"),
    ("Debian:12", "pkg:deb/debian/git@1?distro=debian-13"),
    ("Debian:12", "pkg:deb/debian/git@1?distro=debian-12&upstream=source%40"),
    ("Debian:12", "pkg:deb/debian/git@1?distro=debian-12&upstream=source%401%3A"),
    ("Debian:12", "pkg:deb/debian/git@1?distro=debian-12&upstream=source%401-"),
    ("Debian:12", "pkg:apk/debian/git@1?distro=debian-12"),
    ("Debian:12", "pkg:deb/ubuntu/git@1?distro=debian-12"),
    ("Ubuntu:22.04:LTS", "pkg:deb/ubuntu/nodejs@24.21.0-1nodesource1?distro=ubuntu-22.04"),
])
def test_unknown_or_conflicting_context_is_degraded_not_clean(tmp_path, ecosystem, purl):
    dep = replace(_dep("git", "24.21.0-1nodesource1" if "nodesource" in purl else "1", ecosystem=ecosystem), purl=purl)
    http = FakeHttp()
    osv = OsvClient(http, JsonCache(root=tmp_path / "cache"))
    assert osv.query_batch([dep])[0].advisories == []
    assert osv.lookup_failed(dep.key())
    assert osv.degraded
    assert dep.key() in osv.coverage_gaps
    assert not http.posts


def test_unavailable_matching_record_is_not_a_clean_result(tmp_path):
    data = record("git", {"Debian:12": "2"})
    osv, http = client(tmp_path, data)
    http.vuln_records.clear()
    dep = _dep("git", "1", ecosystem="Debian:12")
    assert osv.query_batch([dep])[0].advisories == []
    assert osv.degraded
    assert osv.lookup_failed(dep.key())


def test_offline_database_scopes_matches_and_fixes_to_release(tmp_path):
    database = OsvOfflineDB(tmp_path / "osv.sqlite")
    data = record("git", {"Debian:12": "2", "Debian:13": "3"})
    database._init_db()
    database._conn.execute("INSERT INTO advisories (ecosystem, package, osv_id, json) VALUES (?, ?, ?, ?)",
                           ("Debian", "git", data["id"], json.dumps(data)))
    database._conn.commit()
    assert database.query("Debian:12", "git", "2") == []
    assert database.query("Debian:12", "git", "1")[0].fixed_versions == ["2"]
    with pytest.raises(ValueError, match="release is unknown"):
        database.query("Debian", "git", "1")
    database.close()


def test_ubuntu_standard_and_pro_streams_are_distinct(tmp_path):
    data = record("openssl", {"Ubuntu:22.04:LTS": "2", "Ubuntu:Pro:22.04:LTS": "3"})
    osv, _ = client(tmp_path, data)
    standard = _dep("openssl", "2", ecosystem="Ubuntu:22.04:LTS")
    assert osv.query_batch([standard])[0].advisories == []
    pro = replace(standard, ecosystem="Ubuntu:Pro:22.04:LTS")
    assert osv.query_batch([pro])[0].advisories[0].fixed_versions == ["3"]


def test_unreadable_matching_range_is_explicitly_unknown(tmp_path):
    data = record("git", {"Debian:12": "2"})
    data["affected"][0]["ranges"] = [{"type": "GIT", "repo": "https://example.org/git", "events": [{"introduced": "abc"}, {"fixed": "def"}]}]
    osv, _ = client(tmp_path, data)
    dep = _dep("git", "1", ecosystem="Debian:12")
    assert osv.query_batch([dep])[0].advisories == []
    assert osv.lookup_failed(dep.key())
    assert "cannot evaluate" in osv.coverage_gaps[dep.key()]


@pytest.mark.parametrize("affected", [[], [{"ranges": []}],
    [{"package": {"name": "git", "ecosystem": "Ubuntu"}, "ranges": []}]])
def test_missing_advisory_context_is_not_a_negative_result(tmp_path, affected):
    data = record("git", {"Ubuntu:22.04:LTS": "2"})
    data["affected"] = affected
    osv, _ = client(tmp_path, data)
    dep = _dep("git", "1", ecosystem="Ubuntu:22.04:LTS")
    assert osv.query_batch([dep])[0].advisories == []
    assert osv.lookup_failed(dep.key())
    assert dep.key() in osv.coverage_gaps


def test_alpine_upstream_qualifier_uses_source_package(tmp_path):
    data = record("musl", {"Alpine:v3.20": "1.2.5-r1"})
    osv, http = client(tmp_path, data)
    dep = replace(_dep("musl-utils", "1.2.5-r0", ecosystem="Alpine:v3.20"),
                  purl="pkg:apk/alpine/musl-utils@1.2.5-r0?distro=alpine-3.20.1&upstream=musl")
    assert osv.query_batch([dep])[0].advisories
    assert http.posts[0][1]["queries"][0]["package"]["name"] == "musl"


def test_cli_records_unknown_release_as_incomplete_coverage(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    from packages.sca.tests.test_sbom_spdx_import import document, package
    data = document.__wrapped__()
    data["packages"] = [package("SPDXRef-image", "git", "pkg:deb/debian/git@1")]
    data["relationships"] = []
    path = tmp_path / "input.json"
    path.write_text(json.dumps(data))
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, "-m", "packages.sca.cli", str(tmp_path),
                             "--sbom", str(path), "--out", str(output), "--offline", "--no-llm",
                             "--no-supply-chain", "--no-reachability"],
                            cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=60)
    assert result.returncode in {0, 1}, result.stderr
    rows = json.loads((output / "findings.json").read_text())
    assert any(r["vuln_type"] == "sca:scan_health:osv_lookup_degraded" for r in rows)
    assert "distro_advisory_context" in (output / "analysis-gaps.jsonl").read_text()


def test_two_binaries_share_a_source_lookup_without_losing_occurrences(tmp_path):
    data = record("openssl", {"Debian:12": "2"})
    osv, http = client(tmp_path, data)
    binaries = [replace(_dep(name, "1", ecosystem="Debian:12"),
                        purl=f"pkg:deb/debian/{name}@1?distro=debian-12&upstream=openssl")
                for name in ("libssl3", "libssl-dev")]
    result = osv.query_batch(binaries)
    assert len(http.posts[0][1]["queries"]) == 1
    assert [r.dep_key for r in result] == [d.key() for d in binaries]
    assert all(r.advisories[0].fixed_versions == ["2"] for r in result)


@pytest.mark.parametrize("family, release, expected", [
    ("Debian", "12.15", "Debian:12"), ("Debian", "bookworm", "Debian:12"),
    ("Debian", "testing", None), ("Ubuntu", "22.04", "Ubuntu:22.04:LTS"),
    ("Ubuntu", "jammy", "Ubuntu:22.04:LTS"), ("Ubuntu", "25.10", "Ubuntu:25.10"),
    ("Ubuntu", "99.04", "Ubuntu:99.04"), ("Ubuntu", "28.04", None),
])
def test_release_identity_is_explicit(family, release, expected):
    assert release_ecosystem(family, release) == expected
