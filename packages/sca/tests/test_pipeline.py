"""Tests for ``packages.sca.pipeline``.

The end-to-end smoke uses an in-process fake HttpClient so the test
runs offline and is deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from core.json import JsonCache
from core.http import HttpError
from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE
from packages.sca.pipeline import (
    RunOptions,
    run_sca,
    select_canonical_for_osv,
)


# ---------------------------------------------------------------------------
# select_canonical_for_osv
# ---------------------------------------------------------------------------

def _dep(name: str, version: str | None, *, is_lockfile: bool = False,
         path: str = "/x") -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=version,
        declared_in=Path(path),
        scope="main",
        is_lockfile=is_lockfile,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl="",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_canonical_prefers_lockfile_over_manifest() -> None:
    deps = [
        _dep("lodash", "4.17.0"),                        # manifest
        _dep("lodash", "4.17.21", is_lockfile=True),     # lockfile
    ]
    canonical = select_canonical_for_osv(deps)
    assert len(canonical) == 1
    assert canonical[0].is_lockfile is True
    assert canonical[0].version == "4.17.21"


def test_canonical_keeps_multiple_lockfile_versions() -> None:
    """npm hoisting can install two copies of a dep at different
    versions — both should reach OSV."""
    deps = [
        _dep("lodash", "4.17.21", is_lockfile=True, path="/a"),
        _dep("lodash", "3.10.0", is_lockfile=True, path="/b"),
    ]
    canonical = select_canonical_for_osv(deps)
    versions = sorted(d.version for d in canonical)
    assert versions == ["3.10.0", "4.17.21"]


def test_canonical_keeps_manifest_when_no_lockfile() -> None:
    deps = [_dep("lodash", "4.17.21")]
    canonical = select_canonical_for_osv(deps)
    assert canonical == deps


def test_canonical_drops_unversioned_rows() -> None:
    deps = [_dep("lodash", None), _dep("safe", "1.0.0")]
    canonical = select_canonical_for_osv(deps)
    assert [d.name for d in canonical] == ["safe"]


def test_canonical_dedups_repeated_lockfile_versions() -> None:
    deps = [
        _dep("lodash", "4.17.21", is_lockfile=True, path="/a"),
        _dep("lodash", "4.17.21", is_lockfile=True, path="/b"),
    ]
    assert len(select_canonical_for_osv(deps)) == 1


# ---------------------------------------------------------------------------
# Full run_sca
# ---------------------------------------------------------------------------

class StubHttp:
    """Routes a small allowlist of OSV / KEV / EPSS URLs to canned data."""

    LOG4J_RECORD = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2024-01-01T00:00:00Z",
        "published": "2021-12-10T00:00:00Z",
        "aliases": ["CVE-2021-44228"],
        "summary": "Log4Shell",
        "details": "Remote code execution.",
        "affected": [{
            "package": {"ecosystem": "Maven",
                        "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0-beta9"},
                                   {"fixed": "2.15.0"}]}],
        }],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "references": [{"type": "WEB", "url": "https://example.com/log4shell"}],
    }

    def __init__(self) -> None:
        self.posts: List[tuple[str, dict]] = []
        self.gets: List[str] = []

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        self.posts.append((url, body))
        if url == OSV_QUERY_BATCH_URL:
            results = []
            for q in body["queries"]:
                if (q["package"]["ecosystem"] == "Maven"
                        and q["package"]["name"]
                            == "org.apache.logging.log4j:log4j-core"
                        and q["version"] == "2.14.1"):
                    results.append({"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]})
                else:
                    results.append({})
            return {"results": results}
        raise HttpError(f"unexpected POST {url}", status=404)

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if url == OSV_VULN_URL_TEMPLATE.format("GHSA-jfh8-c2jp-5v3q"):
            return self.LOG4J_RECORD
        if "cisa.gov" in url:
            return {"vulnerabilities":
                    [{"cveID": "CVE-2021-44228"}]}
        if "first.org" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
        raise HttpError(f"unexpected GET {url}", status=404)

    def get_bytes(self, *a, **k):
        raise NotImplementedError


def test_run_sca_end_to_end_against_log4shell_fixture(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<dependencies><dependency>'
        '<groupId>org.apache.logging.log4j</groupId>'
        '<artifactId>log4j-core</artifactId>'
        '<version>2.14.1</version>'
        '</dependency></dependencies></project>',
        encoding="utf-8",
    )

    http = StubHttp()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(
        target=target, output_dir=out,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=http, cache=cache,
    )

    assert result.deps_analysed == 1
    assert result.vuln_findings == 1
    assert result.in_kev == 1
    assert result.findings_path.exists()
    assert result.report_path.exists()

    # findings.json shape.
    rows = json.loads(result.findings_path.read_text())
    assert any(r["vuln_type"] == "sca:vulnerable_dependency" for r in rows)
    sca_row = [r for r in rows
               if r["vuln_type"] == "sca:vulnerable_dependency"][0]
    assert sca_row["sca"]["in_kev"] is True
    assert sca_row["sca"]["epss"] == pytest.approx(0.97559)
    assert sca_row["sca"]["fixed_version"] == "2.15.0"

    # Report exists and looks like markdown.
    md = result.report_path.read_text()
    assert "SCA Report" in md
    assert "log4j-core" in md
    assert "**KEV**" in md


def test_run_sca_offline_mode_does_not_call_network(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.0"}}', encoding="utf-8",
    )

    http = StubHttp()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(
        target=target, output_dir=out,
        options=RunOptions(offline=True),
        http=http, cache=cache,
    )

    # No advisory queries were sent.
    assert http.posts == []
    assert http.gets == []
    # Still produces artefacts.
    assert result.findings_path.exists()
    assert result.report_path.exists()


def test_run_sca_emits_hygiene_findings(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.0"}}',
        encoding="utf-8",
    )

    http = StubHttp()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(
        target=target, output_dir=out,
        options=RunOptions(offline=True),     # no OSV calls
        http=http, cache=cache,
    )
    rows = json.loads(result.findings_path.read_text())
    hygiene_kinds = {r["vuln_type"] for r in rows
                     if r["vuln_type"].startswith("sca:hygiene:")}
    # No lockfile sibling and a caret-pinned dep ⇒ both checks fire.
    assert "sca:hygiene:lockfile_missing" in hygiene_kinds
    assert "sca:hygiene:loose_pin" in hygiene_kinds


def test_run_sca_warm_cache_avoids_network_on_second_run(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    target.mkdir()
    (target / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<dependencies><dependency>'
        '<groupId>org.apache.logging.log4j</groupId>'
        '<artifactId>log4j-core</artifactId>'
        '<version>2.14.1</version>'
        '</dependency></dependencies></project>',
        encoding="utf-8",
    )

    cache = JsonCache(root=tmp_path / "cache")
    http1 = StubHttp()
    run_sca(target, out1, RunOptions(enable_llm_review=False, enable_triage=False), http=http1, cache=cache)
    posts_first = len(http1.posts)
    gets_first = len(http1.gets)

    http2 = StubHttp()
    cache2 = JsonCache(root=tmp_path / "cache")     # same root, same data
    result = run_sca(target, out2, RunOptions(enable_llm_review=False, enable_triage=False), http=http2, cache=cache2)
    assert http2.posts == []
    assert http2.gets == []
    assert result.cache_hits > 0
    # Sanity: first run actually did network work.
    assert posts_first > 0 and gets_first > 0


# ---------------------------------------------------------------------------
# _find_previous_deps — PermissionError tolerance
# ---------------------------------------------------------------------------


def test_find_previous_deps_skips_unreadable_sibling(tmp_path: Path) -> None:
    """When ``output_dir`` lives under a shared root like /tmp/, the
    parent contains other operators' / system dirs that the SCA
    process can't stat. _find_previous_deps must skip those rather
    than abort the whole version-diff stage."""
    from packages.sca.pipeline import _find_previous_deps

    out_dir = tmp_path / "current-run"
    out_dir.mkdir()
    sibling_ok = tmp_path / "prior-run"
    sibling_ok.mkdir()
    (sibling_ok / "findings.json").write_text("[]")
    sibling_blocked = tmp_path / "blocked-run"
    sibling_blocked.mkdir()
    (sibling_blocked / "findings.json").write_text("[]")
    sibling_blocked.chmod(0o000)
    try:
        result = _find_previous_deps(out_dir)
        assert result == sibling_ok / "findings.json"
    finally:
        sibling_blocked.chmod(0o755)


def test_find_previous_deps_unreadable_parent_returns_none(
    tmp_path: Path,
) -> None:
    """If even iter'ing the parent fails entirely, return None —
    don't raise out."""
    from packages.sca.pipeline import _find_previous_deps

    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.mkdir()
    out_dir = blocked_parent / "current-run"
    out_dir.mkdir()
    blocked_parent.chmod(0o000)
    try:
        assert _find_previous_deps(out_dir) is None
    finally:
        blocked_parent.chmod(0o755)


def test_find_previous_deps_returns_most_recent_by_mtime(
    tmp_path: Path,
) -> None:
    import time
    from packages.sca.pipeline import _find_previous_deps

    out_dir = tmp_path / "current"
    out_dir.mkdir()
    older = tmp_path / "older"
    older.mkdir()
    (older / "findings.json").write_text("[]")
    time.sleep(0.05)
    newer = tmp_path / "newer"
    newer.mkdir()
    (newer / "findings.json").write_text("[]")
    result = _find_previous_deps(out_dir)
    assert result == newer / "findings.json"
