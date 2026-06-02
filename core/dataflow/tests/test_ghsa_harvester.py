"""Tests for the GHSA Advisory Database harvester.

Tests are deterministic: real git fetches are skipped; the parent-resolution
step is exercised by monkeypatching :func:`ghsa_harvester._resolve_parent`.
End-to-end coverage: produce a metadata DB and verify :mod:`cvefix_loader`
reads it without code changes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow import ghsa_harvester as gh
from core.dataflow.cvefix_loader import load_pairs


# ---------------------------------------------------------------------------
# Advisory JSON fixtures
# ---------------------------------------------------------------------------

def _adv(cve: str, cwes, eco: str, commit_url: str, year: str = "2024") -> dict:
    return {
        "schema_version": "1.4.0",
        "id": f"GHSA-test-{cve}",
        "aliases": [cve],
        "summary": "test",
        "details": "x",
        "affected": [{"package": {"ecosystem": eco, "name": "p"}}],
        "references": [{"type": "WEB", "url": commit_url}],
        "database_specific": {"cwe_ids": list(cwes), "github_reviewed": True},
    }


def _write_advisory_tree(root: Path, advs):
    """Lay out ``advs`` as one JSON per advisory under the
    ``advisories/github-reviewed/<year>/01/GHSA.../`` shape that the
    real GHSA repo uses, so :func:`_iter_advisories` finds them."""
    for adv, year in advs:
        ghsa_id = adv["id"]
        adir = root / "advisories" / "github-reviewed" / year / "01" / ghsa_id
        adir.mkdir(parents=True, exist_ok=True)
        (adir / f"{ghsa_id}.json").write_text(json.dumps(adv))


# ---------------------------------------------------------------------------
# Pure-logic helpers
# ---------------------------------------------------------------------------

def test_first_commit_ref_finds_full_sha():
    adv = {"references": [
        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999"},
        {"type": "WEB", "url": "https://github.com/owner/repo/commit/"
                              "abcdef0123456789abcdef0123456789abcdef01"},
    ]}
    assert gh._first_commit_ref(adv) == (
        "owner", "repo", "abcdef0123456789abcdef0123456789abcdef01",
    )


def test_first_commit_ref_short_sha_accepted():
    adv = {"references": [
        {"type": "WEB", "url": "https://github.com/x/y/commit/abc1234"},
    ]}
    assert gh._first_commit_ref(adv) == ("x", "y", "abc1234")


def test_first_commit_ref_none_when_no_commit_url():
    adv = {"references": [
        {"type": "WEB", "url": "https://github.com/x/y/pull/1"},
        {"type": "WEB", "url": "https://example.com/no-commit"},
    ]}
    assert gh._first_commit_ref(adv) is None


def test_first_commit_ref_skips_non_github_commit_urls():
    """A gitlab.com/.../commit/ URL must NOT match (we'd record a wrong
    repo_url that the walker can't fetch).  Soundness > recall: we'd
    rather decline than fabricate a record."""
    adv = {"references": [
        {"type": "WEB", "url": "https://gitlab.com/x/y/commit/abc1234"},
    ]}
    assert gh._first_commit_ref(adv) is None


def test_pick_cwe_eco_deterministic_across_calls():
    """Multi-CWE / multi-ecosystem advisories must always get the same
    label, regardless of dict iteration order — sorted picks guarantee it."""
    adv = {
        "database_specific": {"cwe_ids": ["CWE-79", "CWE-22"]},
        "affected": [{"package": {"ecosystem": "npm", "name": "a"}},
                     {"package": {"ecosystem": "PyPI", "name": "b"}}],
    }
    pick1 = gh._pick_cwe_eco(adv, {"CWE-22", "CWE-79"}, {"npm", "PyPI"})
    pick2 = gh._pick_cwe_eco(adv, {"CWE-22", "CWE-79"}, {"npm", "PyPI"})
    assert pick1 == pick2 == ("CWE-22", "PyPI")  # sorted-first


# ---------------------------------------------------------------------------
# Advisory iteration + filter
# ---------------------------------------------------------------------------

def test_iter_advisories_filters_by_cwe_and_ecosystem(tmp_path: Path):
    _write_advisory_tree(tmp_path, [
        (_adv("CVE-2024-1", ["CWE-22"], "PyPI",
              "https://github.com/x/y/commit/abc1234"), "2024"),
        (_adv("CVE-2024-2", ["CWE-99"], "PyPI",      # wrong CWE
              "https://github.com/x/y/commit/def5678"), "2024"),
        (_adv("CVE-2024-3", ["CWE-22"], "composer",  # wrong ecosystem
              "https://github.com/x/y/commit/9ab9999"), "2024"),
    ])
    out = list(gh._iter_advisories(
        tmp_path, ["2024"], {"CWE-22"}, {"PyPI"},
    ))
    assert len(out) == 1
    assert out[0][1]["aliases"] == ["CVE-2024-1"]


def test_iter_advisories_skips_unreviewed_namespace(tmp_path: Path):
    """``advisories/unreviewed/`` exists in the real GHSA repo with much
    noisier metadata; we restrict to ``github-reviewed`` only.  An empty
    github-reviewed/ subtree must still exist so the harvester doesn't
    abort with a missing-root error."""
    (tmp_path / "advisories" / "github-reviewed").mkdir(parents=True)
    adv = _adv("CVE-2024-9", ["CWE-22"], "PyPI",
               "https://github.com/x/y/commit/9999999")
    adir = tmp_path / "advisories" / "unreviewed" / "2024" / "01" / adv["id"]
    adir.mkdir(parents=True)
    (adir / f"{adv['id']}.json").write_text(json.dumps(adv))
    out = list(gh._iter_advisories(tmp_path, ["2024"], {"CWE-22"}, {"PyPI"}))
    assert out == []


# ---------------------------------------------------------------------------
# End-to-end: main() with mocked parent resolution
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_resolve(monkeypatch):
    """Replace :func:`_resolve_parent` with a deterministic stub: parent
    of every fix is its SHA with the first 8 chars rotated.  Lets us run
    main() end-to-end with no network."""
    def fake(repo_url, fix_hash, timeout=60):
        if "FAIL-REPO" in repo_url:
            return None
        return fix_hash[8:] + fix_hash[:8]
    monkeypatch.setattr(gh, "_resolve_parent", fake)
    return fake


def test_main_e2e_produces_loadable_metadata_db(tmp_path: Path, fake_resolve):
    _write_advisory_tree(tmp_path, [
        (_adv("CVE-2024-1", ["CWE-22"], "PyPI",
              "https://github.com/o/r/commit/aaaa00000000000000000000000000000000bbbb"),
         "2024"),
        (_adv("CVE-2025-2", ["CWE-79"], "npm",
              "https://github.com/o/q/commit/ccccdddd00000000000000000000000000001111"),
         "2025"),
    ])
    out = tmp_path / "metadata.db"
    rc = gh.main([
        "--ghsa-root", str(tmp_path),
        "--out", str(out),
        "--years", "2024", "2025",
    ])
    assert rc == 0
    pairs = load_pairs(out)
    assert len(pairs) == 2
    cves = {p.cve_id for p in pairs}
    assert cves == {"CVE-2024-1", "CVE-2025-2"}
    # parent_hash is populated and different per fix (rotation stub).
    for p in pairs:
        assert p.parent_hash and p.parent_hash != p.fix_hash


def test_main_drops_advisories_with_no_cve_alias(tmp_path: Path, fake_resolve):
    """Advisories without a CVE alias have no canonical id to record;
    they MUST be filtered out (recording GHSA-IDs as cve_id would break
    the schema's contract with downstream consumers)."""
    adv = _adv("CVE-2024-keep", ["CWE-22"], "PyPI",
               "https://github.com/o/r/commit/" + "a" * 40)
    no_cve = dict(adv)
    no_cve["id"] = "GHSA-noaliasN"
    no_cve["aliases"] = []   # advisory has no CVE alias
    _write_advisory_tree(tmp_path, [(adv, "2024"), (no_cve, "2024")])
    out = tmp_path / "metadata.db"
    gh.main(["--ghsa-root", str(tmp_path), "--out", str(out), "--years", "2024"])
    pairs = load_pairs(out)
    assert [p.cve_id for p in pairs] == ["CVE-2024-keep"]


def test_main_sample_size_is_deterministic_under_seed(tmp_path: Path, fake_resolve):
    """Same seed -> same sampled subset; covering the random-sample call
    site since the production run will rely on it for reproducibility."""
    for i in range(5):
        a = _adv(f"CVE-2024-{i}", ["CWE-22"], "PyPI",
                 f"https://github.com/o/r/commit/{i:040d}".replace(
                     " ", "0"))
        _write_advisory_tree(tmp_path, [(a, "2024")])
    out1 = tmp_path / "m1.db"
    out2 = tmp_path / "m2.db"
    gh.main(["--ghsa-root", str(tmp_path), "--out", str(out1),
             "--years", "2024", "--sample-size", "3", "--seed", "7"])
    gh.main(["--ghsa-root", str(tmp_path), "--out", str(out2),
             "--years", "2024", "--sample-size", "3", "--seed", "7"])
    pairs1 = sorted(p.cve_id for p in load_pairs(out1))
    pairs2 = sorted(p.cve_id for p in load_pairs(out2))
    assert pairs1 == pairs2
    assert len(pairs1) == 3


def test_main_skipped_advisories_when_fetch_fails(tmp_path: Path, fake_resolve):
    """Fetch failures are tracked declines, not silent successes — only
    advisories with a resolved parent end up in the metadata DB."""
    _write_advisory_tree(tmp_path, [
        (_adv("CVE-2024-good", ["CWE-22"], "PyPI",
              "https://github.com/o/good/commit/" + "0" * 40), "2024"),
        # repo_url containing FAIL-REPO triggers the stub to return None
        (_adv("CVE-2024-bad", ["CWE-22"], "PyPI",
              "https://github.com/FAIL-REPO/x/commit/" + "1" * 40), "2024"),
    ])
    out = tmp_path / "m.db"
    gh.main(["--ghsa-root", str(tmp_path), "--out", str(out), "--years", "2024"])
    pairs = load_pairs(out)
    assert [p.cve_id for p in pairs] == ["CVE-2024-good"]


# ---------------------------------------------------------------------------
# DB schema check
# ---------------------------------------------------------------------------

def test_metadata_db_has_all_columns_load_pairs_reads(tmp_path: Path, fake_resolve):
    _write_advisory_tree(tmp_path, [
        (_adv("CVE-2024-x", ["CWE-22"], "PyPI",
              "https://github.com/o/r/commit/" + "a" * 40), "2024"),
    ])
    out = tmp_path / "m.db"
    gh.main(["--ghsa-root", str(tmp_path), "--out", str(out), "--years", "2024"])
    # Sanity-check: every column load_pairs's SQL reads is present.
    import sqlite3
    con = sqlite3.connect(out)
    try:
        rows = con.execute("""
            SELECT f.cve_id, c.cwe_id, f.repo_url, r.repo_language,
                   f.hash, cm.parents
            FROM fixes f
            JOIN cwe_classification c ON f.cve_id = c.cve_id
            JOIN commits cm ON f.hash = cm.hash
            JOIN repository r ON f.repo_url = r.repo_url
        """).fetchall()
    finally:
        con.close()
    assert len(rows) == 1
    cve_id, cwe, repo_url, lang, fix_hash, parents = rows[0]
    assert cve_id == "CVE-2024-x"
    assert cwe == "CWE-22"
    assert lang == "Python"
    assert parents.startswith("[") and parents.endswith("]")
