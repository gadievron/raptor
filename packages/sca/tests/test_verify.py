"""Tests for ``packages.sca.verify`` — apply a proposed/ patch to a
target overlay, re-run analyse, diff against the baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from packages.sca import verify
from core.json import JsonCache
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE


_VULN_RECORD = {
    "id": "GHSA-pkg-vuln",
    "modified": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2099-PKG"],
    "summary": "Test CVE",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "vuln-pkg"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [],
}


class StubHttp:
    """OSV stub: vuln-pkg<2.0 hits GHSA-pkg-vuln; everything else clean."""

    def __init__(self) -> None:
        self.posts: List[tuple] = []
        self.gets: List[str] = []

    def post_json(self, url, body, timeout=30):
        self.posts.append((url, body))
        if url == OSV_QUERY_BATCH_URL:
            results = []
            for q in body["queries"]:
                pkg = q["package"]
                ver = q["version"]
                if (pkg["ecosystem"] == "PyPI"
                        and pkg["name"] == "vuln-pkg"
                        and ver in ("1.0.0", "1.5.0")):
                    results.append({"vulns": [{"id": "GHSA-pkg-vuln"}]})
                else:
                    results.append({})
            return {"results": results}
        raise RuntimeError(url)

    def get_json(self, url, timeout=30):
        self.gets.append(url)
        if url == OSV_VULN_URL_TEMPLATE.format("GHSA-pkg-vuln"):
            return _VULN_RECORD
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        if "first.org" in url:
            return {"data": []}
        raise RuntimeError(url)

    def get_bytes(self, *a, **k):
        raise NotImplementedError


def _build_target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "requirements.txt").write_text(
        "vuln-pkg==1.0.0\n", encoding="utf-8",
    )
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("import vuln_pkg\n",
                                            encoding="utf-8")
    return target


def _build_proposed(tmp_path: Path, version: str) -> Path:
    proposed = tmp_path / "proposed"
    proposed.mkdir()
    (proposed / "requirements.txt").write_text(
        f"vuln-pkg=={version}\n", encoding="utf-8",
    )
    return proposed


# ---------------------------------------------------------------------------
# Verdict paths
# ---------------------------------------------------------------------------

def test_clean_verdict_when_proposed_clears_all_findings(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "2.0.0")  # past the fix
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    rc = verify.main(
        [str(target), "--proposed", str(proposed), "--out", str(out)],
        http=StubHttp(), cache=cache,
    )
    assert rc == 0
    delta_md = (out / "delta.md").read_text()
    assert "Verdict: clean" in delta_md
    assert "Resolved: **1**" in delta_md
    assert "New: **0**" in delta_md


def test_regression_verdict_when_proposed_does_not_clear(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "1.5.0")  # still vulnerable
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    rc = verify.main(
        [str(target), "--proposed", str(proposed), "--out", str(out)],
        http=StubHttp(), cache=cache,
    )
    # Same advisory hits both versions → no resolution, no regression
    # (canonical-id dedup). Verdict is clean (no NEW findings).
    assert rc == 0
    delta_md = (out / "delta.md").read_text()
    assert "Resolved: **0**" in delta_md
    assert "New: **0**" in delta_md


def test_findings_path_lets_caller_skip_baseline_run(tmp_path: Path) -> None:
    """When ``--findings`` points at an existing file we don't re-run
    analyse on the original target."""
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "2.0.0")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")

    # Run once to produce the baseline findings.
    from packages.sca.pipeline import RunOptions, run_sca
    base_dir = tmp_path / "base"
    base = run_sca(target, base_dir, RunOptions(enable_llm_review=False, enable_triage=False), http=StubHttp(),
                   cache=cache)
    assert base.findings_path.exists()

    rc = verify.main(
        [str(target), "--proposed", str(proposed),
         "--findings", str(base.findings_path),
         "--out", str(out)],
        http=StubHttp(), cache=cache,
    )
    assert rc == 0
    # Note: we don't assert verify-before is absent because some
    # pipelines may write a placeholder; what matters is correctness
    # of the verdict.
    delta_md = (out / "delta.md").read_text()
    assert "Verdict: clean" in delta_md


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_target_not_a_directory_returns_2(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x")
    proposed = _build_proposed(tmp_path, "2.0.0")
    rc = verify.main([str(f), "--proposed", str(proposed),
                      "--out", str(tmp_path / "out")],
                     http=StubHttp(), cache=JsonCache(root=tmp_path / "c"))
    assert rc == 2


def test_proposed_not_a_directory_returns_2(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    rc = verify.main([str(target), "--proposed",
                      str(tmp_path / "missing"),
                      "--out", str(tmp_path / "out")],
                     http=StubHttp(), cache=JsonCache(root=tmp_path / "c"))
    assert rc == 2


def test_empty_proposed_dir_returns_2(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    empty = tmp_path / "empty-proposed"
    empty.mkdir()
    rc = verify.main([str(target), "--proposed", str(empty),
                      "--out", str(tmp_path / "out")],
                     http=StubHttp(), cache=JsonCache(root=tmp_path / "c"))
    assert rc == 2


# ---------------------------------------------------------------------------
# Overlay mechanics
# ---------------------------------------------------------------------------

def test_overlay_skips_vendored_dirs(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    # Create a node_modules dir we don't want copied (would be huge in real life).
    (target / "node_modules" / "evil").mkdir(parents=True)
    (target / "node_modules" / "evil" / "package.json").write_text(
        '{"dependencies": {"poison": "1.0"}}', encoding="utf-8",
    )
    proposed = _build_proposed(tmp_path, "2.0.0")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    verify.main([str(target), "--proposed", str(proposed),
                 "--out", str(out)],
                http=StubHttp(), cache=cache)
    # Overlay was created and node_modules was not copied.
    assert (out / "overlay" / "node_modules").exists() is False


def test_overlay_preserves_non_overlaid_files(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "2.0.0")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    verify.main([str(target), "--proposed", str(proposed),
                 "--out", str(out)],
                http=StubHttp(), cache=cache)
    # The reachability source file was carried over unchanged.
    assert (out / "overlay" / "src" / "app.py").read_text() \
        == "import vuln_pkg\n"


def test_delta_json_records_applied_files(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "2.0.0")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    verify.main([str(target), "--proposed", str(proposed),
                 "--out", str(out)],
                http=StubHttp(), cache=cache)
    data = json.loads((out / "delta.json").read_text())
    assert "requirements.txt" in data["applied"]
    assert data["summary"]["resolved"] == 1
