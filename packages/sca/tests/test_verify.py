"""Tests for ``packages.sca.verify`` — apply a proposed/ patch to a
target overlay, re-run analyse, diff against the baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

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


@pytest.mark.slow
def test_regression_verdict_when_proposed_does_not_clear(tmp_path: Path) -> None:
    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "1.5.0")  # still vulnerable
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    rc = verify.main(
        [str(target), "--proposed", str(proposed), "--out", str(out)],
        http=StubHttp(), cache=cache,
    )
    # Same advisory hits both versions → persistent — in a file the
    # patch rewrote, so the advisory the operator expected to clear
    # didn't. Documented contract: exit 1.
    assert rc == 1
    delta_md = (out / "delta.md").read_text()
    assert "Verdict: not cleared" in delta_md
    assert "Resolved: **0**" in delta_md
    assert "New: **0**" in delta_md


def test_verdict_persistent_outside_patched_files_is_clean() -> None:
    """Pre-existing findings persisting in files the patch never
    touched must not gate the exit code — a targeted fix isn't
    responsible for the unrelated backlog."""
    from types import SimpleNamespace
    delta = SimpleNamespace(
        new=[],
        resolved=[],
        persistent=[{"severity": "critical", "id": "OLD-001",
                     "file": "/overlay/other/requirements.txt"}],
        suppression_added=[],
        suppression_lifted=[],
    )
    summary, exit_code = verify._verdict(
        delta, severity_floor="low", applied=[Path("package.json")],
        overlay_root=Path("/overlay"),
    )
    assert exit_code == 0
    assert summary["persistent_above_threshold"] == 1
    assert summary["not_cleared_above_threshold"] == 0


def test_verdict_persistent_in_patched_file_exits_nonzero() -> None:
    """An advisory persisting in a manifest the proposed/ patch rewrote
    means the patch failed to clear it — documented exit-1 contract."""
    from types import SimpleNamespace
    delta = SimpleNamespace(
        new=[],
        resolved=[],
        persistent=[{"severity": "high", "id": "OLD-001",
                     "file": "/overlay/requirements.txt"}],
        suppression_added=[],
        suppression_lifted=[],
    )
    summary, exit_code = verify._verdict(
        delta, severity_floor="high", applied=[Path("requirements.txt")],
        overlay_root=Path("/overlay"),
    )
    assert exit_code == 1
    assert summary["not_cleared_above_threshold"] == 1


def test_verdict_persistent_below_threshold_does_not_gate() -> None:
    """A low-severity advisory persisting in a patched file stays below
    the operator's --fail-on-severity floor."""
    from types import SimpleNamespace
    delta = SimpleNamespace(
        new=[],
        resolved=[],
        persistent=[{"severity": "low", "id": "OLD-001",
                     "file": "/overlay/requirements.txt"}],
        suppression_added=[],
        suppression_lifted=[],
    )
    summary, exit_code = verify._verdict(
        delta, severity_floor="high", applied=[Path("requirements.txt")],
    )
    assert exit_code == 0
    assert summary["not_cleared_above_threshold"] == 0


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


# ---------------------------------------------------------------------------
# delta.md row rendering — untrusted findings fields are neutralised
# ---------------------------------------------------------------------------

def test_row_line_neutralises_hostile_findings_fields() -> None:
    """Package name / advisory id flow from findings.json (registry /
    manifest content) into delta.md tables and stdout — pipes must
    not split the row, newlines must not terminate it, and ANSI
    bytes must be defanged."""
    row = {
        "severity": "high",
        "sca": {
            "ecosystem": "npm",
            "name": "evil|pkg\n</details>",
            "version": "1.0.0\x1b[31m",
            "advisory": {"id": "GHSA-x | forged | yes | 0.99"},
            "in_kev": False,
            "epss": 0.5,
        },
    }
    line = verify._row_line(row)
    assert "\n" not in line
    assert "\x1b" not in line
    assert "</details>" not in line
    # Un-escaped pipes would forge extra table cells: exactly the
    # four data columns plus delimiters survive (hostile pipes are
    # backslash-escaped).
    import re
    assert len(re.findall(r"(?<!\\)\|", line)) == 5


# ---------------------------------------------------------------------------
# _not_cleared_in_applied — exact join, no suffix false positives
# ---------------------------------------------------------------------------

def test_verdict_suffix_sharing_manifest_does_not_false_fail() -> None:
    """A monorepo manifest whose overlay path merely ENDS with a
    patched file's relative path must not read as 'not cleared' — the
    old suffix match false-failed targeted fix --fix=<adv> runs."""
    from types import SimpleNamespace
    delta = SimpleNamespace(
        new=[],
        resolved=[],
        persistent=[
            # Untouched sibling: other/sub/package.json — suffix of
            # the applied rel path 'sub/package.json'.
            {"severity": "high", "id": "OLD-001",
             "file": "/overlay/other/sub/package.json"},
        ],
        suppression_added=[],
        suppression_lifted=[],
    )
    summary, exit_code = verify._verdict(
        delta, severity_floor="high",
        applied=[Path("sub/package.json")],
        overlay_root=Path("/overlay"),
    )
    assert exit_code == 0
    assert summary["not_cleared_above_threshold"] == 0
    # The genuinely patched manifest still gates.
    delta.persistent = [{"severity": "high", "id": "OLD-001",
                         "file": "/overlay/sub/package.json"}]
    summary, exit_code = verify._verdict(
        delta, severity_floor="high",
        applied=[Path("sub/package.json")],
        overlay_root=Path("/overlay"),
    )
    assert exit_code == 1
    assert summary["not_cleared_above_threshold"] == 1


# ---------------------------------------------------------------------------
# _copy_target — never follows symlinks (directory or file)
# ---------------------------------------------------------------------------

def test_copy_target_does_not_follow_directory_symlinks(
    tmp_path: Path,
) -> None:
    """A hostile repo's symlinked directory must not pull outside
    files into the overlay (pre-3.13 Path.rglob recursed THROUGH
    directory symlinks; os.walk(followlinks=False) never does)."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "id_ed25519").write_text("SECRET", encoding="utf-8")
    target = tmp_path / "repo"
    target.mkdir()
    (target / "requirements.txt").write_text("requests==2.0.0\n",
                                             encoding="utf-8")
    (target / "docs").symlink_to(victim, target_is_directory=True)
    (target / "link.txt").symlink_to(victim / "id_ed25519")

    dst = tmp_path / "overlay"
    verify._copy_target(target, dst)

    copied = {str(p.relative_to(dst)) for p in dst.rglob("*")}
    assert "requirements.txt" in copied
    assert not any("id_ed25519" in c for c in copied), copied
    assert "docs" not in copied and "link.txt" not in copied


def test_copy_target_survives_cyclic_symlink(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "loop").symlink_to(target, target_is_directory=True)
    (target / "package.json").write_text("{}", encoding="utf-8")
    dst = tmp_path / "overlay"
    verify._copy_target(target, dst)          # must terminate
    assert (dst / "package.json").exists()
    assert not (dst / "loop").exists()


def test_overlay_skip_list_cannot_drift_from_discovery(
    tmp_path: Path,
) -> None:
    """The overlay skip list is derived from discovery's exclusions —
    a hand-mirrored copy drifted (no .out / .claude / codeql_dbs), so
    every verify run copied CodeQL DB caches and agent state into the
    scratch overlay."""
    from packages.sca.discovery import EXCLUDED_DIR_NAMES

    assert verify._SKIP_DIR_NAMES == set(EXCLUDED_DIR_NAMES)

    target = tmp_path / "repo"
    (target / "codeql_dbs").mkdir(parents=True)
    (target / "codeql_dbs" / "huge.idx").write_text("x", encoding="utf-8")
    (target / ".claude").mkdir()
    (target / ".claude" / "state.json").write_text("{}", encoding="utf-8")
    (target / "requirements.txt").write_text("requests==2.0.0\n",
                                             encoding="utf-8")
    dst = tmp_path / "overlay"
    verify._copy_target(target, dst)
    assert (dst / "requirements.txt").exists()
    assert not (dst / "codeql_dbs").exists()
    assert not (dst / ".claude").exists()


# ---------------------------------------------------------------------------
# OSV degradation — verdict availability
# ---------------------------------------------------------------------------

def test_osv_degraded_run_exits_4_not_clean(tmp_path: Path) -> None:
    """An OSV outage during the analyse runs makes every advisory
    invisible, so the delta reads "clean" while the vulnerable pin is
    untouched — the patch-safety gate must refuse to conclude (distinct
    exit 4 + explicit degraded section), never report resolution."""
    from core.http import HttpError

    class OutageHttp(StubHttp):
        def post_json(self, url, body, timeout=30):
            raise HttpError(f"simulated OSV outage: {url}")

    target = _build_target(tmp_path)
    proposed = _build_proposed(tmp_path, "2.0.0")
    out = tmp_path / "out"
    rc = verify.main(
        [str(target), "--proposed", str(proposed), "--out", str(out)],
        http=OutageHttp(), cache=JsonCache(root=tmp_path / "cache"),
    )
    assert rc == 4
    delta_md = (out / "delta.md").read_text()
    assert "OSV lookups degraded" in delta_md
    assert "verdict unavailable" in delta_md
    # The verdict line itself reflects the degradation — no
    # "Verdict: clean" above the refusal section.
    assert "**Verdict: unavailable**" in delta_md
    assert "Verdict: clean" not in delta_md
