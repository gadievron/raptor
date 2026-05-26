"""Tier-1 E2E: subprocess-invoke each CLI subcommand against a small
fixture; assert exit code + key output files.

Catches the class of bug where unit tests pass but the actual
``raptor-sca <subcommand>`` invocation breaks — argparse drift,
dispatcher routing, libexec wiring, output file paths.

Each test invokes the CLI via ``python -m packages.sca.cli`` so the
test runs in the same interpreter that imports the rest of the
suite (CI-friendly; no PATH dependency on a pip-installed entry
point). The dispatcher exercised is identical to the one
``libexec/raptor-sca`` calls.

All scans use ``--offline`` to keep CI hermetic — no OSV / KEV /
EPSS / registry network calls. Cached data only.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import List


# Anchor to the repo root via __file__ (test sits at
# packages/sca/tests/test_cli_smoke.py — three parents up).
REPO_ROOT = Path(__file__).resolve().parents[3]


# Single fixture used by all subcommands — small enough that the full
# pipeline runs in <5s per invocation.
def _build_fixture(repo: Path) -> None:
    """A minimal-but-realistic multi-ecosystem fixture: one Python
    dep, one npm dep, one Dockerfile ARG pin. All offline-safe
    (no network lookups required for the subcommands we exercise
    here)."""
    repo.mkdir(parents=True, exist_ok=True)

    # Python — requirements.txt with a known-stable pin.
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )

    # npm — package.json with a known-stable pin + no lockfile (so
    # hygiene fires).
    (repo / "package.json").write_text(json.dumps({
        "name": "fixture",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.21"},
    }), encoding="utf-8")

    # Dockerfile — one ARG pin (bump candidate; no network needed
    # to enumerate, only to look up upstream-latest).
    (repo / "Dockerfile").write_text(
        "FROM python:3.13-slim\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
        "RUN pip install semgrep==${SEMGREP_VERSION}\n",
        encoding="utf-8",
    )


def _run_cli(args: List[str], *, cwd: Path = None,
             timeout: int = 60) -> subprocess.CompletedProcess:
    """Invoke the CLI via ``python -m``. Returns the completed
    process; caller asserts on it."""
    cmd = [sys.executable, "-m", "packages.sca.cli"] + args
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(cwd) if cwd else str(REPO_ROOT),
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# scan (the default subcommand)
# ---------------------------------------------------------------------------

def test_scan_offline_smoke(tmp_path: Path) -> None:
    """``raptor-sca <target> --offline --out <out>`` — default
    scan path. Asserts exit code 0, all four canonical output
    files present, findings.json parses + has expected
    top-level structure."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_cli([str(repo), "--offline", "--out", str(out),
                      "--no-progress"])

    assert proc.returncode == 0, (
        f"scan failed: rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:2000]}"
    )

    # Four canonical output files per docs/sca.md.
    assert (out / "findings.json").exists()
    assert (out / "report.md").exists()
    assert (out / "sbom.cdx.json").exists()
    assert (out / "coverage-sca.json").exists()

    # findings.json shape — list of finding dicts.
    findings = json.loads((out / "findings.json").read_text())
    assert isinstance(findings, list)
    # Each finding has the invariant trio: finding_id + severity
    # + file (per packages/sca/findings.py canonical schema).
    for f in findings:
        assert "finding_id" in f
        assert "severity" in f
        assert "file" in f


# ---------------------------------------------------------------------------
# check (single-package pre-add evaluation)
# ---------------------------------------------------------------------------

def test_check_offline_smoke(tmp_path: Path) -> None:
    """``raptor-sca check <eco> <name> <version> --offline`` —
    asserts the subcommand routes correctly + produces an exit
    code (0 Clean / 1 Review / 2 Block per the doc'd contract).

    Without a populated offline cache the verdict will be
    Clean (no findings, no signal); we don't assert specific
    verdict here — just that the dispatcher works."""
    proc = _run_cli([
        "check", "npm", "lodash", "4.17.21",
        "--offline", "--out", str(tmp_path / "out"),
    ])
    assert proc.returncode in (0, 1, 2), (
        f"check returned unexpected rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:1000]}"
    )


# ---------------------------------------------------------------------------
# upgrade (whatif)
# ---------------------------------------------------------------------------

def test_upgrade_offline_smoke(tmp_path: Path) -> None:
    """``raptor-sca upgrade npm lodash 4.17.4 4.17.21 --offline``
    — forward-looking impact analysis. Exit codes per docs:
    0 net-positive, 1 mixed/regression."""
    proc = _run_cli([
        "upgrade", "npm", "lodash", "4.17.4", "4.17.21",
        "--offline", "--out", str(tmp_path / "out"),
    ])
    assert proc.returncode in (0, 1), (
        f"upgrade returned unexpected rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:1000]}"
    )


# ---------------------------------------------------------------------------
# diff (compare two findings.json)
# ---------------------------------------------------------------------------

def test_diff_offline_smoke(tmp_path: Path) -> None:
    """``raptor-sca diff <a> <b>`` — compare two findings sets.
    Build two minimal findings files; the comparison should
    succeed regardless of content."""
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps([]))
    b.write_text(json.dumps([{
        "tag": "sca:vulnerable_dependency",
        "severity": "high",
        "file": "package.json",
        "title": "Test finding",
    }]))

    proc = _run_cli(["diff", str(a), str(b), "--out",
                      str(tmp_path / "diff-out")])
    # Diff doesn't have a defined "fail" — 0 means produced a report.
    # With --fail-on-severity it can return 1; we don't set it here.
    assert proc.returncode == 0, (
        f"diff failed: rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:1000]}"
    )


# ---------------------------------------------------------------------------
# bump (the dependabot++ subcommand)
# ---------------------------------------------------------------------------

def test_bump_no_candidates_smoke(tmp_path: Path) -> None:
    """``raptor-sca bump <empty-repo>`` — no bumpable surfaces
    (no Dockerfile / GHA workflows / k8s images / Helm
    Chart.yaml / .gitmodules). Asserts the subcommand routes,
    runs to completion, and emits a "no candidates" outcome
    without making any network calls (no surfaces means no
    upstream-latest lookups)."""
    empty = tmp_path / "empty-repo"
    empty.mkdir()

    proc = _run_cli(["bump", str(empty), "--json"])
    assert proc.returncode == 0, (
        f"bump on empty repo failed: rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:1000]}"
    )

    # --json prints a parseable report; verify it parses + has
    # the expected top-level shape.
    payload = json.loads(proc.stdout)
    assert "candidates" in payload
    assert "results" in payload
    assert payload["candidates"] == []


# ---------------------------------------------------------------------------
# fix (auto-fix CVEs)
# ---------------------------------------------------------------------------

def test_fix_offline_smoke(tmp_path: Path) -> None:
    """``raptor-sca fix <target> --offline`` — scan + propose
    fixes pass. With no online CVE feed available, fix should
    still exit cleanly (no fixes to propose). Plan-only by
    default; we don't pass --apply."""
    repo = tmp_path / "repo"
    _build_fixture(repo)

    proc = _run_cli([
        "fix", str(repo), "--offline",
        "--out", str(tmp_path / "fix-out"),
        "--no-llm",
    ])
    # 0 = plan produced successfully; non-zero would be a crash.
    assert proc.returncode == 0, (
        f"fix failed: rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr[:2000]}"
    )


# ---------------------------------------------------------------------------
# version / help (sanity)
# ---------------------------------------------------------------------------

def test_help_smoke() -> None:
    """``raptor-sca --help`` — argparse renders without error
    on every subcommand registered in SUBCOMMANDS."""
    proc = _run_cli(["--help"], timeout=10)
    assert proc.returncode == 0
    assert "raptor-sca" in proc.stdout
    # Every documented subcommand should be discoverable from
    # the top-level help OR the dispatcher; check the dispatcher
    # registry directly to catch regressions in either direction.
    from packages.sca.cli import SUBCOMMANDS
    assert "scan" not in SUBCOMMANDS  # scan is the implicit default
    for sub in ("fix", "check", "upgrade", "diff", "bump"):
        assert sub in SUBCOMMANDS, f"missing subcommand: {sub}"
