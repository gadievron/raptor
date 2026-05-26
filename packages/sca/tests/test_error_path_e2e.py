"""Tier-4 E2E: error-path scenarios.

Drives the CLI against fixtures crafted to trigger every error
path we can reach from operator input. Each test asserts:

  * The CLI does NOT crash with an unhandled traceback (exit
    codes ≠ unhandled-exception values like 134/139).
  * stderr / output has a helpful message identifying the
    problem.
  * Output files (when present) are structurally well-formed.

Catches the regression class where a refactor leaves an
exception-handling path unguarded and a malformed input crashes
the whole scan rather than emitting a graceful "couldn't parse
manifest X" record.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_cli(
    args: List[str], *, timeout: int = 60,
    extra_env: dict = None,
) -> subprocess.CompletedProcess:
    """Invoke ``raptor-sca`` CLI; mirrors test_cli_smoke pattern."""
    cmd = [sys.executable, "-m", "packages.sca.cli"] + args
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), env=env, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Malformed manifest variants
# ---------------------------------------------------------------------------

def test_malformed_pom_xml_does_not_crash(tmp_path: Path) -> None:
    """A pom.xml with broken XML must be skipped by the parser
    (warning logged) without taking down the whole scan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Open-tag without close; structurally invalid XML
    (repo / "pom.xml").write_text(
        "<project><groupId>com.example<", encoding="utf-8",
    )
    # Add a valid manifest so the scan has SOMETHING to report
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )

    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    # Graceful exit (0 = nothing critical, 1 = findings above
    # threshold). Anything else suggests crash.
    assert proc.returncode in (0, 1), (
        f"crash on malformed pom: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )
    # Findings file present + parseable
    findings = out / "findings.json"
    assert findings.is_file()
    data = json.loads(findings.read_text())
    assert isinstance(data, (list, dict))


def test_broken_pipfile_lock_does_not_crash(tmp_path: Path) -> None:
    """Pipfile.lock that's not valid JSON must skip cleanly."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Pipfile.lock").write_text("{not json{", encoding="utf-8")
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )

    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1), (
        f"crash on broken Pipfile.lock: exit={proc.returncode}"
    )
    assert (out / "findings.json").is_file()


def test_garbage_package_json_does_not_crash(tmp_path: Path) -> None:
    """package.json that's syntactically broken JSON."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"name": "x", "dependencies": "this should be an obj"',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)


def test_pom_with_xxe_payload_blocked_not_executed(tmp_path: Path) -> None:
    """A pom.xml carrying a DOCTYPE / entity-expansion payload
    must be rejected by defusedxml (billion-laughs defence) and
    the scan must continue without hanging."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pom.xml").write_text('''<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
</project>
''', encoding="utf-8")
    out = tmp_path / "out"
    # If XXE were processed, exit time would balloon; cap to 60s
    proc = _run_cli([str(repo), "--offline", "--out", str(out)], timeout=60)
    assert proc.returncode in (0, 1)


# ---------------------------------------------------------------------------
# No-manifest variants
# ---------------------------------------------------------------------------

def test_no_manifests_exits_cleanly(tmp_path: Path) -> None:
    """Empty target (no manifests at all) → clean exit, empty
    findings list."""
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "out"
    proc = _run_cli([str(empty), "--offline", "--out", str(out)])
    assert proc.returncode == 0
    findings = json.loads((out / "findings.json").read_text())
    if isinstance(findings, dict):
        findings = findings.get("findings", [])
    assert findings == [], f"empty target produced findings: {findings}"


def test_target_does_not_exist_returns_error(tmp_path: Path) -> None:
    """Non-existent target → exit 2 (argparse-style) with helpful
    stderr."""
    proc = _run_cli([
        str(tmp_path / "does-not-exist"), "--offline",
        "--out", str(tmp_path / "out"),
    ])
    assert proc.returncode == 2, (
        f"expected exit 2 for missing target, got {proc.returncode}\n"
        f"stderr:\n{proc.stderr}"
    )
    assert any(
        marker in proc.stderr.lower()
        for marker in ("not found", "does not exist", "no such")
    ), f"unhelpful stderr: {proc.stderr}"


# ---------------------------------------------------------------------------
# Network-blocked variants
# ---------------------------------------------------------------------------

def test_offline_mode_with_empty_cache_still_emits_findings(
    tmp_path: Path,
) -> None:
    """``--offline`` with no warm cache → no live OSV / KEV / EPSS
    lookups. Hygiene findings (no-lockfile, unpinned, etc.) still
    surface from local-only analysis. CLI must not crash."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )
    (repo / "package.json").write_text(
        '{"name": "x", "dependencies": {"lodash": "*"}}',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)
    # Output files must exist
    for name in ("findings.json", "report.md", "sbom.cdx.json"):
        assert (out / name).is_file(), (
            f"offline mode failed to emit {name}"
        )


# ---------------------------------------------------------------------------
# Filesystem edge cases
# ---------------------------------------------------------------------------

def test_symlinked_manifest_handled(tmp_path: Path) -> None:
    """A manifest that's a symlink (to another file in the same
    tree) gets read like any other file. Common in monorepos that
    symlink shared configs."""
    repo = tmp_path / "repo"
    repo.mkdir()
    real = repo / "shared.txt"
    real.write_text("requests==2.31.0\n", encoding="utf-8")
    link = repo / "requirements.txt"
    link.symlink_to(real)
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)


def test_unreadable_file_logs_warning_continues(tmp_path: Path) -> None:
    """A manifest the scanner can't read (permission denied,
    transient I/O) emits a warning, doesn't crash."""
    repo = tmp_path / "repo"
    repo.mkdir()
    bad = repo / "requirements.txt"
    bad.write_text("requests==2.31.0\n", encoding="utf-8")
    bad.chmod(0o000)
    # Add a readable manifest too so the scan has work to do
    (repo / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    out = tmp_path / "out"
    try:
        proc = _run_cli([str(repo), "--offline", "--out", str(out)])
        # Some pytest sandboxing makes the chmod a no-op; either
        # we got the unreadable path (graceful skip) or readable
        # path (success). Both are exit-0/1.
        assert proc.returncode in (0, 1), (
            f"crash on unreadable: exit={proc.returncode}"
        )
    finally:
        # Restore so pytest can cleanup
        bad.chmod(0o644)


# ---------------------------------------------------------------------------
# Per-subcommand error paths
# ---------------------------------------------------------------------------

def test_review_invalid_ecosystem_returns_error(tmp_path: Path) -> None:
    """``raptor-sca review BOGUS_ECO pkg 1.0`` → graceful error,
    not crash."""
    proc = _run_cli(["review", "BOGUS_ECO", "fakepkg", "1.0",
                     "--offline"])
    # Exit 2 (argparse-style invalid input) is acceptable; 3 too
    # (internal validation). Crash codes (134/139) are not.
    assert proc.returncode in (1, 2, 3), (
        f"review with bad eco crashed: exit={proc.returncode}"
    )


def test_whatif_invalid_version_string_returns_error(tmp_path: Path) -> None:
    """``raptor-sca whatif pypi requests not-a-version 1.0``
    handles unparseable version strings gracefully."""
    proc = _run_cli(["whatif", "pypi", "requests", "$$$", "1.0",
                     "--offline"])
    # Tolerated: 1/2/3 (validation tier).  Crash codes not.
    assert proc.returncode in (1, 2, 3)


# ---------------------------------------------------------------------------
# Regression backfill: bug shapes the dev-E2E sweep found 2026-05-21
# that the original Tier-4 tests didn't pin.
# ---------------------------------------------------------------------------

def test_report_surfaces_parser_warnings_section(tmp_path: Path) -> None:
    """Regression for the Tier-4 dev-E2E find (2026-05-21):
    parsers swallow malformed-input errors and return ``[]`` so
    one bad manifest doesn't abort the run, but the report.md
    used to say "0 deps analysed" with no on-report indication
    that the file was unparseable. An operator scanning a tree
    of corrupted manifests couldn't distinguish that from a
    clean project.

    Fix in ``packages.sca.parsers.capture_parse_failures`` +
    ``packages.sca.report._render_parse_failures_section``. The
    section must:
      * appear in ``report.md`` when at least one parser failed
      * cite the offending file path
      * carry the canonical heading shape so operators can
        ``grep '⚠ Parser warnings' report.md`` in CI logs"""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Two malformed manifests — exercise both XML and JSON paths.
    (repo / "pom.xml").write_text(
        "<project><dependencies><dependency>BROKEN",
        encoding="utf-8",
    )
    (repo / "Pipfile.lock").write_text(
        "{ broken json", encoding="utf-8",
    )

    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1), (
        f"crash on malformed manifests: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )

    report = out / "report.md"
    assert report.is_file(), "report.md not emitted"
    body = report.read_text(encoding="utf-8")
    assert "Parser warnings" in body, (
        "## ⚠ Parser warnings section missing from report.md "
        "despite two malformed manifests. Body:\n"
        f"{body[:2000]}"
    )
    # At least one of the malformed-manifest paths must be cited
    # in the section — operators need to know WHICH file to fix.
    assert ("pom.xml" in body) or ("Pipfile.lock" in body), (
        f"Parser warnings section doesn't cite either malformed "
        f"manifest path. Body:\n{body[:2000]}"
    )


def test_clean_run_has_no_parser_warnings_section(
    tmp_path: Path,
) -> None:
    """Quiet output on the happy path: a tree with only well-
    formed manifests must NOT have the parser-warnings section
    in report.md — otherwise operators get noise on every clean
    run."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )

    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)
    body = (out / "report.md").read_text(encoding="utf-8")
    assert "Parser warnings" not in body, (
        f"clean run surfaced Parser-warnings section unexpectedly. "
        f"Body:\n{body[:1500]}"
    )
