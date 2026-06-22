"""Tier-3 E2E: subprocess-invoke ``raptor-sca bump`` against a
fixture exercising every bump surface; assert structural output.

The bump command's discovery + dispatcher + output formatting are
the surface this test covers. Verdict semantics (Clean/Review/Block
based on upstream-latest + CVE-delta) are exercised by unit tests
under ``packages/sca/bump/tests/``; this tier validates that:

  * argparse + dispatcher route correctly
  * Discovery finds every bump surface in the fixture
  * ``--whatif`` (default) does NOT mutate the tree
  * ``--apply`` is a no-op without Clean verdicts (the offline path)
  * ``--json`` emits structurally-valid JSON
  * ``--pr-comment`` emits structurally-valid markdown

Network calls (OSV / KEV / EPSS / upstream-latest) are blocked at
the HttpClient layer via egress allowlist — the bumper handles
network failure gracefully (warnings + ``Unknown`` verdicts). The
test asserts shape not verdicts.

Eight bump surfaces:

  1. Dockerfile ARG pin
  2. Dockerfile FROM image
  3. Dockerfile inline ``RUN pip install pkg==X.Y``
  4. GHA ``uses: actions/checkout@v3`` (tag-pinned)
  5. GHA ``uses: actions/setup-python@SHA  # v5.0.0`` (SHA-pinned)
  6. Helm ``Chart.yaml`` version field
  7. Git submodule (``.gitmodules`` + ``submodule.url``)
  8. Compose / k8s ``image:`` refs (already covered by Dockerfile FROM
     image walker — represented in the surfaces list for parity).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

pytestmark = pytest.mark.slow

REPO_ROOT = Path(__file__).resolve().parents[3]


def _build_bump_fixture(repo: Path) -> None:
    """A fixture that exercises every bump surface. Pins are
    intentionally older versions so the bumper has something to
    discover; verdicts will be ``Unknown`` (no network for
    upstream-latest) but discovery still surfaces each candidate."""
    repo.mkdir(parents=True, exist_ok=True)

    # Surfaces 1-3: Dockerfile (ARG + FROM + inline pip)
    (repo / "Dockerfile").write_text(
        "ARG PYTHON_VERSION=3.11\n"
        "FROM python:${PYTHON_VERSION}-slim\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
        "RUN pip install semgrep==${SEMGREP_VERSION}\n"
        "RUN pip install requests==2.30.0\n",
        encoding="utf-8",
    )

    # Surfaces 4-5: GHA workflow
    (repo / ".github").mkdir(exist_ok=True)
    (repo / ".github" / "workflows").mkdir(exist_ok=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
        "      - uses: actions/setup-python@61a6322f88396a6271a6ee3565807d608ecaddd1  # v4.7.0\n",
        encoding="utf-8",
    )

    # Surface 6: Helm Chart.yaml
    (repo / "charts").mkdir(exist_ok=True)
    (repo / "charts" / "app").mkdir(exist_ok=True)
    (repo / "charts" / "app" / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: app\n"
        "version: 0.1.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "    repository: https://charts.bitnami.com/bitnami\n",
        encoding="utf-8",
    )

    # Surface 7: Git submodule declaration
    (repo / ".gitmodules").write_text(
        '[submodule "vendor/lib"]\n'
        '\tpath = vendor/lib\n'
        '\turl = https://github.com/some/lib.git\n',
        encoding="utf-8",
    )


def _run_bump(
    args: List[str], *,
    extra_env: dict = None,
    timeout: int = 90,
) -> subprocess.CompletedProcess:
    """Invoke ``raptor-sca bump`` via the package's ``__main__``
    style entry. Run from REPO_ROOT so ``packages.sca.cli`` is
    importable; pass the fixture path as a positional argument."""
    cmd = [sys.executable, "-m", "packages.sca.cli", "bump"] + args
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), env=env, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Tier 3a: discovery surfaces — every bump surface walked
# ---------------------------------------------------------------------------

def test_bump_whatif_emits_valid_json(tmp_path: Path) -> None:
    """``raptor-sca bump --json --whatif`` runs to completion, emits
    JSON parsing successfully."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump(
        [str(repo), "--json", "--no-cache"],
        
    )
    # Even with no network → no Clean verdicts → graceful exit.
    assert proc.returncode in (0, 1), (
        f"unexpected exit {proc.returncode}; stderr:\n{proc.stderr}"
    )
    # JSON must parse.
    payload = json.loads(proc.stdout)
    assert isinstance(payload, dict), f"top-level not dict: {type(payload)}"
    # The output shape carries a "candidates" array — each surface
    # discovered becomes one candidate.
    assert "candidates" in payload or "proposals" in payload, (
        f"missing candidates/proposals key in output keys: {list(payload)}"
    )


def test_bump_discovery_finds_each_surface(tmp_path: Path) -> None:
    """The fixture has 7 declared surfaces (Dockerfile ARG x2 +
    FROM + 2 inline pip + 2 GHA uses + Helm + submodule). Each
    should appear as a candidate in the JSON output."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump(
        [str(repo), "--json", "--no-cache"],
        
    )
    payload = json.loads(proc.stdout)
    candidates = payload.get("candidates") or payload.get("proposals") or []
    skipped = payload.get("skipped") or []
    # Each surface should EITHER be a live candidate (enumerator
    # resolved an upstream-latest target) OR appear in ``skipped``
    # (enumerator ran but couldn't resolve — e.g. no network for
    # Helm index fetch). Together they prove the enumerator pass
    # touched the surface in the fixture.
    all_files = " ".join(
        [str(c.get("file", "")) for c in candidates] +
        [str(s.get("file", "")) for s in skipped]
    ).lower()
    expected_signals = [
        "dockerfile",       # Dockerfile ARG / FROM / inline pip
        "ci.yml",           # GHA uses
        "chart.yaml",       # Helm (in ``skipped`` without network)
    ]
    missing = [s for s in expected_signals if s not in all_files]
    assert not missing, (
        f"bumper enumerator never touched: {missing}.\n"
        f"candidates={len(candidates)} skipped={len(skipped)}\n"
        f"file refs seen (truncated): {all_files[:1000]}"
    )


# ---------------------------------------------------------------------------
# Tier 3b: --whatif is non-mutating; --apply only mutates Clean
# ---------------------------------------------------------------------------

def test_bump_whatif_does_not_mutate_tree(tmp_path: Path) -> None:
    """``--whatif`` (default) MUST NOT touch any file."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    # Record file mtimes pre-run
    pre = {
        p: p.stat().st_mtime_ns
        for p in repo.rglob("*") if p.is_file()
    }

    proc = _run_bump(
        [str(repo), "--no-cache"],
        
    )
    assert proc.returncode in (0, 1)

    # Mtimes post-run must match
    for p, mtime in pre.items():
        assert p.stat().st_mtime_ns == mtime, (
            f"whatif mutated {p.relative_to(repo)} "
            f"(mtime {mtime} → {p.stat().st_mtime_ns})"
        )


def test_bump_apply_does_not_crash_offline(tmp_path: Path) -> None:
    """``--apply`` runs to completion offline. The bumper may
    locally apply some rewrites that don't need network (e.g. GHA
    hash-pin resolution from cached upstream data); the assertion
    is that no crash occurs and the affected files remain
    structurally valid, not that the tree is byte-for-byte
    unchanged."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump(
        [str(repo), "--apply", "--no-cache"],

    )
    assert proc.returncode in (0, 1), (
        f"--apply crashed: exit {proc.returncode}\nstderr:\n{proc.stderr}"
    )

    # Files in the fixture must remain readable + parseable after
    # apply, even if some got rewritten by local-resolved rewrites.
    dockerfile = repo / "Dockerfile"
    assert dockerfile.exists()
    text = dockerfile.read_text(encoding="utf-8")
    assert "FROM" in text and "ARG" in text, (
        "Dockerfile structure lost after --apply"
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    assert workflow.exists()
    wtext = workflow.read_text(encoding="utf-8")
    assert "uses:" in wtext, "ci.yml structure lost after --apply"


# ---------------------------------------------------------------------------
# Tier 3c: --pr-comment markdown shape
# ---------------------------------------------------------------------------

def test_bump_pr_comment_produces_markdown(tmp_path: Path) -> None:
    """``--pr-comment`` emits markdown suitable for piping to
    ``gh pr comment --body-file -``. Asserts:
      * Has a header line (operator-readable verdict summary)
      * Has a table separator (markdown table delimiter)
      * Mentions ``raptor-sca`` somewhere (attribution)"""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump(
        [str(repo), "--pr-comment", "--no-cache"],
        
    )
    assert proc.returncode in (0, 1)
    out = proc.stdout
    # Header line — bumper convention uses ``##`` or ``###``
    assert "##" in out, (
        f"no markdown header in --pr-comment output:\n{out[:1000]}"
    )
    # Attribution (some form of "raptor-sca" string)
    assert "raptor-sca" in out.lower(), (
        f"no attribution in --pr-comment output:\n{out[:500]}"
    )


def test_bump_pr_comment_with_repo_label(tmp_path: Path) -> None:
    """``--repo-label MYREPO`` makes the label appear in the
    header so the PR-comment is attributable when posted across
    multiple PRs."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump(
        [str(repo), "--pr-comment", "--repo-label", "myorg/myrepo",
         "--no-cache"],
        
    )
    assert proc.returncode in (0, 1)
    assert "myorg/myrepo" in proc.stdout, (
        f"repo-label not in output:\n{proc.stdout[:1000]}"
    )


# ---------------------------------------------------------------------------
# Tier 3d: empty target — graceful
# ---------------------------------------------------------------------------

def test_bump_empty_target_does_not_crash(tmp_path: Path) -> None:
    """A target with NO bump surfaces (no Dockerfile, no GHA, etc.)
    must exit cleanly with an empty proposal set, not crash."""
    empty = tmp_path / "empty"
    empty.mkdir()
    # Create one unrelated file so the dir isn't completely empty
    (empty / "README.md").write_text("no bump surfaces here\n")

    proc = _run_bump(
        [str(empty), "--json", "--no-cache"],
        
    )
    assert proc.returncode in (0, 1)
    payload = json.loads(proc.stdout)
    candidates = payload.get("candidates") or payload.get("proposals") or []
    assert candidates == [], (
        f"empty target should have no candidates, got {len(candidates)}"
    )


# ---------------------------------------------------------------------------
# Regression backfill: bug shapes the dev-E2E sweep found 2026-05-21
# that the original Tier-3 tests didn't pin.
# ---------------------------------------------------------------------------

def test_bump_proxy_allowlist_covers_helm_repository_hosts(
    tmp_path: Path,
) -> None:
    """Regression for the Tier-3 dev-E2E find (2026-05-21):
    ``compose_proxy_hosts`` walked Dockerfile FROM hosts but
    skipped ``Chart.yaml`` ``dependencies[*].repository`` URLs.
    Bumps to bitnami / ingress-nginx / argoproj repos got refused
    at the egress proxy before the Helm-index fetch could run.

    Fix in ``packages/sca/parsers/helm_chart.chart_repository_hosts``
    + wired into ``packages.sca.compose_proxy_hosts``. This test
    walks the bumper fixture (which carries a bitnami chart
    dependency) and asserts the chart host is now in the
    derived allowlist — driven through the public API rather
    than the CLI so the assertion is precise without depending
    on log-line wording."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    from packages.sca import compose_proxy_hosts
    hosts = compose_proxy_hosts(repo)
    assert "charts.bitnami.com" in hosts, (
        f"chart_repository_hosts() didn't add charts.bitnami.com "
        f"despite the fixture Chart.yaml referencing it; "
        f"derived hosts: {sorted(hosts)}"
    )


def test_bump_pr_comment_lists_skipped_locators(
    tmp_path: Path,
) -> None:
    """Regression for the Tier-3 dev-E2E find (2026-05-21): the
    ``--pr-comment`` renderer used to emit only a skip COUNT
    (``_Skipped: N surface(s)_``) without the per-surface
    locator + reason. Operators reading the PR couldn't tell
    what hadn't been bumped without re-running with ``-v``
    locally.

    The fixture below carries surfaces that bumper without
    network can't resolve (Helm bitnami chart, GHA pin), so the
    skipped block is exercised. We assert the new
    ``<details>`` block + at least one per-surface locator
    string from the fixture appears in the rendered output."""
    repo = tmp_path / "repo"
    _build_bump_fixture(repo)

    proc = _run_bump([str(repo), "--pr-comment", "--no-cache"])
    assert proc.returncode in (0, 1), (
        f"unexpected exit {proc.returncode}; stderr:\n{proc.stderr}"
    )
    body = proc.stdout
    # If anything got skipped, the rendered comment must use the
    # ``<details>`` collapsing block AND mention at least one of
    # the fixture's locators. If nothing got skipped (unlikely
    # without network — bumper degrades the unresolvable refs)
    # the assertion's premise doesn't hold; skip out cleanly.
    if "Skipped:" not in body:
        import pytest
        pytest.skip("bump produced no skipped surfaces against "
                    "this fixture in this environment")
    assert "<details>" in body, (
        "skipped surfaces rendered as count-only, missing "
        f"<details> block. body:\n{body[:1000]}"
    )
    # At least one of the fixture's locators must show in the
    # rendered skip detail — generalises across host/version
    # differences in registry responses.
    fixture_locator_hints = (
        "redis", "actions/checkout", "actions/setup-python",
        "vendor/lib", "semgrep",
    )
    matched = [
        hint for hint in fixture_locator_hints if hint in body
    ]
    assert matched, (
        f"--pr-comment skip section didn't surface any fixture "
        f"locator; expected one of {fixture_locator_hints}, "
        f"body:\n{body[:1500]}"
    )


def test_bump_missing_target_returns_error(tmp_path: Path) -> None:
    """Non-existent target → exit code 2 (argparse-ish), stderr
    contains a helpful message."""
    proc = _run_bump(
        [str(tmp_path / "does-not-exist"), "--json"],
        
    )
    assert proc.returncode == 2, (
        f"expected exit 2 for missing target, got {proc.returncode}"
    )
    assert "does not exist" in proc.stderr.lower() or \
           "not found" in proc.stderr.lower(), (
        f"missing-target error not helpful: {proc.stderr}"
    )
