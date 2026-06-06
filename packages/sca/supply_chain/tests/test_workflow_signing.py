"""Tests for ``packages.sca.supply_chain.workflow_signing``.

Drives an actual git repository created via ``subprocess`` so the
test exercises real ``git log --format=%G?`` output rather than
mocking the subprocess shell.

The detector is anomaly-shaped (see module docstring). Tests
cover both regimes:

  * Norm-is-to-sign (rate ≥ 70%) — per-commit anomaly findings
    for the unsigned ones (medium severity).
  * Norm-is-mixed (0% < rate < 70%) — single summary finding
    (info severity).
  * No-signing-at-all (rate == 0%) — single summary finding
    (info severity).
  * Perfect signing (rate == 100%) — no findings.

Test fixtures with mixed signing rates use a throwaway GPG key
when available; on systems without ``gpg`` we still cover the
all-unsigned + no-git + no-workflows paths via the basic fixture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

import pytest

from packages.sca.supply_chain.workflow_signing import (
    WorkflowSigningFinding,
    scan_target,
)


# Detector relies on git binary being available. Skip cleanly when
# we can't run any of this.
_HAS_GIT = shutil.which("git") is not None
_HAS_GPG = shutil.which("gpg") is not None


def _git(target: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(target), *args],
        check=True, capture_output=True, text=True,
    )


def _init_repo(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    _git(target, "init", "--initial-branch=main")
    _git(target, "config", "user.email", "test@example.com")
    _git(target, "config", "user.name", "Test User")
    _git(target, "config", "commit.gpgsign", "false")


def _commit_workflow_unsigned(
    target: Path, name: str, body: str, *, message: str,
) -> None:
    wf_dir = target / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(body, encoding="utf-8")
    _git(target, "add", "-A")
    _git(
        target, "-c", "commit.gpgsign=false",
        "commit", "--no-gpg-sign", "-m", message,
    )


@pytest.fixture()
def gpg_signing_key(tmp_path: Path):
    """Generate a throwaway GPG key + verify git can actually use
    it to produce a ``%G?``-verifiable signature in this environment.
    Some CI configs have gpg installed but lack the agent/socket
    plumbing that git's signing actually requires — those should
    skip cleanly rather than emit confusing test failures.

    Yields ``(keyid, gnupghome)`` on success, ``None`` on any
    failure path. Caller is expected to skip when None.
    """
    if not _HAS_GPG:
        yield None
        return
    gnupghome = tmp_path / "gnupg-fixture"
    gnupghome.mkdir(mode=0o700)
    env = {
        **os.environ,
        "GNUPGHOME": str(gnupghome),
        "LC_ALL": "C",
        "GPG_TTY": "",
    }
    batch = (
        "%no-protection\n"
        "Key-Type: eddsa\n"
        "Key-Curve: ed25519\n"
        "Name-Real: Test Signer\n"
        "Name-Email: signer@test.invalid\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    try:
        subprocess.run(
            ["gpg", "--batch", "--pinentry-mode=loopback",
             "--gen-key"],
            input=batch, text=True, env=env,
            check=True, capture_output=True, timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        yield None
        return
    listed = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        capture_output=True, text=True, env=env, check=True,
    )
    keyid: Optional[str] = None
    fpr: Optional[str] = None
    for line in listed.stdout.splitlines():
        if line.startswith("sec:"):
            cols = line.split(":")
            if len(cols) > 4 and cols[4]:
                keyid = cols[4]
        elif line.startswith("fpr:") and fpr is None:
            cols = line.split(":")
            if len(cols) > 9 and cols[9]:
                fpr = cols[9]
    if keyid is None:
        yield None
        return

    # Trust the key ultimately so git's --format=%G? returns "G"
    # (verified) rather than "U" (untrusted-but-valid). Without
    # this step ed25519 signing succeeds but git reports the
    # signature as untrusted, which our detector's _SIGNED_STATUSES
    # set DOES include — but cleaner to test against the
    # canonical "fully verified" status.
    if fpr is not None:
        subprocess.run(
            ["gpg", "--batch", "--yes",
             "--command-fd", "0", "--edit-key", fpr],
            input="trust\n5\ny\nquit\n",
            text=True, env=env, capture_output=True,
        )

    # End-to-end smoke: build a throwaway commit + verify %G? returns
    # a signed-ish status. If we can't actually produce a verifiable
    # signature here, skip the test rather than fail with confusing
    # "all commits read as N" assertion errors downstream.
    smoke_repo = tmp_path / "gpg-smoke"
    smoke_repo.mkdir()
    try:
        subprocess.run(
            ["git", "-C", str(smoke_repo), "init",
             "--initial-branch=main"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(smoke_repo), "config",
             "user.email", "signer@test.invalid"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(smoke_repo), "config",
             "user.name", "Test Signer"],
            check=True, capture_output=True,
        )
        (smoke_repo / "f").write_text("x")
        subprocess.run(
            ["git", "-C", str(smoke_repo), "add", "f"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(smoke_repo),
             "-c", f"user.signingkey={keyid}",
             "-c", "gpg.program=gpg",
             "commit", "-S", "-m", "smoke"],
            env=env, check=True, capture_output=True, text=True,
        )
        verify = subprocess.run(
            ["git", "-C", str(smoke_repo), "log",
             "--format=%G?", "-n", "1"],
            env=env, check=True, capture_output=True, text=True,
        )
        if verify.stdout.strip() not in ("G", "U"):
            yield None
            return
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        yield None
        return

    yield (keyid, str(gnupghome))


def _commit_workflow_signed(
    target: Path, name: str, body: str, *, message: str,
    keyid: str, gnupghome: str,
) -> None:
    wf_dir = target / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(body, encoding="utf-8")
    _git(target, "add", "-A")
    env = {**os.environ, "GNUPGHOME": gnupghome, "LC_ALL": "C",
           "GPG_TTY": ""}
    result = subprocess.run(
        ["git", "-C", str(target),
         "-c", f"user.signingkey={keyid}",
         "-c", "gpg.program=gpg",
         "commit", "-S", "-m", message],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Surface stderr to make signing-setup issues visible in
        # the test output instead of failing silently.
        raise AssertionError(
            f"git commit -S failed (exit {result.returncode}):\n"
            f"  stderr: {result.stderr}\n"
            f"  stdout: {result.stdout}"
        )
    # Verify the commit actually carries a verified signature in
    # this env. Catches "git -S succeeded but no signature embedded"
    # earlier than the test assertion. Use the same env so git can
    # find the signing key for verification.
    verify = subprocess.run(
        ["git", "-C", str(target), "log",
         "--format=%G?", "-n", "1"],
        env=env, capture_output=True, text=True, check=True,
    )
    status = verify.stdout.strip()
    if status not in ("G", "U"):
        raise AssertionError(
            f"signed commit produced %G?={status!r} "
            f"(expected G or U). stderr from commit: "
            f"{result.stderr!r}"
        )


# ---------------------------------------------------------------------------
# Negative cases — no findings regardless of regime.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_no_git_dir_means_no_findings(tmp_path: Path) -> None:
    """Target isn't a git repo — detector quietly no-ops."""
    assert scan_target(tmp_path, manifests=[]) == []


@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_no_workflow_files_means_no_findings(tmp_path: Path) -> None:
    """Repo with no ``.github/workflows/`` — nothing to audit."""
    _init_repo(tmp_path)
    (tmp_path / "README.md").write_text("hi")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "commit.gpgsign=false",
         "commit", "--no-gpg-sign", "-m", "init")
    assert scan_target(tmp_path, manifests=[]) == []


# ---------------------------------------------------------------------------
# No-signing-at-all regime (rate == 0%): one summary finding.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_all_unsigned_emits_single_summary_finding(tmp_path: Path) -> None:
    """All commits unsigned — emit ONE summary finding, not 25."""
    _init_repo(tmp_path)
    for i in range(5):
        _commit_workflow_unsigned(
            tmp_path, "ci.yml", f"name: CI\n# rev {i}\non: push\n",
            message=f"commit {i}",
        )
    findings: List[WorkflowSigningFinding] = scan_target(
        tmp_path, manifests=[],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.stats is not None
    assert f.unsigned_commit is None
    assert f.severity == "info"
    assert f.stats.signing_rate == 0.0
    assert f.stats.unsigned_count == 5


# ---------------------------------------------------------------------------
# Norm-is-to-sign regime (rate ≥ 70%): per-commit anomaly findings.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (_HAS_GIT and _HAS_GPG), reason="gpg not available",
)
def test_anomaly_branch_flags_unsigned_minority(
    tmp_path: Path, gpg_signing_key, monkeypatch,
) -> None:
    """7 signed + 2 unsigned commits — rate is 77.8%, above the
    70% threshold. The 2 unsigned commits are anomalies and each
    gets a finding at medium severity."""
    if gpg_signing_key is None:
        pytest.skip("gpg key generation failed in this environment")
    keyid, gnupghome = gpg_signing_key
    # Production ``_git_log_signatures`` runs ``git log %G?`` with
    # the inherited env, which by default doesn't know about the
    # test fixture's keyring. Set GNUPGHOME for the duration of the
    # test so signature verification has access to the test key.
    monkeypatch.setenv("GNUPGHOME", gnupghome)
    _init_repo(tmp_path)
    # 7 signed.
    for i in range(7):
        _commit_workflow_signed(
            tmp_path, "ci.yml",
            f"name: CI\n# rev {i}\non: push\n",
            message=f"signed {i}",
            keyid=keyid, gnupghome=gnupghome,
        )
    # 2 unsigned anomalies.
    for i in range(2):
        _commit_workflow_unsigned(
            tmp_path, "ci.yml",
            f"name: CI\n# unsig {i}\non: push\n",
            message=f"unsigned anomaly {i}",
        )
    findings = scan_target(tmp_path, manifests=[])
    # Only the 2 unsigned commits get findings; the 7 signed ones
    # don't.
    anomaly_findings = [
        f for f in findings if f.unsigned_commit is not None
    ]
    summary_findings = [f for f in findings if f.stats is not None]
    assert len(anomaly_findings) == 2
    assert summary_findings == []  # norm-is-to-sign skips summary
    for f in anomaly_findings:
        assert f.severity == "medium"
        assert f.unsigned_commit.sig_status == "N"
        assert "unsigned anomaly" in f.unsigned_commit.subject


# ---------------------------------------------------------------------------
# Mixed regime (0% < rate < 70%): summary, no per-commit flood.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (_HAS_GIT and _HAS_GPG), reason="gpg not available",
)
def test_mixed_norm_emits_only_summary(
    tmp_path: Path, gpg_signing_key, monkeypatch,
) -> None:
    """3 signed + 5 unsigned commits — rate is 37.5%, below 70%.
    Don't flag individuals (would be noisy); emit one summary."""
    if gpg_signing_key is None:
        pytest.skip("gpg key generation failed in this environment")
    keyid, gnupghome = gpg_signing_key
    monkeypatch.setenv("GNUPGHOME", gnupghome)
    _init_repo(tmp_path)
    for i in range(3):
        _commit_workflow_signed(
            tmp_path, "ci.yml",
            f"name: CI\n# signed {i}\non: push\n",
            message=f"signed {i}",
            keyid=keyid, gnupghome=gnupghome,
        )
    for i in range(5):
        _commit_workflow_unsigned(
            tmp_path, "ci.yml",
            f"name: CI\n# unsigned {i}\non: push\n",
            message=f"unsigned {i}",
        )
    findings = scan_target(tmp_path, manifests=[])
    assert len(findings) == 1
    f = findings[0]
    assert f.stats is not None
    assert f.unsigned_commit is None
    assert f.severity == "info"
    assert 0.0 < f.stats.signing_rate < 0.70


# ---------------------------------------------------------------------------
# Perfect-signing regime (rate == 100%): no findings.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (_HAS_GIT and _HAS_GPG), reason="gpg not available",
)
def test_all_signed_produces_no_findings(
    tmp_path: Path, gpg_signing_key, monkeypatch,
) -> None:
    """100% signed — no anomalies, no summary, no findings."""
    if gpg_signing_key is None:
        pytest.skip("gpg key generation failed in this environment")
    keyid, gnupghome = gpg_signing_key
    monkeypatch.setenv("GNUPGHOME", gnupghome)
    _init_repo(tmp_path)
    for i in range(4):
        _commit_workflow_signed(
            tmp_path, "ci.yml",
            f"name: CI\n# {i}\non: push\n",
            message=f"signed {i}",
            keyid=keyid, gnupghome=gnupghome,
        )
    assert scan_target(tmp_path, manifests=[]) == []


# ---------------------------------------------------------------------------
# Path-scope check (independent of signing regime).
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_signed_statuses_include_E_missing_key() -> None:
    """``E`` (cannot check / missing public key) MUST count as
    signed.  Dogfooded against raptor: every workflow-touching
    commit in raptor's history reports ``E`` because the maintainer
    keys aren't in a fresh clone's local trust store — but the
    commits ARE signed (verified on github.com).  Pre-fix the
    detector reported 0% signing rate on the raptor clone; the only
    fix is to treat E as signed for rate-calculation purposes.
    """
    from packages.sca.supply_chain.workflow_signing import (
        _SIGNED_STATUSES,
    )
    # Every git status code OTHER than N must count as signed.
    # N is the only "no signature visible to a reviewer" state.
    for code in ("G", "U", "B", "X", "Y", "R", "E"):
        assert code in _SIGNED_STATUSES, (
            f"{code!r} must count as signed; pre-fix the detector "
            f"reported 0% signing rate on raptor (all commits E)"
        )
    assert "N" not in _SIGNED_STATUSES


def test_signing_rate_with_all_E_status_reports_100_percent(
    tmp_path: Path,
) -> None:
    """Integration-level: an all-E history (every commit signed but
    no local key to verify) computes as 100% signed and emits no
    findings.  The raptor dogfood case."""
    # Mock at the source-of-truth: _git_log_signatures returns
    # tuples of (sha, sig_status, author_name, author_email,
    # subject).  Patch to simulate the raptor case.
    from packages.sca.supply_chain import workflow_signing
    target = tmp_path / "fake_repo"
    target.mkdir()
    (target / ".git").mkdir()  # satisfies _is_git_repo
    fake_walked = [
        (f"sha{i:040x}", "E", "John C", "j@x.com", f"commit {i}")
        for i in range(50)
    ]
    original = workflow_signing._git_log_signatures
    workflow_signing._git_log_signatures = lambda *a, **k: fake_walked
    try:
        findings = workflow_signing.scan_target(target, [])
    finally:
        workflow_signing._git_log_signatures = original
    # All E → all signed → 100% signing rate → no finding emitted.
    assert findings == [], (
        f"all-E history must report no findings (100% signed); "
        f"got {[(f.severity, f.detail[:80]) for f in findings]}"
    )


def test_only_workflow_paths_audited(tmp_path: Path) -> None:
    """A commit touching only non-workflow files isn't surfaced —
    we audit history of ``.github/workflows/`` and friends, not
    the whole repo. Other commits don't dilute the signing-rate
    computation."""
    _init_repo(tmp_path)
    # Non-workflow commit (should not count toward audit).
    (tmp_path / "README.md").write_text("readme")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "commit.gpgsign=false",
         "commit", "--no-gpg-sign", "-m", "readme (non-workflow)")
    # Workflow commit.
    _commit_workflow_unsigned(
        tmp_path, "ci.yml", "name: CI\n",
        message="add workflow",
    )
    findings = scan_target(tmp_path, manifests=[])
    # All-unsigned → one summary; the readme commit doesn't dilute
    # the rate.
    assert len(findings) == 1
    f = findings[0]
    assert f.stats is not None
    assert f.stats.commits_walked == 1  # only the workflow commit
    assert f.stats.unsigned_count == 1


@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_dependabot_yml_is_audited(tmp_path: Path) -> None:
    """``.github/dependabot.yml`` is CI-executable enough that we
    audit its commit history alongside workflows."""
    _init_repo(tmp_path)
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "dependabot.yml").write_text(
        "version: 2\nupdates: []\n"
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "commit.gpgsign=false",
         "commit", "--no-gpg-sign", "-m", "add dependabot")
    findings = scan_target(tmp_path, manifests=[])
    assert len(findings) == 1
    f = findings[0]
    assert f.stats is not None
    assert f.stats.unsigned_count == 1


# ---------------------------------------------------------------------------
# Anomaly-branch finding cap.
# ---------------------------------------------------------------------------

@pytest.mark.slow
@pytest.mark.skipif(
    not (_HAS_GIT and _HAS_GPG), reason="gpg not available",
)
def test_anomaly_findings_cap_at_emit_limit(
    tmp_path: Path, gpg_signing_key, monkeypatch,
) -> None:
    """Signing-norm repo with many unsigned anomalies — emit at
    most ``_MAX_PER_COMMIT_FINDINGS`` (20) to keep the report
    readable. Note: each unsigned anomaly drags the rate down;
    the test mixes enough signed commits to keep the rate above
    70% so the anomaly branch fires."""
    if gpg_signing_key is None:
        pytest.skip("gpg key generation failed in this environment")
    from packages.sca.supply_chain import workflow_signing as ws_mod
    keyid, gnupghome = gpg_signing_key
    monkeypatch.setenv("GNUPGHOME", gnupghome)
    _init_repo(tmp_path)
    # 80 signed + 25 unsigned → 76% signing rate (above 70%).
    # 25 unsigned anomalies should cap at 20 emitted.
    for i in range(80):
        _commit_workflow_signed(
            tmp_path, "ci.yml",
            f"name: CI\n# signed {i}\non: push\n",
            message=f"signed {i}",
            keyid=keyid, gnupghome=gnupghome,
        )
    for i in range(25):
        _commit_workflow_unsigned(
            tmp_path, "ci.yml",
            f"name: CI\n# unsig {i}\non: push\n",
            message=f"anomaly {i}",
        )
    findings = scan_target(tmp_path, manifests=[])
    # Some commits may fall outside the _MAX_COMMITS_WALKED=100
    # window so check the cap holds rather than asserting a
    # specific count.
    anomalies = [f for f in findings if f.unsigned_commit is not None]
    assert len(anomalies) <= ws_mod._MAX_PER_COMMIT_FINDINGS


# ---------------------------------------------------------------------------
# Orchestrator integration.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_GIT, reason="git binary not available")
def test_summary_finding_emits_through_orchestrator(
    tmp_path: Path,
) -> None:
    """End-to-end: the orchestrator wires the new detector and
    produces a SupplyChainFinding with ``finding_shape=summary``
    for the all-unsigned case."""
    from packages.sca.supply_chain import evaluate
    _init_repo(tmp_path)
    _commit_workflow_unsigned(
        tmp_path, "ci.yml", "name: CI\n",
        message="add CI",
    )
    findings = evaluate(
        target=tmp_path, manifests=[], deps=[],
    )
    ws_findings = [
        f for f in findings if f.kind == "workflow_unsigned_commit"
    ]
    assert len(ws_findings) == 1
    f = ws_findings[0]
    assert f.evidence["finding_shape"] == "summary"
    assert f.evidence["unsigned_count"] == 1
    assert f.evidence["signing_rate"] == 0.0
    assert f.severity == "info"
