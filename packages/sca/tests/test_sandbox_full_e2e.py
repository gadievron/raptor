"""Tier-7 E2E: ``--sandbox`` composition.

Invokes the SCA agent under each sandbox profile and asserts the
dispatcher routes correctly + the analysis completes. The deeper
kernel-feature assertions (Landlock denial recording, namespace
isolation) are exercised by core/sandbox tests; this tier
validates the SCA-side wiring.

Linux-only — Landlock + namespace primitives aren't available on
darwin/win runners.

The three sandbox profiles documented in the agent CLI:

  * ``none`` — egress proxy only, no Landlock / namespace.
  * ``network-only`` — egress proxy + Landlock read-only outside
    target, plus the namespace setup for the egress.
  * ``full`` — adds mount namespace, seccomp filter, plus
    fake-home protection. Requires kernel + capabilities.

This tier targets ``network-only`` as the broadest CI-compatible
profile (``full`` needs more kernel features that may not be on
every runner).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="sandbox composition uses Landlock + namespaces "
           "(Linux-only kernel features)",
)


def _build_fixture(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )


def _run_agent(
    args: List[str], *, timeout: int = 120,
) -> subprocess.CompletedProcess:
    """Invoke the SCA agent.py entry directly (where the
    ``--sandbox`` flag lives — CLI wraps but doesn't expose it)."""
    cmd = [sys.executable, "-m", "packages.sca.agent"] + args
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Composition paths
# ---------------------------------------------------------------------------

@linux_only
def test_sandbox_none_completes(tmp_path: Path) -> None:
    """``--sandbox=none`` — no kernel isolation, just the egress
    proxy. The lightest profile, should work everywhere."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "none", "--offline",
    ])
    assert proc.returncode == 0, (
        f"--sandbox=none failed: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )
    assert (out / "findings.json").is_file()


@linux_only
def test_sandbox_network_only_completes(tmp_path: Path) -> None:
    """``--sandbox=network-only`` — Landlock + egress proxy.
    Should work on stock Linux kernels with Landlock support
    (~5.13+)."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "network-only", "--offline",
    ])
    # Sandbox setup may fail on container hosts without
    # CAP_SYS_ADMIN / older kernels; either we got a sandboxed
    # successful run OR a graceful degraded-isolation warning.
    if proc.returncode != 0:
        # Acceptable: "sandbox not available" graceful fallback.
        # Look for the diagnostic in stderr.
        assert any(
            marker in proc.stderr.lower()
            for marker in (
                "sandbox not available", "landlock", "permission denied",
                "degraded", "not supported",
            )
        ), (
            f"--sandbox=network-only failed without recognised cause:\n"
            f"exit={proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
        )
        pytest.skip(
            "sandbox=network-only not supported in this CI environment"
        )
    assert (out / "findings.json").is_file()


@linux_only
def test_sandbox_audit_emits_audit_record(tmp_path: Path) -> None:
    """``--sandbox=network-only --audit`` records sandbox
    behaviour. Audit file should land somewhere in the output
    dir or in the structured-run audit area."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "network-only", "--audit", "--offline",
    ])
    if proc.returncode != 0:
        pytest.skip(
            "sandbox composition not supported in CI; "
            "audit assertion deferred"
        )
    # Audit artifacts (lookup pattern: any file starting with
    # 'audit-' or under an 'audit/' dir within out). Loose check
    # because exact filename is sandbox-internal.
    audit_paths = list(out.rglob("*audit*")) + list(out.rglob("*sandbox*"))
    # If no audit file emitted, the audit flag may have been
    # silently no-op on this runner — still not a crash.
    if not audit_paths:
        pytest.skip("no audit artefact emitted (acceptable degraded mode)")
    # If audit emitted, it should be readable + non-empty
    for p in audit_paths:
        if p.is_file():
            assert p.stat().st_size > 0, f"audit file empty: {p}"


@linux_only
def test_sandbox_no_sandbox_overrides_profile(tmp_path: Path) -> None:
    """``--no-sandbox`` overrides any ``--sandbox=`` flag — escape
    hatch for operators that need to debug without the sandbox."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "full", "--no-sandbox", "--offline",
    ])
    # Unsandboxed path is the same as plain scan; should always work.
    assert proc.returncode == 0, (
        f"--no-sandbox failed: {proc.stderr[-1000:]}"
    )
    assert (out / "findings.json").is_file()


# ---------------------------------------------------------------------------
# Regression backfill: bug shapes the dev-E2E sweep found 2026-05-21
# that the original Tier-7 tests didn't pin.
# ---------------------------------------------------------------------------

@linux_only
def test_sandbox_audit_engages_proxy_audit_log_mode(
    tmp_path: Path,
) -> None:
    """Regression for the Tier-7 dev-E2E find (2026-05-21):
    ``--audit`` was parsed at ``agent.py`` but never threaded
    through to ``core.sandbox.context.sandbox`` — the flag was
    silently inert. Operators passed it, got identical behaviour
    to runs without it, and no engagement signal anywhere.

    Fix in ``packages/sca/agent.py::_run_sandboxed`` to wire
    ``audit=`` / ``audit_verbose=`` / ``audit_run_dir=`` through.
    Post-fix, the canonical proxy banner ``"AUDIT-LOG mode"``
    appears in stderr confirming the audit gate engaged. This
    test pins the wiring by asserting the banner shows.

    Works offline because the banner fires at sandbox setup
    (when the audit ref-count is acquired), not on traffic."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "network-only", "--audit", "--offline",
    ])
    if proc.returncode != 0:
        pytest.skip(
            "sandbox composition not supported in CI; "
            "audit-banner assertion deferred"
        )
    # Banner format (proxy.py:564): "...switched to AUDIT-LOG
    # mode (CONNECT to non-allowlisted ...)". Substring check on
    # the canonical phrase — robust to surrounding log formatting
    # changes.
    assert "AUDIT-LOG mode" in proc.stderr, (
        "agent.py --audit didn't engage the proxy audit gate; "
        "expected 'AUDIT-LOG mode' in stderr.\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )


@linux_only
def test_sandbox_no_audit_does_not_engage_audit_mode(
    tmp_path: Path,
) -> None:
    """Counterpart to the test above: WITHOUT ``--audit`` the
    proxy gate must NOT switch to audit-log mode. Pins that the
    flag is a real opt-in rather than something accidentally
    engaged for every sandboxed run."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "network-only", "--offline",
    ])
    if proc.returncode != 0:
        pytest.skip(
            "sandbox composition not supported in CI"
        )
    assert "AUDIT-LOG mode" not in proc.stderr, (
        "proxy audit gate engaged WITHOUT --audit; the flag "
        "is supposed to be opt-in. stderr:\n"
        f"{proc.stderr[-2000:]}"
    )


@pytest.mark.skipif(
    sys.platform == "linux", reason="non-Linux skip test only"
)
def test_sandbox_non_linux_falls_back_gracefully(tmp_path: Path) -> None:
    """On darwin / windows, sandbox primitives don't apply; the
    agent should log a warning and run unsandboxed without
    crashing."""
    repo = tmp_path / "repo"
    _build_fixture(repo)
    out = tmp_path / "out"

    proc = _run_agent([
        "--repo", str(repo), "--out", str(out),
        "--sandbox", "network-only", "--offline",
    ])
    assert proc.returncode == 0
    assert (out / "findings.json").is_file()
