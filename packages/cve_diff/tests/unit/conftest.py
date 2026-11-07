"""Shared fixtures for cve-diff unit tests.

The acquisition layers (and any pipeline test that exercises them) build
hermetic ``file://`` git repos as fixtures. ``core.git.{clone_repository,
fetch_commit}`` enforce a URL allowlist (github.com / gitlab.com only)
and route through the sandbox + egress proxy — neither accepts file://.

The autouse fixture below replaces the layer module's references to
those two functions with plain-subprocess shims for the duration of
each test, keeping the acquisition layer's composition logic under
test while sidestepping the transport's input policy. The substitution
is per-test (pytest's ``monkeypatch`` is function-scoped); ``core.git``
is unaffected.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

# Invocations that cut out the repo-root conftest (``--confcutdir``, a
# vendored copy of this package) skip the session-wide git hermeticity
# pin, so it is re-applied here: this suite's fixture helpers create
# real commits in several per-file ``_git()`` dialects, and the
# operator's environment must not steer them — an exported ``GIT_DIR``
# overrides ``git -C`` discovery and would aim every fixture write at
# an operator-chosen repo (the incident class), and operator config
# (``commit.gpgsign=true``, ``core.hooksPath``, ``url.insteadOf``)
# breaks or instruments the commit/clone shims. Deliberately coarser
# than core.testing.git_hermeticity's curated strip list (which may
# not be importable without the root conftest's sys.path setup): drop
# every ambient GIT_* wholesale — a fixture-building unit suite has no
# legitimate use for any of them — then pin the two config files.
# Keep this scoped to execution: collection must not erase the ambient
# environment before sibling suites can capture or deliberately test it.
@pytest.fixture(autouse=True)
def _isolated_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


# Keep these stubs' signatures in lockstep with
# ``core.git.{clone_repository, fetch_commit}``: if either gains a new
# parameter, the layer module's call site uses it but the stub doesn't,
# and the autouse swap silently drops it. Re-mirror after any core.git
# signature change.


def _test_clone_repository(url: str, target: Path, depth=None) -> bool:
    """Test-only stand-in for ``core.git.clone_repository``."""
    cmd = ["git", "clone", "--quiet"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--no-tags"])
    cmd.extend([url, str(target)])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"git clone failed: {result.stderr.strip() or 'unknown'}",
        )
    return True


def _test_fetch_commit(repo_dir: Path, url: str, sha: str, depth: int = 5) -> bool:
    """Test-only stand-in for ``core.git.fetch_commit``."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    if not (repo_dir / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "init", "--quiet"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git init failed: {result.stderr.strip()}")
    add = subprocess.run(
        ["git", "-C", str(repo_dir), "remote", "add", "origin", url],
        capture_output=True, text=True, timeout=30,
    )
    if add.returncode != 0:
        # already-exists path: rewrite via set-url
        subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "set-url", "origin", url],
            capture_output=True, text=True, timeout=30, check=True,
        )
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "fetch",
         "--depth", str(depth), "--no-tags", "origin", sha],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git fetch failed: {result.stderr.strip() or 'unknown'}",
        )
    return True


@pytest.fixture(autouse=True)
def _bypass_git_sandbox(monkeypatch):
    """Route layer-module calls to plain subprocess so file:// fixtures
    keep working. Per-test scope; no cross-test bleed."""
    from cve_diff.acquisition import layers as layers_mod
    monkeypatch.setattr(layers_mod, "clone_repository", _test_clone_repository)
    monkeypatch.setattr(layers_mod, "fetch_commit", _test_fetch_commit)


@pytest.fixture(autouse=True)
def _no_real_retry_backoff(monkeypatch):
    """Skip client retry delays without changing unrelated clocks.

    Retry counts and error propagation stay real. Tests of backoff itself
    can replace the client's private sleep binding with a recording clock.
    Rate-limit tests continue to use their injected clocks.
    """
    from cve_diff.llm import client
    from core.testing.module_bindings import patch_module_attribute

    patch_module_attribute(monkeypatch, client, "time", "sleep", lambda _s: None)


@pytest.fixture(autouse=True)
def _offline_consensus(monkeypatch):
    """Keep the default-on 2-method consensus offline in unit tests.

    Pipeline.run() executes run_consensus() by default
    (enable_consensus=True), which calls the live OSV and NVD APIs via
    cve_diff.report.consensus._osv_client() / _nvd_client(). CI can't
    reach those hosts, so each request blocks on NvdClient's 30s socket
    timeout (DEFAULT_TIMEOUT_S) — the flat ~30s on the pipeline/CLI
    tests. The _no_real_retry_backoff sleep no-op can't help: a socket
    timeout is not a sleep.

    Stub the two network entry points so run_consensus runs its real
    aggregation logic but resolves to "no pointer" without any HTTP.
    test_report_consensus re-patches these same names inside each test
    body (after this autouse fixture), so those tests are unaffected.
    """
    from cve_diff.report import consensus as consensus_mod

    class _OfflineOsvClient:
        def get_vuln(self, _cve_id):
            return None

    class _OfflineNvdClient:
        def get_payload(self, _cve_id):
            return None

    monkeypatch.setattr(consensus_mod, "_osv_client", lambda: _OfflineOsvClient())
    monkeypatch.setattr(consensus_mod, "_nvd_client", lambda: _OfflineNvdClient())


