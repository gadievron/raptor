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

import subprocess
from pathlib import Path

import pytest


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


@pytest.fixture
def http(monkeypatch):
    """Monkey-patches ``requests.get`` / ``requests.post`` so unit tests
    don't need the ``responses`` library. Pre-2026-05-02 the discovery
    + oracle test files imported ``responses``; with cve-diff trimming
    its test-time deps, this fixture covers the same patterns
    (URL-keyed canned responses, retry sequences, transport-error
    injection, header capture) at zero external cost."""
    from ._http_mock import HttpMock
    return HttpMock(monkeypatch)
