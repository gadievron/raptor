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


@pytest.fixture(autouse=True)
def _no_real_retry_backoff(monkeypatch):
    """No-op ``time.sleep`` for unit tests.

    ResilientLLMClient (``llm/client.py``) retries with
    ``time.sleep(backoff_factor ** attempt)`` and AgentLoop adds an
    in-loop 0/5/15s backoff. Tests that drive the retry path with a
    mocked-failing provider otherwise sit through the REAL backoff —
    measured at 14s for ``test_provider_error_raises_llm_call_failed``
    and ~9-11s each for the pipeline retry tests on the 2-core CI
    runner (they were the entire cve_diff tier's wall-clock). The retry
    COUNT and error-propagation behaviour is independent of how long
    the backoff sleeps, so no-op the sleep.

    Safe across the unit tree: the only timing-sensitive tests
    (``infra/test_rate_limit.py``) drive an INJECTED fake clock
    (``clk.sleep``), not the global ``time.sleep``, so their assertions
    are unaffected.
    """
    import time
    monkeypatch.setattr(time, "sleep", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _no_retry_backoff_sleep(monkeypatch):
    """Neutralise the LLM client's retry backoff for unit tests.

    cve_diff/llm/client.py retries a failed provider.generate with
    time.sleep(backoff_factor ** attempt) (factor 2.0 -> 2+4+8s...). Any
    test that drives the pipeline into retries or the meta-retry path
    otherwise pays real backoff seconds -- the dominant cost behind the
    slow cve_diff pipeline tests. No-op the sleep: retry *logic* is
    unchanged, only the wall-clock delay is removed. The infra rate-limit
    tests inject their own fake clock, so they are unaffected by this
    global patch.
    """
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)


