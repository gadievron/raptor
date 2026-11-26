"""``_git`` environment hygiene and never-raise contract when
``core.config`` cannot import (degraded/partial install).

Two properties, both load-bearing for probes against SCANNED (hostile)
targets:

* the git child's environment must fail CLOSED — the minimal
  allowlist from ``safe_subprocess_env``, never a wholesale
  ``os.environ`` copy carrying credentials and injection vectors;
* the untrusted leg must honour ``_git``'s "never raises" contract —
  ``core.git.clone`` imports ``core.config`` at module top, so the
  same failure the env chokepoint survives must degrade the probe to
  ``None``, not propagate.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import core.run.provenance as provenance
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def broken_core_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate a degraded install where ``import core.config`` fails.

    ``None`` in ``sys.modules`` makes every fresh ``from core.config
    import …`` raise ImportError. ``core.git.clone`` is evicted so the
    untrusted leg's import re-executes (and so fails) instead of
    serving the cached module object.
    """
    monkeypatch.setitem(sys.modules, "core.config", None)
    monkeypatch.delitem(sys.modules, "core.git.clone", raising=False)


def test_git_env_fails_closed_on_config_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    broken_core_config: None,
) -> None:
    monkeypatch.setenv("FAKE_CRED_API_KEY", "sentinel-cred")
    monkeypatch.setenv("GIT_SEQUENCE_EDITOR", "sentinel-editor")
    captured: dict[str, dict[str, str] | None] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        captured["env"] = kwargs.get("env")  # type: ignore[assignment]
        return subprocess.CompletedProcess(cmd, 0, stdout="deadbeef\n", stderr="")

    patch_module_attribute(monkeypatch, provenance, "subprocess", "run", fake_run)
    assert provenance._git(tmp_path, "rev-parse", "HEAD") == "deadbeef"
    env = captured["env"]
    assert env is not None, "a sanitised env mapping must always be passed"
    # Fail-closed means the minimal allowlist — the parent env's
    # credential-shaped and git-behaviour vars must never reach the child.
    assert "FAKE_CRED_API_KEY" not in env
    assert "GIT_SEQUENCE_EDITOR" not in env


def test_git_untrusted_never_raises_on_config_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    broken_core_config: None,
) -> None:
    def refuse_spawn(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        raise AssertionError(
            "no git child may spawn against an untrusted repo without "
            "the safe per-invocation overrides"
        )

    patch_module_attribute(monkeypatch, provenance, "subprocess", "run", refuse_spawn)
    # "Never raises — provenance capture must not be able to break a
    # run": the probe degrades to None instead of propagating the
    # ImportError out of the untrusted leg.
    assert provenance._git(tmp_path, "rev-parse", "HEAD", untrusted=True) is None
