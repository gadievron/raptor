"""Socket-dir hygiene for the in-process dispatcher route.

``shutdown()``/``atexit`` remove the socket dir on normal teardown;
the ownership marker + boot-time sweep in
``ensure_inprocess_dispatcher_env`` reclaim dirs a hard-killed owner
leaves behind.

These tests use :func:`tempfile.gettempdir` as-is (the pytest session
containment already points it at per-session scratch) rather than a
``tmp_path`` override: the dispatcher binds AF_UNIX sockets in its
dir, and a deep per-test path can exceed the sun_path limit.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import LLMDispatcher
from core.run.tmp_ownership import OWNER_MARKER_NAME


@pytest.fixture
def fake_creds() -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fake-key", "openai": None, "gemini": None}
    return creds


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _owned_dir(prefix: str, pid: int) -> Path:
    d = Path(tempfile.gettempdir()) / (
        f"{prefix}{uuid.uuid4().hex[:8]}-fixture"
    )
    d.mkdir()
    (d / OWNER_MARKER_NAME).write_text(
        json.dumps({"pid": pid, "created": time.time()}),
        encoding="utf-8",
    )
    return d


def _inproc_dir(pid: int) -> Path:
    return _owned_dir("raptor-llm-inproc-", pid)


def test_sock_dir_carries_owner_marker(fake_creds):
    d = LLMDispatcher(run_id="inproc-unittest", creds=fake_creds)
    try:
        marker = d._sock_dir / OWNER_MARKER_NAME
        assert marker.is_file()
        data = json.loads(marker.read_text(encoding="utf-8"))
        assert data["pid"] == os.getpid()
    finally:
        d.shutdown()


def test_shutdown_removes_sock_dir_despite_marker(fake_creds):
    d = LLMDispatcher(run_id="inproc-unittest", creds=fake_creds)
    sock_dir = d._sock_dir
    d.shutdown()
    assert not sock_dir.exists()


def test_init_failure_removes_sock_dir_and_marker(
        fake_creds, monkeypatch: pytest.MonkeyPatch):
    def boom(self, run_id):
        raise RuntimeError("bind failed")
    monkeypatch.setattr(LLMDispatcher, "_init_server", boom)
    before = set(Path(tempfile.gettempdir()).glob("raptor-llm-inproc-*"))
    with pytest.raises(RuntimeError):
        LLMDispatcher(run_id="inproc-unittest", creds=fake_creds)
    after = set(Path(tempfile.gettempdir()).glob("raptor-llm-inproc-*"))
    assert after == before


def test_construction_sweeps_dead_owner_run_scoped_dirs(fake_creds):
    """Run-scoped dirs (``raptor-llm-<run_id>-``, dispatcher_for_run's
    prefix) are reclaimed at the next dispatcher construction — not
    only the in-process ``raptor-llm-inproc-`` family. Pre-fix the
    sweep matched the inproc prefix alone, so a hard-killed launcher's
    run-scoped dir waited on the 24 h age-based reaper despite its
    owner marker."""
    dead = _owned_dir("raptor-llm-agentic_20260914-", _dead_pid())
    live = _owned_dir("raptor-llm-agentic_20260915-", os.getpid())
    d = LLMDispatcher(run_id="inproc-unittest", creds=fake_creds)
    try:
        assert not dead.exists()
        assert live.is_dir()
        assert d._sock_dir.is_dir()
    finally:
        d.shutdown()
        shutil.rmtree(live, ignore_errors=True)
        shutil.rmtree(dead, ignore_errors=True)


def test_ensure_inprocess_sweeps_dead_owner_dirs(
        monkeypatch: pytest.MonkeyPatch):
    from core.llm.dispatcher.lifecycle import (
        ensure_inprocess_dispatcher_env,
    )
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)

    dead = _inproc_dir(_dead_pid())
    live = _inproc_dir(os.getpid())

    d = ensure_inprocess_dispatcher_env(label="scratch-test")
    try:
        assert d is not None
        assert not dead.exists()
        assert live.is_dir()
        assert d._sock_dir.is_dir()
    finally:
        # The helper mutates os.environ by design; scrub the route so
        # later tests don't dial a dead dispatcher socket.
        os.environ.pop("RAPTOR_LLM_SOCKET", None)
        os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
        if d is not None:
            d.shutdown()
        shutil.rmtree(live, ignore_errors=True)
        shutil.rmtree(dead, ignore_errors=True)
