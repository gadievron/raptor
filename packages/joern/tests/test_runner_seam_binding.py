"""Unit contract of the thread-pinned sandbox-runner seam.

``bound_sandbox_runner`` pins a resolved runner for the CURRENT
thread so work handed to a background thread keeps its submitter's
spawn seam; ``_default_sandbox_runner`` prefers that pin over live
``core.sandbox.run`` resolution, per thread, restore-on-exit.
"""

from __future__ import annotations

import threading

import pytest

import core.sandbox
from packages.joern.runner import (
    _default_sandbox_runner,
    bound_sandbox_runner,
    resolve_sandbox_runner,
)


def _sentinel_runner(argv, **kwargs):  # pragma: no cover — never spawned
    raise AssertionError("sentinel runner must not be invoked")


class TestBoundSandboxRunner:
    def test_pin_wins_over_a_live_global_patch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real_run = core.sandbox.run
        with bound_sandbox_runner(real_run):
            monkeypatch.setattr(core.sandbox, "run", _sentinel_runner)
            assert _default_sandbox_runner() is real_run
        # Pin gone: live resolution sees the (still-patched) global.
        assert _default_sandbox_runner() is _sentinel_runner

    def test_nesting_restores_the_outer_pin(self) -> None:
        outer = object()
        inner = object()
        with bound_sandbox_runner(outer):
            with bound_sandbox_runner(inner):
                assert _default_sandbox_runner() is inner
            assert _default_sandbox_runner() is outer

    def test_pin_restored_when_the_body_raises(self) -> None:
        real_run = core.sandbox.run
        with pytest.raises(RuntimeError):
            with bound_sandbox_runner(_sentinel_runner):
                raise RuntimeError("body failure")
        assert _default_sandbox_runner() is real_run

    def test_pin_is_thread_local(self) -> None:
        real_run = core.sandbox.run
        seen: dict[str, object] = {}
        pinned = threading.Event()
        done = threading.Event()

        def other_thread() -> None:
            assert pinned.wait(timeout=30)
            seen["runner"] = _default_sandbox_runner()
            done.set()

        t = threading.Thread(target=other_thread, daemon=True)
        t.start()
        with bound_sandbox_runner(_sentinel_runner):
            pinned.set()
            assert done.wait(timeout=30)
        t.join(timeout=30)
        assert seen["runner"] is real_run


class TestResolveSandboxRunner:
    def test_resolves_the_current_live_seam(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Submit-time capture is deliberate: it returns whatever the
        default seam resolves NOW — the submitter's context, patched
        or not — so a caller pinning it hands the worker exactly the
        submitter's view."""
        assert resolve_sandbox_runner() is core.sandbox.run
        monkeypatch.setattr(core.sandbox, "run", _sentinel_runner)
        assert resolve_sandbox_runner() is _sentinel_runner
