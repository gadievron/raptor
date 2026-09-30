"""The presweep worker's sandbox runner is pinned at submit time.

``resolve_joern_evidence`` hands the CPG presweep to a background
thread that outlives its caller. The spawn seam (``core.sandbox.run``)
is re-resolved lazily by ``packages.joern.runner``, so an unpinned
worker picks up whatever is globally live at each SPAWN instant —
including a transient process-wide patch installed by unrelated code
running later in the same process (test fixtures monkeypatch that
seam). These tests pin the submit-time contract: the worker's default
runner is the one resolved when the work was submitted, immune to
patches that become live afterwards.
"""

from __future__ import annotations

import threading

import pytest

import core.audit.joern_backend as jb
import core.sandbox


class TestPresweepRunnerPinnedAtSubmit:
    def _gate_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(jb, "joern_available", lambda overrides=None: True)
        monkeypatch.setattr(jb, "target_has_c_sources", lambda p: True)

    def test_patch_live_after_submit_never_steers_the_worker(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path,
    ) -> None:
        """A ``core.sandbox.run`` patch installed AFTER submission is
        invisible to the worker's default-runner resolution."""
        self._gate_open(monkeypatch)
        real_run = core.sandbox.run

        entered = threading.Event()
        patch_installed = threading.Event()
        resolved: dict[str, object] = {}

        def fake_build(target_path, out_dir, joern_overrides,
                       on_progress, joern_server, abort_check=None,
                       deadline_monotonic=None, scope_exclude_dirs=()):
            # Worker side: wait until the patch window is live, then
            # resolve the runner exactly as a spawn lane would.
            entered.set()
            assert patch_installed.wait(timeout=30)
            from packages.joern.runner import _default_sandbox_runner
            resolved["runner"] = _default_sandbox_runner()
            return None

        monkeypatch.setattr(jb, "build_joern_evidence", fake_build)

        _flows, future = jb.resolve_joern_evidence(str(tmp_path))
        assert future is not None
        assert entered.wait(timeout=30)

        def swallowing_fake(argv, **kwargs):  # pragma: no cover — must not run
            raise AssertionError("patched fake must never be resolved")

        monkeypatch.setattr(core.sandbox, "run", swallowing_fake)
        patch_installed.set()
        try:
            assert future.result(timeout=30) is None
        finally:
            # The worker is done before monkeypatch teardown restores
            # the seam — nothing outlives this test.
            patch_installed.set()

        assert resolved["runner"] is real_run

    def test_resolution_failure_keeps_its_lazy_surface(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path,
    ) -> None:
        """When submit-time resolution raises, submission still
        succeeds and the worker resolves lazily (the original
        fail-closed surface: the future carries any error)."""
        self._gate_open(monkeypatch)

        from packages.joern import runner as jr

        def boom():
            raise RuntimeError("sandbox unavailable at submit")

        monkeypatch.setattr(jr, "resolve_sandbox_runner", boom)

        resolved: dict[str, object] = {}

        def fake_build(target_path, out_dir, joern_overrides,
                       on_progress, joern_server, abort_check=None,
                       deadline_monotonic=None, scope_exclude_dirs=()):
            resolved["runner"] = jr._default_sandbox_runner()
            return None

        monkeypatch.setattr(jb, "build_joern_evidence", fake_build)

        _flows, future = jb.resolve_joern_evidence(str(tmp_path))
        assert future is not None
        assert future.result(timeout=30) is None
        # No pin: the worker fell back to live resolution.
        assert resolved["runner"] is core.sandbox.run
