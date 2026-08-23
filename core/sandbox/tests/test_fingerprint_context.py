"""Tests for the context.py public-API integration of fingerprint
sanitisation: opt-in kwarg threading, degradation behaviour,
require_sanitisation hard-fail, per-call kwarg rejection.

These tests do NOT exercise the full mount-ns spawn path (covered by
test_fingerprint_e2e.py) — they focus on context.py's bookkeeping
around the persona lifecycle and the public API surface.
"""

from __future__ import annotations

import logging
import sys
import tempfile

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="fingerprint context tests target the Linux substrate",
)


def test_cpu_count_without_master_switch_logs_warning(caplog):
    """Passing cpu_count without sanitise_host_fingerprint=True should
    warn the caller — silently engaging the CPU mask without the rest
    of the persona would be inconsistent and confusing."""
    from core.sandbox import sandbox
    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        with tempfile.TemporaryDirectory() as tmp:
            with sandbox(target=tmp, output=tmp, cpu_count=4):
                pass
    assert any(
        "cpu_count=4 ignored" in rec.message for rec in caplog.records
    ), [rec.message for rec in caplog.records]


def test_sanitise_kwarg_rejected_on_inner_run():
    """sanitise_host_fingerprint is sandbox-context-level. Passing it to
    sandbox().run() must raise TypeError (same as block_network=, etc.).
    """
    from core.sandbox import sandbox
    with tempfile.TemporaryDirectory() as tmp:
        with sandbox(target=tmp, output=tmp) as run:
            with pytest.raises(TypeError, match="sanitise_host_fingerprint"):
                run(["true"], sanitise_host_fingerprint=True)


def test_cpu_count_rejected_on_inner_run():
    from core.sandbox import sandbox
    with tempfile.TemporaryDirectory() as tmp:
        with sandbox(target=tmp, output=tmp) as run:
            with pytest.raises(TypeError, match="cpu_count"):
                run(["true"], cpu_count=4)


def test_require_sanitisation_rejected_on_inner_run():
    from core.sandbox import sandbox
    with tempfile.TemporaryDirectory() as tmp:
        with sandbox(target=tmp, output=tmp) as run:
            with pytest.raises(TypeError, match="require_sanitisation"):
                run(["true"], require_sanitisation=True)


def test_require_sanitisation_raises_when_unsupported(monkeypatch):
    """If require_sanitisation=True and mount-ns is unavailable, the
    sandbox() context must raise RuntimeError at entry. Operators who
    explicitly require sanitisation prefer a hard fail over silent
    degradation."""
    from core.sandbox import sandbox
    # Force mount_ns_available() to return False regardless of host.
    import core.sandbox._spawn as _sp
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: False)
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(RuntimeError, match="require_sanitisation=True"):
            with sandbox(target=tmp, output=tmp,
                         sanitise_host_fingerprint=True,
                         require_sanitisation=True):
                pass


def test_unsupported_soft_degrades_with_warning(monkeypatch, caplog):
    """Without require_sanitisation, an unsupported environment should
    log a WARNING but not raise — sandbox continues without the persona,
    identity surfaces remain host-real."""
    from core.sandbox import sandbox
    import core.sandbox._spawn as _sp
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: False)
    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        with tempfile.TemporaryDirectory() as tmp:
            with sandbox(target=tmp, output=tmp,
                         sanitise_host_fingerprint=True) as _run:
                pass
    assert any(
        "sanitise_host_fingerprint" in rec.message
        and "host-real" in rec.message
        for rec in caplog.records
    ), [rec.message for rec in caplog.records]


def test_sanitise_without_target_or_output_soft_degrades(monkeypatch, caplog):
    """sandbox() with sanitise_host_fingerprint=True but neither
    target nor output set: mount-ns gets skipped by _spawn (its gate
    is `if target or output`), so file overlays can't apply. Must
    soft-degrade with a clear warning rather than silently producing
    half-coverage (UTS + affinity engage; file overlays don't)."""
    from core.sandbox import sandbox
    import core.sandbox._spawn as _sp
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        with sandbox(sanitise_host_fingerprint=True) as _run:
            pass
    assert any(
        "no target/output" in rec.message for rec in caplog.records
    ), [rec.message for rec in caplog.records]


def test_sanitise_without_target_or_output_hard_fails_when_required(monkeypatch):
    """require_sanitisation=True must hard-fail on the no-target/output
    corner case too — not just on platform / mount-ns unavailability."""
    from core.sandbox import sandbox
    import core.sandbox._spawn as _sp
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    with pytest.raises(RuntimeError, match="require_sanitisation=True"):
        with sandbox(sanitise_host_fingerprint=True,
                     require_sanitisation=True):
            pass


def test_top_level_run_forwards_kwargs_to_sandbox():
    """The standalone run() must forward sanitise/cpu_count/require
    kwargs through to its inner sandbox() — otherwise callers of
    run(sanitise_host_fingerprint=True) get nothing. We can't easily
    test the full sandbox-spawn path here (depends on host
    capabilities); instead, drive require_sanitisation=True against
    a forced-False mount-ns and assert run() propagates the
    resulting RuntimeError."""
    import tempfile as _tf
    from core.sandbox import run as _run
    with pytest.raises(RuntimeError, match="require_sanitisation=True"):
        with _tf.TemporaryDirectory() as t:
            # mount_ns will report unavailable -> hard-fail propagates
            # from sandbox() through run()'s `with sandbox(...) as _r`.
            # We don't monkeypatch mount_ns_available here so the test
            # is portable across hosts.
            from unittest.mock import patch
            with patch("core.sandbox._spawn.mount_ns_available",
                       return_value=False):
                _run(["true"], target=t, output=t,
                     sanitise_host_fingerprint=True,
                     require_sanitisation=True)


def test_apply_overlay_strict_missing_target_raises(tmp_path):
    """require_sanitisation rides on the persona: a missing overlay
    target must ABORT setup instead of skip-and-continue — a
    fail-closed persona request silently running with host-real
    /proc/cpuinfo is exactly the half-state the flag forbids."""
    from core.sandbox.fingerprint import Persona, apply_overlay
    src = tmp_path / "cpuinfo"
    src.write_text("persona-cpuinfo")
    root = tmp_path / "root"
    root.mkdir()
    persona = Persona(files={"/proc/cpuinfo": str(src)},
                      cpu_count=2, strict=True)
    with pytest.raises(OSError, match="require_sanitisation"):
        apply_overlay(persona, root_prefix=str(root))


def test_apply_overlay_strict_bind_failure_raises(tmp_path, monkeypatch):
    from core.sandbox import fingerprint as fp
    from core.sandbox import mount_ns as mns
    src = tmp_path / "cpuinfo"
    src.write_text("persona-cpuinfo")
    root = tmp_path / "root" / "proc"
    root.mkdir(parents=True)
    (root / "cpuinfo").write_text("host")

    def _bind_fails(*a, **k):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(mns, "_mount", _bind_fails)
    persona = fp.Persona(files={"/proc/cpuinfo": str(src)},
                         cpu_count=2, strict=True)
    with pytest.raises(OSError, match="require_sanitisation"):
        fp.apply_overlay(persona, root_prefix=str(tmp_path / "root"))


def test_apply_overlay_nonstrict_keeps_partial_coverage(tmp_path):
    """The default posture is unchanged: missing targets skip with a
    debug log (partial coverage beats none)."""
    from core.sandbox.fingerprint import Persona, apply_overlay
    src = tmp_path / "cpuinfo"
    src.write_text("persona-cpuinfo")
    root = tmp_path / "root"
    root.mkdir()
    persona = Persona(files={"/proc/cpuinfo": str(src)}, cpu_count=2)
    apply_overlay(persona, root_prefix=str(root))  # must not raise


def test_required_sanitisation_refuses_landlock_degrade(
        monkeypatch, tmp_path):
    """A mount-ns setup failure ('M' status — where a strict
    per-overlay failure lands) must raise under require_sanitisation
    instead of degrading to the Landlock-only retry, which cannot
    apply the persona at all."""
    import subprocess

    import core.sandbox._spawn as _sp
    import core.sandbox.context as ctx
    import core.sandbox.fingerprint as _fp
    from core.sandbox.errors import SandboxSetupError

    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_fp, "is_supported", lambda: True)
    monkeypatch.setattr(ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(ctx, "check_mount_available", lambda: True)

    def _fake_run_sandboxed(cmd, **_kw):
        cp = subprocess.CompletedProcess(
            args=list(cmd), returncode=126, stdout="", stderr="")
        cp._setup_status = (
            "M", "fingerprint overlay bind failed under "
                 "require_sanitisation")
        return cp

    monkeypatch.setattr(_sp, "run_sandboxed", _fake_run_sandboxed)
    with pytest.raises(SandboxSetupError,
                       match="require_sanitisation"):
        with ctx.sandbox(target=str(tmp_path), output=str(tmp_path),
                         sanitise_host_fingerprint=True,
                         require_sanitisation=True) as _run:
            _run(["/bin/true"])


def _required_sanitisation_ctx(monkeypatch, tmp_path):
    """Common monkeypatch set for the pre-spawn demotion gates: the
    mount-ns backend reports available (so the context-entry gate
    passes) and the persona builds for real."""
    import core.sandbox._spawn as _sp
    import core.sandbox.context as ctx
    import core.sandbox.fingerprint as _fp

    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_fp, "is_supported", lambda: True)
    monkeypatch.setattr(ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(ctx, "check_mount_available", lambda: True)
    return ctx


def test_required_sanitisation_refuses_input_kwarg_demotion(
        monkeypatch, tmp_path):
    """input= routes the call to the Landlock-only subprocess path
    (spawn_eligible=False), where the persona never applies — a
    require_sanitisation caller must get a refusal, not a silent
    host-real run."""
    ctx = _required_sanitisation_ctx(monkeypatch, tmp_path)
    from core.sandbox.errors import SandboxSetupError
    with pytest.raises(SandboxSetupError,
                       match="require_sanitisation"):
        with ctx.sandbox(target=str(tmp_path), output=str(tmp_path),
                         sanitise_host_fingerprint=True,
                         require_sanitisation=True) as _run:
            _run(["/bin/cat"], input=b"host-real?")


def test_required_sanitisation_refuses_speculative_cache_demotion(
        monkeypatch, tmp_path):
    """A speculative-failure-cache hit (poisonable by an earlier
    NON-strict failure of the same binary in this process) silently
    skipped mount-ns — and the persona with it."""
    import os

    from core.sandbox import state as sbx_state

    ctx = _required_sanitisation_ctx(monkeypatch, tmp_path)
    from core.sandbox.errors import SandboxSetupError
    import shutil as _shutil
    _resolved = _shutil.which("true") or "/usr/bin/true"
    monkeypatch.setitem(
        sbx_state._speculative_failure_cache, _resolved, True)
    monkeypatch.setitem(
        sbx_state._speculative_failure_cache,
        os.path.realpath(_resolved), True)
    with pytest.raises(SandboxSetupError,
                       match="require_sanitisation"):
        with ctx.sandbox(target=str(tmp_path), output=str(tmp_path),
                         sanitise_host_fingerprint=True,
                         require_sanitisation=True) as _run:
            _run(["true"])


def test_persona_tmpdir_cleaned_up_on_exit(monkeypatch):
    """The tmpdir created for persona files in sandbox() must be
    removed on context exit. Catches a class of bug where a long-lived
    parent process accumulates /tmp/raptor-persona-* over many runs."""
    import os
    from core.sandbox import sandbox

    # Need mount_ns to be reported available for the persona to be built.
    # On a CI host without uidmap this would otherwise short-circuit.
    import core.sandbox._spawn as _sp
    import core.sandbox.fingerprint as _fp
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_fp, "is_supported", lambda: True)

    seen_dirs = []
    real_mkdtemp = tempfile.mkdtemp

    def _track_mkdtemp(*args, **kw):
        d = real_mkdtemp(*args, **kw)
        # Capture both positional and keyword prefix forms — Python's
        # own TemporaryDirectory calls mkdtemp(suffix, prefix, dir)
        # positionally, so a kw-only matcher would miss it.
        prefix = kw.get("prefix")
        if prefix is None and len(args) >= 2:
            prefix = args[1]
        if prefix and str(prefix).startswith("raptor-persona-"):
            seen_dirs.append(d)
        return d

    monkeypatch.setattr(tempfile, "mkdtemp", _track_mkdtemp)

    with tempfile.TemporaryDirectory() as tmp:
        try:
            with sandbox(target=tmp, output=tmp,
                         sanitise_host_fingerprint=True) as _run:
                # We don't actually spawn — mount_ns_available was
                # monkeypatched, so an actual run() would fall back to
                # the Landlock-only path. We just verify the persona
                # tmpdir got created.
                assert len(seen_dirs) == 1, (
                    f"expected one persona tmpdir, got {seen_dirs}"
                )
                assert os.path.isdir(seen_dirs[0]), seen_dirs[0]
        finally:
            pass
    # After context exit, the tmpdir must be gone.
    for d in seen_dirs:
        assert not os.path.exists(d), (
            f"persona tmpdir leaked: {d} still exists after sandbox exit"
        )
