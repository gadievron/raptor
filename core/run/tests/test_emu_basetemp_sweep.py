"""Darwin-emulation basetemp roots collapse instead of accreting.

The root conftest mints a per-pid ``raptor-pytest-emu-<pid>`` basetemp
root for emulated sessions. Per-pid roots defeat pytest's keep-last-3
retention (it prunes numbered runs under one SHARED basetemp, never
sibling per-pid roots), and under the launcher they sit outside the
session-TMPDIR the stale-tmp sweep covers — so dead sessions accreted
~25k inodes each, forever. The emulation gate now sweeps dead-pid
sibling roots (keep the 3 newest for post-mortem parity) before
minting its own.

The test drives the REAL ``_apply_platform_emulation`` from the root
conftest against a private tmp root; ``sys.platform`` is restored
afterwards so the emulation patch never leaks into this session.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import types
from pathlib import Path


def _root_conftest():
    # Fresh import of the root conftest module (pytest loads it under
    # a rootdir-derived name); its import-time side effects are
    # idempotent by design (env pinning re-asserts, handoff env var
    # already published by this session).
    import conftest
    return conftest


def _dead_pid() -> int:
    proc = subprocess.Popen(["true"])
    proc.wait(timeout=10)
    return proc.pid


def test_emulation_gate_sweeps_dead_emu_roots(tmp_path, monkeypatch):
    conftest_mod = _root_conftest()
    monkeypatch.setattr(conftest_mod, "_EMULATED_PLATFORM", "darwin")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

    stale = tmp_path / f"raptor-pytest-emu-{_dead_pid()}"
    stale.mkdir()
    (stale / "old-run").mkdir()

    config = types.SimpleNamespace(
        option=types.SimpleNamespace(basetemp=""),
    )
    real_platform = sys.platform
    try:
        conftest_mod._apply_platform_emulation(config)
    finally:
        sys.platform = real_platform

    basetemp = Path(str(config.option.basetemp))
    assert f"raptor-pytest-emu-{os.getpid()}" in str(basetemp)
    assert basetemp.parent.is_dir()  # darwin-shaped intermediates made
    # A single dead sibling sits within the keep=3 post-mortem
    # retention and must be KEPT — the sweep collapses accretion, it
    # is not a delete-everything pass.
    assert stale.is_dir()


def test_emulation_gate_collapses_beyond_the_keep_horizon(
    tmp_path, monkeypatch,
):
    conftest_mod = _root_conftest()
    monkeypatch.setattr(conftest_mod, "_EMULATED_PLATFORM", "darwin")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

    now = time.time()
    dead_roots = []
    for i in range(5):
        d = tmp_path / f"raptor-pytest-emu-{_dead_pid()}"
        d.mkdir()
        os.utime(d, (now - 1000 * (i + 1), now - 1000 * (i + 1)))
        dead_roots.append(d)

    config = types.SimpleNamespace(
        option=types.SimpleNamespace(basetemp=""),
    )
    real_platform = sys.platform
    try:
        conftest_mod._apply_platform_emulation(config)
    finally:
        sys.platform = real_platform

    # Newest 3 dead roots kept (pytest-retention parity), older two
    # collapsed — the unbounded-accretion direction the survey found.
    survivors = [d for d in dead_roots if d.exists()]
    assert survivors == dead_roots[:3]


def test_explicit_basetemp_still_wins(tmp_path, monkeypatch):
    # Per-run flags beat the gate: an operator --basetemp is never
    # replaced, and no sweep runs against it.
    conftest_mod = _root_conftest()
    monkeypatch.setattr(conftest_mod, "_EMULATED_PLATFORM", "darwin")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    explicit = tmp_path / "operator-basetemp"
    config = types.SimpleNamespace(
        option=types.SimpleNamespace(basetemp=str(explicit)),
    )
    real_platform = sys.platform
    try:
        conftest_mod._apply_platform_emulation(config)
    finally:
        sys.platform = real_platform
    assert config.option.basetemp == str(explicit)
