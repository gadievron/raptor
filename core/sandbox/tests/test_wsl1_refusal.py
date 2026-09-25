"""WSL1 refusal at the checked-dispatch chokepoint.

WSL1 emulates Linux syscalls on the NT kernel — no namespaces, no
Landlock, no seccomp. There is no containment tier to deliver and
nothing to degrade to, so a sandbox-shaped call would run effectively
bare behind warnings tuned for partial degradation. The dispatch
chokepoint (the same fail-closed site the containment-floor contract
asserts at, which every execution lane passes through) refuses
instead, with the real remedy: upgrade the distro to WSL2. The
operator-explicit disable (--sandbox none / --no-sandbox /
disabled=True) stays authoritative — a disabled run asked for no
sandbox, and refusing it would remove the only escape the message
names.

Detection is mocked at the core.startup.wsl module attributes (the
consumer contract); the flavour predicates are pinned coherently per
scenario. All parent-side — no namespace capability needed for the
refusal itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox.errors import SandboxSetupError
from core.startup import wsl as startup_wsl

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux",
                       reason="WSL is a Linux-host concern"),
    pytest.mark.wsl,
]

_TRUE = "/usr/bin/true"


def _mock_flavour(monkeypatch, *, wsl: bool, wsl2: bool) -> None:
    monkeypatch.setattr(startup_wsl, "is_wsl",
                        lambda kernel_id=None: wsl)
    monkeypatch.setattr(startup_wsl, "is_wsl2",
                        lambda kernel_id=None: wsl2)


class TestWsl1Refusal:
    def test_plain_run_refuses_on_wsl1(self, monkeypatch, tmp_path):
        from core.sandbox import run
        _mock_flavour(monkeypatch, wsl=True, wsl2=False)
        marker = tmp_path / "executed"
        with pytest.raises(SandboxSetupError) as exc_info:
            run(["/usr/bin/touch", str(marker)],
                capture_output=True, text=True, timeout=30)
        msg = str(exc_info.value)
        assert "WSL1" in msg
        assert "wsl --set-version" in msg
        assert "--no-sandbox" in msg
        # Fail-closed means the target never executed.
        assert not marker.exists()

    def test_policy_carrying_run_refuses_on_wsl1(
            self, monkeypatch, tmp_path):
        # A sandbox-engaging shape (target/output/network policy)
        # refuses through the same chokepoint — no lane is exempt.
        from core.sandbox import run
        _mock_flavour(monkeypatch, wsl=True, wsl2=False)
        target = tmp_path / "t"
        output = tmp_path / "o"
        target.mkdir()
        output.mkdir()
        with pytest.raises(SandboxSetupError):
            run([_TRUE], target=str(target), output=str(output),
                block_network=True,
                capture_output=True, text=True, timeout=30)

    def test_operator_disable_still_runs_on_wsl1(
            self, monkeypatch, tmp_path):
        # The documented all-bets-off surface: an explicitly disabled
        # sandbox is not a sandboxed-execution path and keeps working
        # (it is also the escape hatch the refusal message names).
        from core.sandbox import run
        _mock_flavour(monkeypatch, wsl=True, wsl2=False)
        marker = tmp_path / "executed"
        r = run(["/usr/bin/touch", str(marker)], disabled=True,
                capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, getattr(r, "stderr", "")
        assert marker.exists()

    def test_wsl2_does_not_refuse(self, monkeypatch):
        from core.sandbox import run
        _mock_flavour(monkeypatch, wsl=True, wsl2=True)
        r = run([_TRUE], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, getattr(r, "stderr", "")

    def test_plain_linux_does_not_refuse(self, monkeypatch):
        # The inertness pin: off-WSL the chokepoint behaves exactly
        # as before (two cached boolean probes, no refusal).
        from core.sandbox import run
        _mock_flavour(monkeypatch, wsl=False, wsl2=False)
        r = run([_TRUE], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, getattr(r, "stderr", "")
