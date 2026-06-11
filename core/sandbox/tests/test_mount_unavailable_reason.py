"""Regression guard for ``mount_unavailable_reason()`` — the
diagnostic routing that PR #777 surfaced was hardcoded to AppArmor.

When ``check_mount_available()`` returns False, the caller (context.py
spawn-blockers branch) used to emit a fixed
``apparmor_restrict_unprivileged_userns=1`` message. On a SELinux host
the operator chased the wrong sysctl; on a host where the uidmap
package was simply missing they were told to flip an AppArmor flag
that wasn't the problem.

This module pins the four routing branches:
  - AppArmor sysctl=1 → AppArmor guidance
  - uidmap binaries missing → uidmap-install guidance
  - SELinux enforcing → SELinux guidance
  - catch-all → outer-seccomp/nested-userns guidance
"""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals — the probe is gated on Linux paths",
)

from core.sandbox import probes


def _no_apparmor_sysctl(*a, **kw):
    """Force the AppArmor branch to fall through (FileNotFoundError on
    sysctl read). Used by tests that want a deeper branch."""
    raise FileNotFoundError("apparmor sysctl absent")


class TestMountUnavailableReason:

    def test_apparmor_branch_returns_apparmor_guidance(self, monkeypatch):
        """sysctl == ``1`` → operator-guidance names AppArmor."""
        from pathlib import Path

        def _fake_read_text(self, *a, **kw):
            return "1\n"

        monkeypatch.setattr(Path, "read_text", _fake_read_text)
        condition, fix = probes.mount_unavailable_reason()
        assert "apparmor" in condition.lower()
        assert "apparmor" in fix.lower()

    def test_uidmap_missing_branch_returns_uidmap_guidance(
        self, monkeypatch,
    ):
        """AppArmor absent, ``newuidmap``/``newgidmap`` missing →
        operator-guidance names the uidmap package."""
        from pathlib import Path
        monkeypatch.setattr(Path, "read_text", _no_apparmor_sysctl)
        monkeypatch.setattr(probes.shutil, "which", lambda _: None)
        condition, fix = probes.mount_unavailable_reason()
        assert "uidmap" in condition.lower()
        assert ("apt install uidmap" in fix
                or "shadow-utils" in fix), fix

    def test_selinux_branch_returns_selinux_guidance(self, monkeypatch):
        """AppArmor absent, uidmap present, SELinux enforcing →
        operator-guidance names SELinux + setsebool, NOT AppArmor."""
        from pathlib import Path

        def _read_text(self, *a, **kw):
            s = str(self)
            if s.endswith("apparmor_restrict_unprivileged_userns"):
                raise FileNotFoundError
            if s == "/sys/fs/selinux/enforce":
                return "1\n"
            raise FileNotFoundError

        monkeypatch.setattr(Path, "read_text", _read_text)
        monkeypatch.setattr(probes.shutil, "which",
                            lambda b: f"/usr/bin/{b}")
        condition, fix = probes.mount_unavailable_reason()
        assert "selinux" in condition.lower()
        assert "setenforce" in fix or "setsebool" in fix, fix
        # And critically — must NOT misattribute to AppArmor.
        assert "apparmor" not in condition.lower()
        assert "apparmor" not in fix.lower()

    def test_catch_all_branch_when_no_specific_cause_detected(
        self, monkeypatch,
    ):
        """AppArmor absent, uidmap present, SELinux not enforcing →
        catch-all guidance mentions outer seccomp / nested userns
        as plausible causes."""
        from pathlib import Path
        monkeypatch.setattr(Path, "read_text", _no_apparmor_sysctl)
        monkeypatch.setattr(probes.shutil, "which",
                            lambda b: f"/usr/bin/{b}")
        condition, fix = probes.mount_unavailable_reason()
        text = (condition + " " + fix).lower()
        assert "seccomp" in text or "nested" in text or "lsm" in text


class TestSelinuxEnforcingProbe:
    """The ``_selinux_enforcing()`` helper drives the SELinux routing
    branch. Tests pin the three states (enforcing, permissive, absent)
    without depending on the host's actual SELinux configuration."""

    def test_enforcing_returns_true(self, monkeypatch):
        from pathlib import Path
        monkeypatch.setattr(Path, "read_text",
                            lambda self, *a, **kw: "1\n")
        assert probes._selinux_enforcing() is True

    def test_permissive_returns_false(self, monkeypatch):
        from pathlib import Path
        monkeypatch.setattr(Path, "read_text",
                            lambda self, *a, **kw: "0\n")
        assert probes._selinux_enforcing() is False

    def test_absent_file_returns_false(self, monkeypatch):
        from pathlib import Path

        def _raise(self, *a, **kw):
            raise FileNotFoundError("not selinux")

        monkeypatch.setattr(Path, "read_text", _raise)
        assert probes._selinux_enforcing() is False

    def test_unreadable_returns_false_not_raise(self, monkeypatch):
        """The diagnostic path must never raise — caller wants a
        routing decision, not exception flow."""
        from pathlib import Path

        def _raise(self, *a, **kw):
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "read_text", _raise)
        assert probes._selinux_enforcing() is False
