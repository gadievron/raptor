"""Regression: uid/gid-mapping helpers must never resolve via PATH.

Pre-fix, ``check_mount_available`` / ``mount_unavailable_reason`` gated
the mount-ns tier on ``shutil.which('newuidmap'/'newgidmap')`` — the
inherited PATH — and ``_spawn`` resolved ``newuidmap`` / ``newgidmap``
/ ``getcap`` the same way, EXECUTING them in the unsandboxed parent.
That contradicts the module's own ``_resolve_sandbox_binary`` doctrine,
which refuses PATH precisely because a poisoned PATH (malicious
``.envrc`` / direnv, ``.`` entry with cwd in a hostile tree) could
hijack the sandbox bootstrap.

These tests plant executable stubs in a poisoned PATH and assert the
probe verdict does not flip and the stub is never the executed helper.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns probe / uidmap helpers)",
)

import os  # noqa: E402
from pathlib import Path  # noqa: E402

from core.sandbox import _spawn, probes, state  # noqa: E402


def _no_apparmor_sysctl(*a, **kw):
    raise FileNotFoundError("apparmor sysctl absent")


def _make_stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / name
    stub.write_text(f"#!/bin/sh\n{body}\n")
    stub.chmod(0o755)
    return stub


def _reset_resolver_caches(monkeypatch):
    for attr in ("_newuidmap_path_cache", "_newgidmap_path_cache",
                 "_getcap_path_cache"):
        monkeypatch.setattr(state, attr, None, raising=False)


class TestProbeIgnoresPoisonedPath:

    def test_mount_available_not_flipped_by_path_stubs(
            self, tmp_path, monkeypatch):
        """Host without uidmap in the trusted dirs + PATH stubs: the
        availability verdict must stay False (pre-fix: PATH stubs
        flipped it toward attempting the newuidmap tier)."""
        poisoned = tmp_path / "poisoned-bin"
        _make_stub(poisoned, "newuidmap", "exit 0")
        _make_stub(poisoned, "newgidmap", "exit 0")
        monkeypatch.setenv("PATH", str(poisoned))
        trusted = tmp_path / "trusted-bin"
        trusted.mkdir()
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)
        monkeypatch.setattr(state, "_mount_available_cache", None)
        monkeypatch.setattr(probes, "check_net_available", lambda: True)
        monkeypatch.setattr(Path, "read_text", _no_apparmor_sysctl)

        assert probes.check_mount_available() is False

    def test_unavailable_reason_names_uidmap_despite_path_stubs(
            self, tmp_path, monkeypatch):
        """The diagnosis must agree with the probe: with uidmap absent
        from the trusted dirs, the reason is the uidmap package — not
        the SELinux/catch-all branches a PATH hit steered it to."""
        poisoned = tmp_path / "poisoned-bin"
        _make_stub(poisoned, "newuidmap", "exit 0")
        _make_stub(poisoned, "newgidmap", "exit 0")
        monkeypatch.setenv("PATH", str(poisoned))
        trusted = tmp_path / "trusted-bin"
        trusted.mkdir()
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)
        monkeypatch.setattr(Path, "read_text", _no_apparmor_sysctl)

        condition, fix = probes.mount_unavailable_reason()
        assert "uidmap" in condition.lower()


class TestSpawnHelperResolutionIgnoresPath:

    def test_mount_ns_available_never_executes_path_stub(
            self, tmp_path, monkeypatch):
        """mount_ns_available runs `newuidmap --help` in the
        unsandboxed parent. The executed binary must come from the
        trusted dirs; the PATH stub must never run."""
        poisoned = tmp_path / "poisoned-bin"
        path_marker = tmp_path / "path-stub-ran"
        _make_stub(poisoned, "newuidmap", f": > {path_marker}; exit 0")
        _make_stub(poisoned, "newgidmap", f": > {path_marker}; exit 0")
        monkeypatch.setenv("PATH", str(poisoned))
        trusted = tmp_path / "trusted-bin"
        trusted_marker = tmp_path / "trusted-stub-ran"
        _make_stub(trusted, "newuidmap", f": > {trusted_marker}; exit 0")
        _make_stub(trusted, "newgidmap", "exit 0")
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)
        monkeypatch.setattr(state, "_mount_ns_available_cache", None)

        assert _spawn.mount_ns_available() is True
        assert trusted_marker.exists(), (
            "the trusted-dir newuidmap should have been probed"
        )
        assert not path_marker.exists(), (
            "PATH-resolved newuidmap stub was executed in the "
            "unsandboxed parent — PATH hijack regression"
        )

    def test_gidmap_allow_getcap_not_resolved_via_path(
            self, tmp_path, monkeypatch):
        """A PATH-planted getcap that vouches cap_setgid must not make
        _gidmap_allow_available bless (and later exec) the helper."""
        poisoned = tmp_path / "poisoned-bin"
        path_marker = tmp_path / "path-getcap-ran"
        _make_stub(
            poisoned, "getcap",
            f': > {path_marker}; echo "$1 cap_setgid=ep"; exit 0',
        )
        monkeypatch.setenv("PATH", str(poisoned))
        trusted = tmp_path / "trusted-bin"
        trusted.mkdir()
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)
        monkeypatch.setattr(state, "_gidmap_allow_cache", None)
        # Make the helper binary exist so the getcap branch is reached.
        helper = tmp_path / "raptor-gidmap-allow"
        helper.write_text("")
        monkeypatch.setattr(_spawn, "GIDMAP_ALLOW_PATH", helper)

        assert _spawn._gidmap_allow_available() is None
        assert not path_marker.exists(), (
            "PATH-resolved getcap stub was executed in the "
            "unsandboxed parent — PATH hijack regression"
        )


class TestTrustedDirResolutionStillWorks:

    def test_find_sandbox_binary_prefers_trusted_dir(
            self, tmp_path, monkeypatch):
        trusted = tmp_path / "trusted-bin"
        real = _make_stub(trusted, "newuidmap", "exit 0")
        poisoned = tmp_path / "poisoned-bin"
        _make_stub(poisoned, "newuidmap", "exit 1")
        monkeypatch.setenv("PATH", str(poisoned))
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)

        assert probes._find_sandbox_binary("newuidmap") == str(real)

    def test_find_sandbox_binary_returns_none_when_absent(
            self, tmp_path, monkeypatch):
        trusted = tmp_path / "trusted-bin"
        trusted.mkdir()
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        _reset_resolver_caches(monkeypatch)

        assert probes._find_sandbox_binary("newuidmap") is None

    def test_resolution_result_is_path_independent(
            self, tmp_path, monkeypatch):
        """Same call, wildly different PATHs — identical answer."""
        trusted = tmp_path / "trusted-bin"
        real = _make_stub(trusted, "newgidmap", "exit 0")
        monkeypatch.setattr(probes, "_SAFE_BIN_DIRS", (str(trusted),))
        results = set()
        for path_value in ("", str(tmp_path), "/nonexistent"):
            _reset_resolver_caches(monkeypatch)
            monkeypatch.setenv("PATH", path_value)
            results.add(probes._find_sandbox_binary("newgidmap"))
        assert results == {str(real)}


def test_no_os_environ_path_lookup_for_uidmap_helpers():
    """Structural guard: neither probes.py nor _spawn.py may resolve
    newuidmap/newgidmap/getcap through shutil.which (PATH) again."""
    import re

    sandbox_dir = Path(probes.__file__).resolve().parent
    for fname in ("probes.py", "_spawn.py"):
        src = (sandbox_dir / fname).read_text()
        hits = re.findall(
            r"which\(\s*['\"](?:newuidmap|newgidmap|getcap)['\"]", src)
        assert hits == [], (
            f"{fname} resolves {hits} via PATH — use "
            f"probes._find_sandbox_binary (trusted dirs only)"
        )


# The test-scoped stubs above never leave tmp_path; make sure nothing
# in this module leaked a poisoned PATH into the process (monkeypatch
# restores env per-test, this is a belt-and-braces tripwire for the
# module as a whole).
def test_environment_restored():
    assert "poisoned-bin" not in os.environ.get("PATH", "")
