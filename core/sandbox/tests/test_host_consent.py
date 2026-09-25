"""WSL host-consent marker store: conditional inertness, tamper
handling, atomic writes, grant/revoke semantics.

Everything here runs hermetically off-WSL: the WSL/Landlock probes and
the kernel-identity / machine-id sources are monkeypatched, and the
marker path is redirected through ``XDG_DATA_HOME``.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.sandbox import host_consent as hc

WSL2_RELEASE = "5.15.167.4-microsoft-standard-WSL2"
WSL2_RELEASE_BUMPED = "6.6.36.6-microsoft-standard-WSL2"
OTHER_FLAVOUR_RELEASE = "6.6.0-microsoft-custom-flavour"
MACHINE_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def _fresh_latches():
    hc._reset_warning_latches()
    yield
    hc._reset_warning_latches()


@pytest.fixture()
def wsl_host(tmp_path, monkeypatch):
    """A mocked WSL2 host without Landlock, with hermetic identity
    sources and a tmp marker path. Returns the tmp base dir."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    osrelease = tmp_path / "osrelease"
    osrelease.write_text(WSL2_RELEASE + "\n", encoding="ascii")
    machine_id = tmp_path / "machine-id"
    machine_id.write_text(MACHINE_ID + "\n", encoding="ascii")
    monkeypatch.setattr(hc, "_OSRELEASE_PATH", str(osrelease))
    monkeypatch.setattr(hc, "_MACHINE_ID_PATH", str(machine_id))
    monkeypatch.setattr(hc, "sys",
                        types.SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        "core.startup.wsl.is_wsl", lambda kernel_id=None: True)
    monkeypatch.setattr(
        "core.sandbox.landlock.check_landlock_available", lambda: False)
    return tmp_path


def _grant(tmp_path) -> Path:
    return hc.write_marker()


# ─── kernel_family ───────────────────────────────────────────────────

class TestKernelFamily:
    def test_wsl2_release(self):
        assert hc.kernel_family(WSL2_RELEASE) == "microsoft-standard-wsl2"

    def test_version_bump_keeps_family(self):
        assert (hc.kernel_family(WSL2_RELEASE)
                == hc.kernel_family(WSL2_RELEASE_BUMPED))

    def test_flavour_change_breaks_family(self):
        assert (hc.kernel_family(WSL2_RELEASE)
                != hc.kernel_family(OTHER_FLAVOUR_RELEASE))

    def test_case_insensitive(self):
        assert (hc.kernel_family("5.15.0-Microsoft-Standard-WSL2")
                == "microsoft-standard-wsl2")

    def test_empty_and_numeric_only(self):
        assert hc.kernel_family("") == ""
        assert hc.kernel_family("6.6.36") == ""

    def test_first_line_only(self):
        assert (hc.kernel_family(WSL2_RELEASE + "\ngarbage-line")
                == "microsoft-standard-wsl2")


# ─── grant / roundtrip / revoke ──────────────────────────────────────

class TestGrantRevoke:
    def test_grant_writes_valid_marker_and_applies(self, wsl_host):
        path = _grant(wsl_host)
        assert path == hc.marker_path()
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["schema"] == 1
        assert record["floor"] == "ns-only"
        assert record["kernel_identity"] == WSL2_RELEASE
        assert record["kernel_family"] == "microsoft-standard-wsl2"
        assert record["machine_id"] == MACHINE_ID
        assert record["evidence"]["is_wsl"] is True
        assert record["evidence"]["landlock_available"] is False
        consent = hc.applied_consent()
        assert consent is not None
        assert consent.floor == "ns-only"
        assert hc.host_consented_floor() == "ns-only"

    def test_marker_file_and_dir_modes(self, wsl_host):
        path = _grant(wsl_host)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    def test_write_leaves_no_tempfile_behind(self, wsl_host):
        path = _grant(wsl_host)
        assert [p.name for p in path.parent.iterdir()] == [path.name]

    def test_grant_is_idempotent_overwrite(self, wsl_host):
        _grant(wsl_host)
        path = _grant(wsl_host)
        assert json.loads(path.read_text(encoding="utf-8"))["floor"] == (
            "ns-only")

    def test_revoke_removes_and_reports(self, wsl_host):
        _grant(wsl_host)
        assert hc.remove_marker() is True
        assert hc.host_consented_floor() is None
        assert hc.remove_marker() is False  # missing-ok

    def test_grant_refuses_off_wsl(self, wsl_host, monkeypatch):
        monkeypatch.setattr(
            "core.startup.wsl.is_wsl", lambda kernel_id=None: False)
        with pytest.raises(hc.HostConsentError, match="does not identify"):
            hc.grant_preflight()

    def test_grant_refuses_when_landlock_present(self, wsl_host,
                                                 monkeypatch):
        monkeypatch.setattr(
            "core.sandbox.landlock.check_landlock_available",
            lambda: True)
        with pytest.raises(hc.HostConsentError, match="Landlock is "
                                                      "available"):
            hc.grant_preflight()

    def test_grant_refuses_unreadable_kernel_identity(self, wsl_host,
                                                      monkeypatch):
        monkeypatch.setattr(hc, "_OSRELEASE_PATH",
                            str(wsl_host / "missing"))
        with pytest.raises(hc.HostConsentError, match="kernel identity"):
            hc.grant_preflight()

    def test_grant_refuses_unreadable_machine_id(self, wsl_host,
                                                 monkeypatch):
        monkeypatch.setattr(hc, "_MACHINE_ID_PATH",
                            str(wsl_host / "missing"))
        with pytest.raises(hc.HostConsentError, match="machine"):
            hc.grant_preflight()


# ─── conditional inertness ───────────────────────────────────────────

class TestInertness:
    def test_absent_marker_is_silent(self, wsl_host, caplog):
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert not caplog.records
        assert hc.marker_status()["reason"] == "absent"

    def test_inert_on_non_wsl(self, wsl_host, monkeypatch, caplog):
        _grant(wsl_host)
        monkeypatch.setattr(
            "core.startup.wsl.is_wsl", lambda kernel_id=None: False)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert not caplog.records  # silent — a dormant marker is normal
        assert hc.marker_status()["reason"] == "not-wsl"

    def test_inert_when_landlock_appears(self, wsl_host, monkeypatch,
                                         caplog):
        _grant(wsl_host)
        monkeypatch.setattr(
            "core.sandbox.landlock.check_landlock_available",
            lambda: True)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert not caplog.records  # the automatic-rise direction
        assert hc.marker_status()["reason"] == "landlock-available"

    def test_version_bump_keeps_consent(self, wsl_host, monkeypatch):
        _grant(wsl_host)
        (wsl_host / "osrelease").write_text(
            WSL2_RELEASE_BUMPED + "\n", encoding="ascii")
        assert hc.host_consented_floor() == "ns-only"

    def test_kernel_flavour_change_is_inert_with_warning(
            self, wsl_host, caplog):
        _grant(wsl_host)
        (wsl_host / "osrelease").write_text(
            OTHER_FLAVOUR_RELEASE + "\n", encoding="ascii")
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert any("kernel family" in r.getMessage()
                   for r in caplog.records)
        assert hc.marker_status()["reason"] == "kernel-family-mismatch"

    def test_unreadable_running_identity_is_inert(self, wsl_host,
                                                  monkeypatch):
        _grant(wsl_host)
        monkeypatch.setattr(hc, "_OSRELEASE_PATH",
                            str(wsl_host / "missing"))
        assert hc.host_consented_floor() is None


# ─── tamper / corruption (inert + one warning) ───────────────────────

def _tamper(path: Path, **changes) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    record.update(changes)
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)


class TestTamper:
    @pytest.mark.parametrize(
        ("changes", "reason"),
        [
            ({"schema": 2}, "wrong-schema"),
            ({"floor": "landlock"}, "wrong-floor"),
            ({"floor": "none"}, "wrong-floor"),
            ({"granted_at": "not-a-date"}, "bad-granted-at"),
            ({"granted_at": "2026-09-24T12:00:00"}, "bad-granted-at"),
            ({"kernel_identity": ""}, "missing-field"),
            ({"machine_id": 7}, "missing-field"),
        ],
    )
    def test_field_tamper_is_inert_with_warning(
            self, wsl_host, caplog, changes, reason):
        path = _grant(wsl_host)
        _tamper(path, **changes)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert any(reason in r.getMessage() for r in caplog.records)
        assert hc.marker_status()["reason"] == reason

    def test_future_timestamp_is_tamper(self, wsl_host, caplog):
        path = _grant(wsl_host)
        future = (datetime.now(timezone.utc)
                  + timedelta(days=2)).isoformat(timespec="seconds")
        _tamper(path, granted_at=future)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "future-granted-at"

    def test_copied_from_another_host_is_inert(self, wsl_host, caplog):
        path = _grant(wsl_host)
        _tamper(path, machine_id="f" * 32)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "machine-id-mismatch"

    def test_invalid_json_is_inert_with_warning(self, wsl_host, caplog):
        path = _grant(wsl_host)
        path.write_bytes(b"{not json")
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
        assert any("invalid-json" in r.getMessage()
                   for r in caplog.records)

    def test_non_dict_json_is_inert(self, wsl_host):
        path = _grant(wsl_host)
        path.write_text(json.dumps(["ns-only"]), encoding="utf-8")
        assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "wrong-schema"

    def test_group_writable_marker_is_refused(self, wsl_host):
        path = _grant(wsl_host)
        path.chmod(0o620)
        assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "permissive-mode"

    def test_symlinked_marker_is_refused(self, wsl_host):
        path = _grant(wsl_host)
        real = path.with_name("elsewhere.json")
        path.rename(real)
        path.symlink_to(real)
        assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "symlink"

    def test_fifo_marker_is_refused_without_blocking(self, wsl_host):
        """A writer-less FIFO planted at the marker path must not hang
        floor resolution (a plain open would block forever): the
        O_NONBLOCK open returns instantly and the not-regular-file
        classification makes it inert."""
        path = _grant(wsl_host)
        path.unlink()
        os.mkfifo(str(path))
        assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "not-regular-file"

    def test_oversized_marker_is_refused(self, wsl_host):
        path = _grant(wsl_host)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(" " * (hc._MAX_MARKER_BYTES + 1))
        assert hc.host_consented_floor() is None
        assert hc.marker_status()["reason"] == "too-large"

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="mode bits do not bind root")
    def test_unreadable_marker_is_inert_with_warning(self, wsl_host,
                                                     caplog):
        path = _grant(wsl_host)
        path.chmod(0o000)
        try:
            with caplog.at_level(logging.WARNING):
                assert hc.host_consented_floor() is None
            assert any("unreadable" in r.getMessage()
                       for r in caplog.records)
        finally:
            path.chmod(0o600)

    def test_warning_fires_once_per_process(self, wsl_host, caplog):
        path = _grant(wsl_host)
        _tamper(path, schema=99)
        with caplog.at_level(logging.WARNING):
            assert hc.host_consented_floor() is None
            assert hc.host_consented_floor() is None
        warnings = [r for r in caplog.records
                    if r.levelno == logging.WARNING]
        assert len(warnings) == 1

    def test_evaluation_error_reads_as_inert(self, wsl_host,
                                             monkeypatch):
        _grant(wsl_host)
        def _boom() -> bool:
            raise RuntimeError("probe exploded")
        monkeypatch.setattr(
            "core.sandbox.landlock.check_landlock_available", _boom)
        assert hc.applied_consent() is None  # never raises


# ─── status surface ──────────────────────────────────────────────────

class TestStatus:
    def test_active_status(self, wsl_host):
        _grant(wsl_host)
        status = hc.marker_status()
        assert status["applies"] is True
        assert status["reason"] == "active"
        assert status["present"] is True
        assert status["record"]["floor"] == "ns-only"

    def test_absent_status(self, wsl_host):
        status = hc.marker_status()
        assert status == {
            "path": str(hc.marker_path()), "present": False,
            "applies": False, "reason": "absent", "record": None,
        }
