"""Tests for core.startup.wsl — WSL detection and messaging helpers.

Hermetic by construction: kernel identity is injected as text, the
statfs probe is monkeypatched, and the only real-syscall cases assert
shape (a bool / an int-or-None), never a host-specific verdict — so
the suite passes identically on any CI filesystem.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

from core.startup import wsl

pytestmark = pytest.mark.wsl


@pytest.fixture(autouse=True)
def reset_wsl_cache():
    """``is_wsl()`` caches its filesystem answer process-wide; tests
    mock different kernel identities, so the cache is cleared around
    each test to keep them independent."""
    wsl._is_wsl_cache = None
    yield
    wsl._is_wsl_cache = None


class TestIsWsl:
    def test_wsl2_osrelease_detected(self):
        assert wsl.is_wsl("5.15.167.4-microsoft-standard-WSL2\n") is True

    def test_wsl1_proc_version_detected_case_insensitive(self):
        assert wsl.is_wsl(
            "Linux version 4.4.0-19041-Microsoft "
            "(Microsoft@Microsoft.com)\n"
        ) is True

    def test_mainline_kernel_not_wsl(self):
        assert wsl.is_wsl("6.8.0-generic\n") is False
        assert wsl.is_wsl("Linux version 6.8.0-generic (gcc ...)\n") is False

    def test_empty_identity_not_wsl(self):
        assert wsl.is_wsl("") is False

    def test_filesystem_answer_cached(self):
        calls: list[int] = []

        def fake_read() -> str:
            calls.append(1)
            return "5.15.167.4-microsoft-standard-WSL2\n"

        with mock.patch.object(sys, "platform", "linux"), \
             mock.patch.object(wsl, "_read_kernel_id", fake_read):
            assert wsl.is_wsl() is True
            assert wsl.is_wsl() is True
        assert len(calls) == 1

    def test_injected_identity_bypasses_cache(self):
        wsl._is_wsl_cache = False
        assert wsl.is_wsl("microsoft-standard") is True

    def test_probe_failure_reads_false(self):
        with mock.patch.object(sys, "platform", "linux"), \
             mock.patch.object(wsl, "_read_kernel_id",
                               side_effect=OSError("masked /proc")):
            assert wsl.is_wsl() is False

    def test_non_linux_reads_false(self):
        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(wsl, "_read_kernel_id") as read:
            assert wsl.is_wsl() is False
        read.assert_not_called()

    def test_read_kernel_id_prefers_osrelease(self, tmp_path):
        osrelease = tmp_path / "osrelease"
        osrelease.write_text("5.15-microsoft-standard-WSL2\n")
        with mock.patch.object(
            wsl, "_KERNEL_ID_PATHS",
            (str(osrelease), str(tmp_path / "version")),
        ):
            assert "microsoft" in wsl._read_kernel_id()

    def test_read_kernel_id_falls_through_unreadable(self, tmp_path):
        version = tmp_path / "version"
        version.write_text("Linux version 6.8.0-generic\n")
        with mock.patch.object(
            wsl, "_KERNEL_ID_PATHS",
            (str(tmp_path / "gone"), str(version)),
        ):
            assert wsl._read_kernel_id().startswith("Linux version")

    def test_read_kernel_id_all_unreadable(self, tmp_path):
        with mock.patch.object(
            wsl, "_KERNEL_ID_PATHS", (str(tmp_path / "gone"),),
        ):
            assert wsl._read_kernel_id() == ""


class TestFsIsDrvfsOr9p:
    def test_v9fs_magic_matches(self, tmp_path):
        with mock.patch.object(wsl, "_statfs_f_type",
                               return_value=wsl._V9FS_MAGIC):
            assert wsl.fs_is_drvfs_or_9p(tmp_path) is True

    def test_other_magic_does_not_match(self, tmp_path):
        # ext4's EXT4_SUPER_MAGIC — the common Linux-root answer.
        with mock.patch.object(wsl, "_statfs_f_type",
                               return_value=0xEF53):
            assert wsl.fs_is_drvfs_or_9p(tmp_path) is False

    def test_statfs_failure_reads_false(self, tmp_path):
        with mock.patch.object(wsl, "_statfs_f_type", return_value=None):
            assert wsl.fs_is_drvfs_or_9p(tmp_path) is False

    def test_probe_exception_reads_false(self, tmp_path):
        with mock.patch.object(wsl, "_statfs_f_type",
                               side_effect=RuntimeError("boom")):
            assert wsl.fs_is_drvfs_or_9p(tmp_path) is False

    def test_nonexistent_path_probes_nearest_ancestor(self, tmp_path):
        probed: list[Path] = []

        def record(path: Path) -> int:
            probed.append(path)
            return wsl._V9FS_MAGIC

        missing = tmp_path / "runs" / "scan-20260101"
        with mock.patch.object(wsl, "_statfs_f_type", record):
            assert wsl.fs_is_drvfs_or_9p(missing) is True
        assert probed == [tmp_path]

    def test_real_statfs_returns_bool(self, tmp_path):
        # Real-syscall smoke: shape only — CI filesystems vary (and a
        # VM runner could legitimately sit on 9p), so no verdict is
        # asserted.
        assert wsl.fs_is_drvfs_or_9p(tmp_path) in (True, False)

    def test_statfs_f_type_shape(self, tmp_path):
        got = wsl._statfs_f_type(tmp_path)
        if sys.platform == "linux":
            assert isinstance(got, int)
        else:
            assert got is None

    def test_statfs_f_type_missing_path(self, tmp_path):
        assert wsl._statfs_f_type(tmp_path / "gone") is None


class TestWslAdvisories:
    def test_off_wsl_is_empty(self):
        with mock.patch.object(wsl, "is_wsl", return_value=False):
            assert wsl.wsl_advisories(landlock_ok=False) == []

    def test_landlock_missing_names_both_remedies(self):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", return_value=None):
            lines = wsl.wsl_advisories(landlock_ok=False)
        landlock_lines = [ln for ln in lines if "Landlock" in ln]
        assert len(landlock_lines) == 1
        assert "--sandbox-floor ns-only" in landlock_lines[0]
        assert ".wslconfig" in landlock_lines[0]
        assert "docs/wsl.md" in landlock_lines[0]

    def test_landlock_present_no_landlock_line(self):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/tool"):
            lines = wsl.wsl_advisories(landlock_ok=True)
        assert not any("Landlock" in ln for ln in lines)

    def test_rr_present_gets_perf_counter_note(self):
        def which(name: str):
            return "/usr/bin/rr" if name == "rr" else "/usr/bin/docker"

        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", which), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False):
            lines = wsl.wsl_advisories(landlock_ok=True)
        assert lines == [
            "rr requires CPU perf counters, typically unavailable "
            "under WSL2 — /crash-analysis recording is likely to "
            "fail on this host (see docs/wsl.md)"
        ]

    def test_docker_absent_gets_desktop_integration_hint(self):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", return_value=None), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False):
            lines = wsl.wsl_advisories(landlock_ok=True)
        assert len(lines) == 1
        assert "Docker Desktop" in lines[0]

    def test_all_good_is_quiet(self):
        def which(name: str):
            return "/usr/bin/docker" if name == "docker" else None

        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", which), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False):
            assert wsl.wsl_advisories(landlock_ok=True) == []

    def test_temp_root_on_interop_mount_gets_tmpdir_line(self):
        def which(name: str):
            return "/usr/bin/docker" if name == "docker" else None

        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", which), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             mock.patch("tempfile.gettempdir",
                        return_value="/mnt/c/Temp"):
            lines = wsl.wsl_advisories(landlock_ok=True)
        assert len(lines) == 1
        assert "temp root" in lines[0]
        assert "/mnt/c/Temp" in lines[0]
        assert "TMPDIR" in lines[0]
        assert "export TMPDIR=/tmp" in lines[0]
        assert "docs/wsl.md" in lines[0]

    def test_temp_root_advisory_escapes_hostile_tmpdir(self):
        def which(name: str):
            return "/usr/bin/docker" if name == "docker" else None

        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch("shutil.which", which), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             mock.patch("tempfile.gettempdir",
                        return_value="/mnt/c/\x1b]0;pwned\x07tmp"):
            lines = wsl.wsl_advisories(landlock_ok=True)
        assert len(lines) == 1
        assert "\x1b" not in lines[0]
        assert "\x07" not in lines[0]


class TestWarnWindowsInteropMount:
    def test_warns_on_interop_mount(self, tmp_path, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            wsl.warn_windows_interop_mount(tmp_path, "default target")
        err = capsys.readouterr().err
        assert "default target" in err
        assert "drvfs/9p" in err
        assert "docs/wsl.md" in err

    def test_silent_off_wsl(self, tmp_path, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=False):
            wsl.warn_windows_interop_mount(tmp_path, "default target")
        assert capsys.readouterr().err == ""

    def test_silent_on_linux_filesystem(self, tmp_path, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False):
            wsl.warn_windows_interop_mount(tmp_path, "output directory")
        assert capsys.readouterr().err == ""

    def test_hostile_path_bytes_escaped(self, capsys):
        hostile = "/mnt/c/\x1b]0;pwned\x07repo"
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            wsl.warn_windows_interop_mount(hostile, "default target")
        err = capsys.readouterr().err
        assert "\x1b" not in err
        assert "\x07" not in err
        assert "default target" in err

    def test_never_raises(self, tmp_path):
        with mock.patch.object(wsl, "is_wsl",
                               side_effect=RuntimeError("boom")):
            wsl.warn_windows_interop_mount(tmp_path, "default target")

    def test_default_remedy_without_detail(self, tmp_path, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            wsl.warn_windows_interop_mount(tmp_path, "default target")
        err = capsys.readouterr().err
        assert "Prefer a path on the distro's Linux filesystem." in err

    def test_detail_replaces_default_remedy(self, tmp_path, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            wsl.warn_windows_interop_mount(
                tmp_path, "temp root", detail="Do the specific thing.",
            )
        err = capsys.readouterr().err
        assert "Do the specific thing." in err
        assert "Prefer a path on the distro's Linux filesystem." not in err
        assert "See docs/wsl.md." in err


class TestWarnTmpdirWindowsInterop:
    @pytest.fixture(autouse=True)
    def reset_tmpdir_latch(self):
        """The advisory latches once per process; tests exercise the
        latch itself, so it is reset around each test."""
        wsl._tmpdir_warned = False
        yield
        wsl._tmpdir_warned = False

    def test_warns_once_per_process(self, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             mock.patch("tempfile.gettempdir",
                        return_value="/mnt/c/Temp"):
            wsl.warn_tmpdir_windows_interop()
            wsl.warn_tmpdir_windows_interop()
            wsl.warn_tmpdir_windows_interop()
        err = capsys.readouterr().err
        assert err.count("WARNING") == 1
        assert "temp root (TMPDIR/RAPTOR_WORK_DIR)" in err
        assert "/mnt/c/Temp" in err
        assert "FIFO" in err
        assert "export TMPDIR=/tmp" in err
        assert "docs/wsl.md" in err

    def test_explicit_base_probed_instead_of_gettempdir(self, capsys):
        probed: list[str] = []

        def probe(path):
            probed.append(str(path))
            return True

        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p", probe):
            wsl.warn_tmpdir_windows_interop("/mnt/c/work-root")
        err = capsys.readouterr().err
        assert probed == ["/mnt/c/work-root"]
        assert "/mnt/c/work-root" in err

    def test_silent_off_wsl(self, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=False):
            wsl.warn_tmpdir_windows_interop()
        assert capsys.readouterr().err == ""

    def test_silent_on_linux_temp_root(self, capsys):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False):
            wsl.warn_tmpdir_windows_interop()
        assert capsys.readouterr().err == ""

    def test_latch_closes_even_when_silent(self, capsys):
        # gettempdir() caches process-wide, so a silent first call
        # settles the question for the process's whole life.
        with mock.patch.object(wsl, "is_wsl", return_value=False):
            wsl.warn_tmpdir_windows_interop()
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            wsl.warn_tmpdir_windows_interop()
        assert capsys.readouterr().err == ""

    def test_never_raises(self):
        # The emission path's own catch-all is the advisory contract;
        # the wrapper adds no raise surface of its own.
        with mock.patch.object(wsl, "is_wsl",
                               side_effect=RuntimeError("boom")):
            wsl.warn_tmpdir_windows_interop()
