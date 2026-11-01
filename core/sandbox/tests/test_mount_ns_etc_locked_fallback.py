"""/etc bind fallback for hosts where the non-recursive bind is refused.

Container runtimes bind files into /etc (resolv.conf, hostname, hosts).
Inside the sandbox child's fresh user namespace those mounts are
MNT_LOCKED, and the kernel refuses a NON-recursive MS_BIND of a subtree
carrying locked children (EINVAL) — so step 4 of setup_mount_ns died on
/etc in every standard docker/containerd container and the whole
mount-ns backend was unavailable there. /etc uses a private read-only
snapshot instead. Other system directories, including /usr beneath an
installation-protected launcher, retain locked children through a recursive
bind with mandatory recursive read-only sealing.

Unit-level: _bind_system_ro_dir is exercised with the mount primitives
mocked. The end-to-end proof needs a real container (locked submounts
cannot be manufactured by an unprivileged test on a bare host).
"""

import errno
import os
from unittest import mock

import pytest

from core.sandbox import mount_ns

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX-only")


class _MountRecorder:
    """Fake mount_ns._mount that can refuse the initial bind."""

    def __init__(self, bind_error: OSError | None = None):
        self.bind_error = bind_error
        self.calls: list[tuple] = []

    def __call__(self, source, target, fstype, flags, data=None):
        self.calls.append((source, target, fstype, flags, data))
        if (self.bind_error is not None
                and flags == mount_ns.MS_BIND and fstype is None
                and source not in (None, "tmpfs")):
            err = self.bind_error
            self.bind_error = None  # refuse only the first bind
            raise err


def _run(d: str, recorder: _MountRecorder, *, etc_overlay=None,
         etc_missing=False, copy=None):
    copy = copy if copy is not None else mock.Mock()
    with mock.patch.object(mount_ns, "_mount", recorder), \
            mock.patch.object(mount_ns, "_copy_etc_tree", copy), \
            mock.patch.object(mount_ns, "_phase_trace"), \
            mock.patch.object(mount_ns, "warn_post_fork") as warn, \
            mock.patch.object(mount_ns, "_ro_remount_flags",
                              return_value=0x21):
        mount_ns._bind_system_ro_dir(
            d, "/sbx-root", f"/{d}", f"/sbx-root/{d}",
            etc_overlay, etc_missing)
    return copy, warn


def test_einval_on_etc_routes_to_tmpfs_copy():
    rec = _MountRecorder(OSError(errno.EINVAL, "Invalid argument"))
    copy, warn = _run("etc", rec)
    # Refused bind, then the tmpfs lane: tmpfs mount + ro remount.
    copy.assert_called_once_with("/etc", "/sbx-root/etc")
    assert ("tmpfs", "/sbx-root/etc", "tmpfs", 0, "mode=755") in rec.calls
    assert ("tmpfs", "/sbx-root/etc", None,
            mount_ns.MS_REMOUNT | mount_ns.MS_BIND | mount_ns.MS_RDONLY,
            None) in rec.calls
    warn.assert_called_once()  # loud note that the lane switched
    # The refused bind is never retried.
    binds = [c for c in rec.calls
             if c[3] == mount_ns.MS_BIND and c[0] == "/etc"]
    assert len(binds) == 1


def test_einval_on_non_etc_dir_requires_recursive_sealing():
    rec = _MountRecorder(OSError(errno.EINVAL, "Invalid argument"))
    with mock.patch.object(mount_ns, "_recursive_bind_system_ro") as seal:
        copy, _ = _run("usr", rec)
    seal.assert_called_once_with("/usr", "/sbx-root/usr")
    copy.assert_not_called()


def test_recursive_sealing_failure_propagates():
    rec = _MountRecorder(OSError(errno.EINVAL, "Invalid argument"))
    with mock.patch.object(mount_ns, "_recursive_bind_system_ro",
                           side_effect=OSError(errno.EPERM, "seal refused")):
        with pytest.raises(OSError, match="seal refused"):
            _run("usr", rec)


@pytest.mark.parametrize("result", [0, -1])
def test_recursive_system_bind_seals_every_mount_without_clearing_flags(result):
    with mock.patch.object(mount_ns, "_mount") as mount, \
            mock.patch.object(mount_ns._libc, "syscall", return_value=result) as syscall, \
            mock.patch("platform.machine", return_value="x86_64"), \
            mock.patch.object(mount_ns.ctypes, "get_errno", return_value=errno.EPERM):
        if result:
            with pytest.raises(OSError, match="read-only sealing failed"):
                mount_ns._recursive_bind_system_ro("/usr", "/private/usr")
        else:
            mount_ns._recursive_bind_system_ro("/usr", "/private/usr")
        mount.assert_called_once_with("/usr", "/private/usr", None, mount_ns.MS_BIND | mount_ns.MS_REC)
        arguments = syscall.call_args.args
        assert arguments[:4] == (442, -100, b"/private/usr", 0x8000)
        assert list(arguments[4]._obj) == [1, 0, 0, 0]
        assert arguments[5] == 32


def test_non_einval_on_etc_propagates():
    rec = _MountRecorder(OSError(errno.EPERM, "Operation not permitted"))
    copy = mock.Mock()
    with pytest.raises(OSError) as ei:
        _run("etc", rec, copy=copy)
    assert ei.value.errno == errno.EPERM
    copy.assert_not_called()


def test_missing_overlay_targets_still_route_to_tmpfs_copy():
    # The pre-existing trigger (etc_overlay entries with missing host
    # targets) keeps working: tmpfs lane without attempting the bind.
    rec = _MountRecorder()
    copy, _ = _run("etc", rec, etc_overlay={"/etc/raptor-x": "/dev/null"},
                   etc_missing=True)
    copy.assert_called_once()
    assert not any(c[0] == "/etc" and c[3] == mount_ns.MS_BIND
                   for c in rec.calls)


def test_success_path_binds_then_remounts_ro():
    rec = _MountRecorder()
    copy, warn = _run("usr", rec)
    assert rec.calls == [
        ("/usr", "/sbx-root/usr", None, mount_ns.MS_BIND, None),
        ("/usr", "/sbx-root/usr", None, 0x21, None),
    ]
    copy.assert_not_called()
    warn.assert_not_called()


def test_tmpfs_copy_handles_absent_overlay():
    # etc_overlay=None on the EINVAL route must not TypeError in the
    # stub pre-create loop (the pre-existing lane only ever ran with a
    # truthy overlay).
    rec = _MountRecorder()
    copy = mock.Mock()
    with mock.patch.object(mount_ns, "_mount", rec), \
            mock.patch.object(mount_ns, "_copy_etc_tree", copy), \
            mock.patch.object(mount_ns, "_phase_trace"):
        mount_ns._mount_etc_tmpfs_copy(
            "/sbx-root", "/etc", "/sbx-root/etc", None)
    copy.assert_called_once()
