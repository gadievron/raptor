"""Size and inode caps on the sandbox's fresh tmpfs mounts.

Regression target: the mount-ns lane's tmpfs instances (/tmp, /run,
/dev, /dev/shm, the pivot root) were mounted without ``size=`` — a
tmpfs then defaults to 50% of physical RAM PER MOUNT, so confined
code could drive the host into RAM/swap exhaustion from inside a
"contained" run with plain writes. The kernel's inode limit is
independent of ``size=`` (default: half the RAM pages, PER MOUNT), so
a size-capped mount still let empty-file spam pin gigabytes of
unswappable kernel slab. Every instance now carries per-install-
jittered ``size=`` AND ``nr_inodes=`` caps (mount_ns._TMPFS_SIZES_MB
/ _TMPFS_INODES).

Two-direction doctrine for the numeric caps:
  * floor tests — a cap dropping below its engineered floor breaks
    legitimate tooling loudly (build scratch ENOSPC, shm_open
    failures, file-heavy fuzzer queue dirs);
  * ceiling tests — a cap creeping above floor+spread re-opens the
    host-memory-fill / slab-pinning DoS the cap exists to close.
"""

from __future__ import annotations

import json
import sys

import pytest

from core.sandbox._spawn import mount_ns_available
from core.sandbox.mount_ns import _TMPFS_INODES, _TMPFS_SIZES_MB, _tmpfs_data
from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns tmpfs caps are Linux-only",
)

# Engineered floor and jitter spread per mount (must mirror the
# _install_jitter calls in mount_ns._TMPFS_SIZES_MB / _TMPFS_INODES —
# a drift here IS the regression these tests exist to catch).
_BOUNDS_MB = {
    "tmp": (4096, 512),
    "shm": (1024, 128),
    "run": (64, 16),
    "dev": (8, 4),
    "root": (64, 16),
}
_BOUNDS_INODES = {
    "tmp": (1048576, 65536),
    "shm": (65536, 8192),
    "run": (16384, 2048),
    "dev": (16384, 2048),
    "root": (16384, 2048),
}


class TestCapBounds:
    def test_every_sandbox_tmpfs_has_a_size_cap(self):
        assert set(_TMPFS_SIZES_MB) == set(_BOUNDS_MB)

    def test_every_sandbox_tmpfs_has_an_inode_cap(self):
        assert set(_TMPFS_INODES) == set(_BOUNDS_INODES)

    @pytest.mark.parametrize("name", sorted(_BOUNDS_MB))
    def test_size_cap_at_or_above_floor(self, name):
        """Too LOW: legitimate tooling breaks mid-run (ENOSPC from
        compiler/extractor scratch, shm_open failures)."""
        floor, _spread = _BOUNDS_MB[name]
        assert _TMPFS_SIZES_MB[name] >= floor

    @pytest.mark.parametrize("name", sorted(_BOUNDS_MB))
    def test_size_cap_below_ceiling(self, name):
        """Too HIGH: the cap stops bounding the RAM/swap fill it
        exists to bound (jitter is surplus-only and < spread)."""
        floor, spread = _BOUNDS_MB[name]
        assert _TMPFS_SIZES_MB[name] < floor + spread

    @pytest.mark.parametrize("name", sorted(_BOUNDS_INODES))
    def test_inode_cap_at_or_above_floor(self, name):
        """Too LOW: file-heavy legitimate workloads break (AFL
        queue/.state dirs, archive/corpus extraction — one file per
        interesting input, easily into the hundreds of thousands
        under /tmp)."""
        floor, _spread = _BOUNDS_INODES[name]
        assert _TMPFS_INODES[name] >= floor

    @pytest.mark.parametrize("name", sorted(_BOUNDS_INODES))
    def test_inode_cap_below_ceiling(self, name):
        """Too HIGH: the budget stops bounding unswappable kernel
        slab (~1 KB per tmpfs inode+dentry) — the uncapped kernel
        default (~half the RAM pages PER MOUNT) lets empty-file spam
        pin gigabytes with the mount at 0% by bytes."""
        floor, spread = _BOUNDS_INODES[name]
        assert _TMPFS_INODES[name] < floor + spread

    def test_total_footprint_bounded(self):
        """The SUM of all size caps is a sandbox's worst-case tmpfs
        byte footprint — it must stay well under small-host RAM+swap."""
        assert sum(_TMPFS_SIZES_MB.values()) < 6 * 1024

    def test_total_inode_footprint_bounded(self):
        """The SUM of all inode budgets bounds worst-case pinned
        slab (~1 KB/inode) — keep it near 1 Mi (~1 GiB slab)."""
        assert sum(_TMPFS_INODES.values()) < 1280 * 1024

    def test_data_string_shapes(self):
        assert _tmpfs_data("tmp") == (
            f"size={_TMPFS_SIZES_MB['tmp']}m,"
            f"nr_inodes={_TMPFS_INODES['tmp']}")
        assert _tmpfs_data("shm", "mode=1777") == (
            f"mode=1777,size={_TMPFS_SIZES_MB['shm']}m,"
            f"nr_inodes={_TMPFS_INODES['shm']}")


_STATVFS_PROG = (
    "import json, os; "
    "print(json.dumps({p: (lambda s: [s.f_blocks * s.f_frsize, s.f_files])"
    "(os.statvfs(p)) "
    "for p in ('/tmp', '/run', '/dev', '/dev/shm', '/')}))"
)

_LIVE = pytest.mark.skipif(
    not (sys.platform == "linux" and mount_ns_available()),
    reason="live tmpfs-cap check needs Linux with mount-ns capability",
)


@requires_landlock
@_LIVE
class TestLiveMountSizes:
    """statvfs(3) inside a real mount-ns sandbox: every fresh tmpfs —
    /tmp, /run, /dev, /dev/shm AND the pivot root at "/" — must
    report the capped size and inode budget, not the kernel defaults
    (50% of RAM in bytes, half the RAM pages in inodes — which is
    what the pre-fix mounts exposed; the "/" entry is the pivot
    root's own tmpfs, the one mount a test looping only over the
    stacked paths would never touch)."""

    # System interpreter: a venv python outside the bind tree would
    # drop the run to the fallback tier and test the wrong path.
    _PY = "/usr/bin/python3"

    def test_tmpfs_sizes_and_inodes_are_capped(self, tmp_path):
        from core.sandbox import run
        r = run([self._PY, "-c", _STATVFS_PROG],
                target=str(tmp_path), output=str(tmp_path),
                block_network=True, capture_output=True, text=True,
                timeout=120)
        if not r.sandbox_info.get("mount_ns_active"):
            pytest.skip("mount namespace did not engage on this host")
        assert r.returncode == 0, r.stderr[-500:] if r.stderr else r
        stats = json.loads(r.stdout.strip().splitlines()[-1])
        for path, key in (("/tmp", "tmp"), ("/run", "run"),
                          ("/dev", "dev"), ("/dev/shm", "shm"),
                          ("/", "root")):
            size_bytes, f_files = stats[path]
            floor, spread = _BOUNDS_MB[key]
            got_mb = size_bytes / (1024 * 1024)
            # Two directions live: at least the engineered floor
            # (tooling headroom present), at most floor+spread (the
            # cap actually took — an uncapped mount reports 50% RAM).
            assert floor <= got_mb < floor + spread, (
                f"{path}: {got_mb:.0f} MiB outside "
                f"[{floor}, {floor + spread}) — size cap not applied?"
            )
            ifloor, ispread = _BOUNDS_INODES[key]
            # Same two directions for the inode budget — an uncapped
            # mount reports ~half the host's RAM pages here.
            assert ifloor <= f_files < ifloor + ispread, (
                f"{path}: f_files={f_files} outside "
                f"[{ifloor}, {ifloor + ispread}) — nr_inodes cap "
                f"not applied?"
            )
