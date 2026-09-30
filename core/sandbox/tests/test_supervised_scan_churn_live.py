"""Live kernel pins for the group scan's mounts latch — the poll
contract the verdict rests on, the known residual, and the end-to-end
two-sided evade, each in a throwaway root-mapped user+mount+pid
namespace (`unshare --map-root-user -Upfm --mount-proc --kill-child`;
the `--map-current-user` idiom drops capabilities at exec for non-root
uids, so mount probes need the root mapping). Hosts without
unprivileged userns/mount skip cleanly; every mount and every process
these probes create is confined to the namespace, which `--kill-child`
collapses with the probe.

What is pinned live (seam-level companions in
test_supervised_scan_churn.py):

- the kernel latch contract itself — open latches, reads never touch
  the latch, the poll consumes and re-latches, attach-and-detach with
  no intervening consumption stays pending;
- the KNOWN residual: a hidepid-class superblock flip from a sibling
  mount namespace never bumps the scanner's counter (if a future
  kernel starts firing it, this fails loudly and the narrowing claim
  gets upgraded — until then nobody can cite this suite as closure);
- the two-sided per-pid-overmount evade with forged stat content ends
  in occlusion, end to end;
- an attacker-authored table bind-mounted at /proc/self/mounts is
  refused by the superblock-magic check.
"""

import functools
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="supervised trees are Linux-only (fork/pidfd/procfs)",
)

_REPO_ROOT = __file__.rsplit("/core/sandbox/tests/", 1)[0]
_UNSHARE = ["unshare", "--map-root-user", "-Upfm", "--mount-proc",
            "--kill-child"]


@functools.lru_cache(maxsize=1)
def _mount_userns_available() -> bool:
    """A successful `--mount-proc` under the root-mapped idiom IS the
    mount-capability proof (it performs a real proc mount)."""
    try:
        return subprocess.run(
            [*_UNSHARE, "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_probe(tmp_path, source: str, marker: str) -> str:
    if not _mount_userns_available():
        pytest.skip("requires unprivileged user+mount namespaces "
                    "(root-mapped unshare with --mount-proc)")
    probe = tmp_path / "probe.py"
    probe.write_text(source)
    # bash rides as the namespace init (reaps the probe's children);
    # the probe path and repo root travel as argv data.
    proc = subprocess.run(
        [*_UNSHARE, "bash", "-c", 'python3 "$1" "$2"', "_",
         str(probe), _REPO_ROOT],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        f"probe failed rc={proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    if "SKIP:" in proc.stdout:
        pytest.skip(proc.stdout.split("SKIP:", 1)[1].splitlines()[0])
    assert marker in proc.stdout, (
        f"probe never reached its marker\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc.stdout


_PROBE_PRELUDE = r'''
import ctypes
import os
import select
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])

MS_BIND = 4096
MS_REMOUNT = 32
MNT_DETACH = 2

libc = ctypes.CDLL(None, use_errno=True)


def _b(value):
    return value.encode() if isinstance(value, str) else value


def mount(src, tgt, fstype, flags, data):
    rc = libc.mount(_b(src), _b(tgt), _b(fstype), flags, _b(data))
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {tgt}: {os.strerror(err)}")


def umount_detach(tgt):
    rc = libc.umount2(_b(tgt), MNT_DETACH)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"umount {tgt}: {os.strerror(err)}")


def churn(fd):
    """One consuming poll: True when a mount-event signal is
    pending on the fd (POLLERR|POLLPRI)."""
    poller = select.poll()
    poller.register(fd, select.POLLPRI)
    return any(ev & (select.POLLERR | select.POLLPRI)
               for _w, ev in poller.poll(0))
'''

# Design test: kernel-contract pin. Asserts the latch contract the
# runtime and its seam tests are written against — a regression in a
# future kernel surfaces as a named failure, not a silent hole.
_KERNEL_CONTRACT_PROBE = _PROBE_PRELUDE + r'''
scratch = tempfile.mkdtemp(prefix="churn-scratch-")

# (a) THE OPEN LATCHES: an fd that has never been read still reports
# churn that happened after the open.
fd = os.open("/proc/self/mounts", os.O_RDONLY)
assert not churn(fd), "fresh fd reports pending churn"
mount("none", scratch, "tmpfs", 0, "size=64k")
assert churn(fd), "mount after open did not latch (open-latch broken)"

# (c) THE POLL CONSUMES: an immediate second poll is quiet.
assert not churn(fd), "consumed signal still pending (consume broken)"

# (d) THE POLL RE-LATCHES: churn after a consumed poll fires again.
umount_detach(scratch)
assert churn(fd), "churn after consumed poll did not fire (re-latch)"
os.close(fd)

# (b) READS NEVER TOUCH THE LATCH: a full re-read that SEES the new
# mount does not clear the pending signal.
fd = os.open("/proc/self/mounts", os.O_RDONLY)
pre = b""
while True:
    chunk = os.read(fd, 65536)
    if not chunk:
        break
    pre += chunk
mount("none", scratch, "tmpfs", 0, "size=64k")
os.lseek(fd, 0, os.SEEK_SET)
post = b""
while True:
    chunk = os.read(fd, 65536)
    if not chunk:
        break
    post += chunk
assert scratch.encode() in post and scratch.encode() not in pre, (
    "re-read through the open fd did not see the live table")
assert churn(fd), "full re-read CLEARED the pending signal"
os.close(fd)
umount_detach(scratch)

# (e) ATTACH+DETACH WITH NO INTERVENING CONSUMPTION STAYS PENDING —
# the two-sided race shape, on a real per-pid overmount.
decoy = subprocess.Popen(["/bin/sleep", "300"])
fd = os.open("/proc/self/mounts", os.O_RDONLY)
assert not churn(fd), "fresh fd reports pending churn"
mount(scratch, f"/proc/{decoy.pid}", None, MS_BIND, None)
umount_detach(f"/proc/{decoy.pid}")
assert churn(fd), (
    "per-pid overmount attach+detach left NO pending signal — "
    "change-and-revert evades the latch")
os.close(fd)
decoy.kill()

# (f) SAME-NS hidepid REMOUNT FLIP FIRES.
fd = os.open("/proc/self/mounts", os.O_RDONLY)
mount("proc", "/proc", "proc", MS_REMOUNT, "hidepid=2")
try:
    assert churn(fd), "same-ns hidepid remount flip did not fire"
finally:
    mount("proc", "/proc", "proc", MS_REMOUNT, "hidepid=off")
os.close(fd)

print("KERNEL-CONTRACT-OK")
'''

# Design test: sibling-namespace superblock-flip residual pin. hidepid
# lives on the proc superblock, which a sibling mount namespace cloned
# from this one SHARES; the sibling's remount bumps only ITS OWN
# namespace's event counter. This is the channel the latch NARROWS TO
# rather than closes — bounded to other-uid members, and a PERSISTING
# flip is still declared by the ordinary reads.
_SIBLING_FLIP_PROBE = _PROBE_PRELUDE + r'''
from core.sandbox import supervised as sup

CLONE_NEWNS = 0x00020000

flip_r, flip_w = os.pipe()
go_r, go_w = os.pipe()

fd = os.open("/proc/self/mounts", os.O_RDONLY)
assert not churn(fd), "fresh fd reports pending churn"

child = os.fork()
if child == 0:
    try:
        os.close(flip_r)
        os.close(go_w)
        if libc.unshare(CLONE_NEWNS) != 0:
            os._exit(3)
        # sibling mount ns, same userns: flip hidepid on the SHARED
        # proc superblock through this namespace's own /proc copy
        mount("proc", "/proc", "proc", MS_REMOUNT, "hidepid=2")
        os.write(flip_w, b"F")
        assert os.read(go_r, 1) == b"G"
        mount("proc", "/proc", "proc", MS_REMOUNT, "hidepid=off")
        os.write(flip_w, b"R")
        os._exit(0)
    except BaseException:
        os._exit(4)

os.close(flip_w)
os.close(go_r)
assert os.read(flip_r, 1) == b"F", "sibling never flipped"

# The flip is LIVE on the scanner's view (shared superblock renders in
# its table) and the persistent shape is declared by the ordinary
# read...
with open("/proc/self/mounts", "rb") as f:
    table = f.read()
assert b"hidepid" in table, "sibling flip invisible in scanner table"
declared = sup._proc_pid_view_filtered()
assert declared is not None and "hidepid" in declared, (
    f"persisting sibling flip not declared: {declared!r}")

# ...but the scanner's mount-event counter NEVER FIRED: the probed
# residual. A future kernel firing here upgrades the narrowing claim.
assert not churn(fd), (
    "sibling-ns superblock flip now bumps the scanner counter — "
    "kernel behaviour changed, upgrade the residual scope bound")

os.write(go_w, b"G")
assert os.read(flip_r, 1) == b"R", "sibling never reverted"
_, status = os.waitpid(child, 0)
assert status == 0, f"sibling exited abnormally: {status}"

assert not churn(fd), "flip-and-revert left a pending signal"
assert sup._proc_pid_view_filtered() is None, (
    "table not clean after revert")
os.close(fd)

print("SIBLING-FLIP-RESIDUAL-PINNED")
'''

# Design test: end-to-end two-sided evade. A cooperating harness
# overmounts /proc/<decoy> with a forged state-Z stat AFTER the scan's
# pre-read and detaches BEFORE the post-read (both declaration reads
# clean), on every scan attempt. Pre-fix code returns the forged
# member on a CLEAN view — the false death evidence that feeds the
# permanent _group_verified latch; fixed code returns occlusion.
_E2E_EVADE_PROBE = _PROBE_PRELUDE + r'''
from core.sandbox import supervised as sup

decoy = subprocess.Popen(["/bin/sleep", "300"], start_new_session=True)
pgid = decoy.pid
deadline = time.monotonic() + 10.0
while os.getpgid(decoy.pid) != pgid:
    assert time.monotonic() < deadline
    time.sleep(0.01)

forge = tempfile.mkdtemp(prefix="forge-")
# fields after the comm's ')': state(0) .. start_time(19)
fields = (["Z", "1", str(pgid), str(pgid), "0", "-1", "4194304"]
          + ["0"] * 12 + ["12345", "0", "0"])
with open(os.path.join(forge, "stat"), "w") as f:
    f.write(f"{pgid} (sleep) " + " ".join(fields) + "\n")

state = {"mounted": False}
calls = {"parse": 0, "read": 0}
real_parse = sup._proc_pid_view_filtered
real_read = getattr(sup, "_mounts_table_read", None)


def attach():
    mount(forge, f"/proc/{pgid}", None, MS_BIND, None)
    state["mounted"] = True


def detach():
    umount_detach(f"/proc/{pgid}")
    state["mounted"] = False


def parse_wrap(*args):
    # Pre-fix interleaving driver: the declaration read happens
    # INSIDE this call, so attach after odd (pre) calls and detach
    # before even (post) calls. Inert when the fixed code's table
    # reads are wrapped instead.
    calls["parse"] += 1
    odd = calls["parse"] % 2 == 1
    if real_read is None and not odd and state["mounted"]:
        detach()
    verdict = real_parse(*args)
    if real_read is None and odd and not state["mounted"]:
        attach()
    return verdict


sup._proc_pid_view_filtered = parse_wrap

if real_read is not None:
    def read_wrap(fd):
        # Fixed-code interleaving driver: attach after the pre-read
        # bytes leave the kernel, detach before the post-read bytes
        # are fetched — both declaration reads see a clean table, on
        # EVERY retry attempt (odd/even parity).
        calls["read"] += 1
        odd = calls["read"] % 2 == 1
        if not odd and state["mounted"]:
            detach()
        data = real_read(fd)
        if odd and not state["mounted"]:
            attach()
        return data

    sup._mounts_table_read = read_wrap

try:
    view = sup._group_sighted_members(pgid)
finally:
    if state["mounted"]:
        detach()
    decoy.kill()

assert view is not None, "/proc unlistable — harness broken"
sighted = [(m.pid, m.state) for m in view.members]
print("MEMBERS", sighted)
print("OCCLUSION", view.occlusion)
assert (pgid, b"Z") in sighted, (
    f"harness never served the forged stat: {sighted}")
assert view.occlusion is not None, (
    "two-sided evade returned a CLEAN view carrying forged state-Z "
    "death evidence for a LIVE member — the false-verify input")
print("E2E-EVADE-OCCLUDED")
'''

# Design test: magic-check red test. A non-procfs file bind-mounted at
# /proc/self/mounts feeds the scan an attacker-authored (clean-
# looking) table; the superblock-magic check on the latched fd must
# refuse it.
_MAGIC_CHECK_PROBE = _PROBE_PRELUDE + r'''
from core.sandbox import supervised as sup

fake_dir = tempfile.mkdtemp(prefix="fakemounts-")
fake = os.path.join(fake_dir, "mounts")
with open(fake, "w") as f:
    f.write("proc /proc proc rw,relatime 0 0\n")
mount(fake, "/proc/self/mounts", None, MS_BIND, None)
try:
    if hasattr(sup, "_fstatfs_f_type"):
        probe_fd = os.open("/proc/self/mounts", os.O_RDONLY)
        try:
            if sup._fstatfs_f_type(probe_fd) is None:
                print("SKIP: fstatfs unavailable — magic check "
                      "degrades to no signal by design")
                sys.exit(0)
        finally:
            os.close(probe_fd)
    view = sup._group_sighted_members(os.getpgrp())
finally:
    umount_detach("/proc/self/mounts")

assert view is not None
print("OCCLUSION", view.occlusion)
assert view.occlusion is not None, (
    "attacker-authored mounts table (non-procfs bind over "
    "/proc/self/mounts) read back as a CLEAN view")
print("MAGIC-OCCLUDED")
'''

# Design test: the post-scan task-read gap, end to end on the REAL
# consumer path. A group member whose thread-group leader
# pthread_exit()ed reads process-level Z while a worker thread runs on
# — the exact pathology the per-member /proc/<pid>/task death proof
# exists to refuse. The attack overmounts an EMPTY dir on /proc/<pid>
# immediately AFTER a scan's verdict poll has been consumed (the
# attach rides the poll seam, so it lands at the first instant the
# latch no longer covers): a task read taken after the scan then hits
# the FileNotFoundError arm and claims death. Gap-era code reads the
# task trees after the scan returned and VERIFIES the teardown of a
# live process (the permanent _group_verified false verify);
# in-window code read the task trees before the poll, so the verify
# is refused (or honestly retried until the member is genuinely
# dead) — never granted while a task still runs.
_POST_SCAN_TASK_FORGE_PROBE = _PROBE_PRELUDE + r'''
from core.sandbox import supervised as sup
from core.sandbox.supervised import (
    SupervisedTeardownError,
    spawn_supervised,
)


def live_tasks(pid):
    """Non-Z tasks of pid, read through whatever /proc serves now."""
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return []
    alive = []
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/stat", "rb") as f:
                tstate = f.read().rsplit(b")", 1)[1].split()[0]
        except (OSError, IndexError):
            continue
        if tstate != b"Z":
            alive.append(int(tid))
    return alive


zdir = tempfile.mkdtemp(prefix="zldr-")
zpath = os.path.join(zdir, "zleader.py")
with open(zpath, "w") as f:
    f.write(
        "import ctypes, signal, threading, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "threading.Thread(target=time.sleep, args=(300,)).start()\n"
        "ctypes.CDLL(None).pthread_exit(None)\n")

h = spawn_supervised(
    ["/bin/sh", "-c", f'"{sys.executable}" "{zpath}" & exit 0'],
    on_parent_death="kill", pid_ns="off",
    env={"PATH": "/usr/bin:/bin"})
pgid = h.pid  # start_new_session leader
assert h.wait(timeout=15) == 0  # natural leader exit; anchor captured

# The orphaned member reparents to the namespace init; wait for the
# split state: process-level Z, at least one live worker task.
member = None
deadline = time.monotonic() + 15.0
while time.monotonic() < deadline:
    found = []
    for e in os.listdir("/proc"):
        if not e.isdigit():
            continue
        try:
            with open(f"/proc/{e}/stat", "rb") as f:
                rest = f.read().rsplit(b")", 1)[1].split()
        except OSError:
            continue
        if rest and int(rest[2]) == pgid:
            found.append((int(e), rest[0]))
    zs = [p for p, st in found if st == b"Z"]
    if len(found) == 1 and zs and live_tasks(zs[0]):
        member = zs[0]
        break
    time.sleep(0.02)
assert member is not None, f"Z-leader/live-worker never reached: {found}"

# Arm the attack at the poll seam: the FIRST consumed verdict poll is
# the first instant outside the latched window — attach the forged
# (empty) view over /proc/<member> right there, and leave it standing
# (a persisting mask is the strongest form: later scans must declare
# it rather than trust it).
forge = tempfile.mkdtemp(prefix="gapforge-")
state = {"attached": False, "mount_err": None}
real_poll = sup._mounts_churn_pending


def poll_then_attach(fd):
    verdict = real_poll(fd)
    if not state["attached"] and state["mount_err"] is None:
        try:
            mount(forge, f"/proc/{member}", None, MS_BIND, None)
            state["attached"] = True
        except OSError as exc:
            state["mount_err"] = exc
    return verdict


sup._mounts_churn_pending = poll_then_attach

rc = None
try:
    try:
        rc = h.terminate(grace_s=1.0)
    except SupervisedTeardownError as exc:
        print(f"REFUSED: {exc}")
finally:
    sup._mounts_churn_pending = real_poll
    if state["attached"]:
        umount_detach(f"/proc/{member}")

if state["mount_err"] is not None:
    print(f"SKIP: cannot bind-mount over /proc/<pid> here "
          f"({state['mount_err']})")
    sys.exit(0)
assert state["attached"], "harness never armed the overmount"

if rc is not None:
    still = live_tasks(member)
    assert still == [], (
        f"FALSE-VERIFY rc={rc} live-tasks={still} — terminate() "
        f"verified the group dead off a task tree forged AFTER the "
        f"scan's verdict poll (the post-scan task-read gap)")
    print(f"VERIFIED-HONESTLY rc={rc} (member genuinely dead)")
print("POST-SCAN-TASK-FORGE-CAUGHT")
'''


class TestMountsLatchLive:
    def test_kernel_latch_contract(self, tmp_path):
        _run_probe(tmp_path, _KERNEL_CONTRACT_PROBE,
                   "KERNEL-CONTRACT-OK")

    def test_sibling_ns_superblock_flip_residual(self, tmp_path):
        _run_probe(tmp_path, _SIBLING_FLIP_PROBE,
                   "SIBLING-FLIP-RESIDUAL-PINNED")

    def test_two_sided_overmount_evade_is_occluded(self, tmp_path):
        _run_probe(tmp_path, _E2E_EVADE_PROBE, "E2E-EVADE-OCCLUDED")

    def test_forged_mounts_table_is_occluded(self, tmp_path):
        _run_probe(tmp_path, _MAGIC_CHECK_PROBE, "MAGIC-OCCLUDED")

    def test_post_scan_task_forge_cannot_verify(self, tmp_path):
        _run_probe(tmp_path, _POST_SCAN_TASK_FORGE_PROBE,
                   "POST-SCAN-TASK-FORGE-CAUGHT")
