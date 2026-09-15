"""_copy_etc_tree: the etc_overlay tmpfs+copy helper.

Regression targets: the helper (formerly ``_copy_dir_shallow`` — a
misnomer, it was always recursive) flattened permissions to 0644/0755,
turning group/other-restricted host /etc files into world-readable
copies inside the sandbox. Mode bits are now preserved on both the
byte-copy and mkdir paths (the hard-link fast path shares the source
inode and preserves them inherently)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from core.sandbox.mount_ns import _copy_etc_tree


@pytest.fixture(autouse=True)
def hostile_umask():
    """Force a restrictive umask for every test in this file.

    Mode preservation must hold under ANY runner umask: mkfifo(2)'s
    and mkdir(2)'s mode arguments are umask-masked, so a permissive
    local umask (e.g. 0o002) hides a missing chmod that a CI umask
    of 0o022 — or a paranoid 0o077 — exposes. Pinning the harshest
    common value makes the assertions deterministic everywhere.
    """
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture
def src_tree(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    f = src / "restricted.conf"
    f.write_text("secret=1\n")
    os.chmod(f, 0o640)
    g = src / "sub" / "open.conf"
    g.write_text("x=1\n")
    os.chmod(g, 0o644)
    os.chmod(src / "sub", 0o750)
    (src / "link.conf").symlink_to("restricted.conf")
    return src


def _copy(monkeypatch, src, dst, *, force_byte_copy):
    if force_byte_copy:
        def _no_link(*a, **k):
            raise OSError("cross-device")
        monkeypatch.setattr(os, "link", _no_link)
    dst.mkdir()
    _copy_etc_tree(str(src), str(dst))


@pytest.mark.parametrize("force_byte_copy", [True, False])
def test_mode_bits_preserved(tmp_path, monkeypatch, src_tree,
                             force_byte_copy):
    dst = tmp_path / f"dst-{force_byte_copy}"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=force_byte_copy)

    assert (dst / "restricted.conf").read_text() == "secret=1\n"
    assert stat.S_IMODE(
        os.lstat(dst / "restricted.conf").st_mode) == 0o640
    assert stat.S_IMODE(
        os.lstat(dst / "sub" / "open.conf").st_mode) == 0o644
    assert stat.S_IMODE(os.lstat(dst / "sub").st_mode) == 0o750


def test_symlinks_recreated_as_symlinks(tmp_path, monkeypatch, src_tree):
    dst = tmp_path / "dst"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
    link = dst / "link.conf"
    assert link.is_symlink()
    assert os.readlink(link) == "restricted.conf"


def test_fifo_never_wedges_the_copy(tmp_path, monkeypatch, src_tree):
    """A FIFO in /etc must not block the copy: the destination is a
    fresh tmpfs, so the hard-link fast path always fails EXDEV and the
    byte-copy fallback used to open(2) the FIFO — blocking forever
    when it has no writer, wedging sandbox setup until the caller's
    timeout. FIFOs are recreated with mkfifo instead."""
    import threading

    fifo_src = src_tree / "wedge.fifo"
    os.mkfifo(fifo_src)
    os.chmod(fifo_src, 0o620)  # exact source mode, umask-independent
    dst = tmp_path / "dst"

    done = threading.Event()

    def _run():
        _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
        done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert done.wait(10), "_copy_etc_tree blocked on the FIFO"

    fifo = dst / "wedge.fifo"
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)
    assert stat.S_IMODE(os.lstat(fifo).st_mode) == 0o620
    # The rest of the tree still copied.
    assert (dst / "restricted.conf").read_text() == "secret=1\n"


def test_socket_entries_skipped_silently(tmp_path, monkeypatch):
    """Unix sockets in /etc cannot be copied or usefully recreated —
    they must be skipped, never opened.

    The socket is bound in a short mkdtemp under /tmp rather than in
    pytest's tmp_path: struct sockaddr_un's sun_path is 104 bytes on
    macOS/BSD and 108 on Linux (NUL included), and macOS runners'
    per-user tmp trees (/private/var/folders/...) blow that budget —
    bind() fails "AF_UNIX path too long". Same short-base approach as
    core/sandbox/proxy.py make_lane_dir.
    """
    import shutil
    import socket as socket_mod
    import tempfile

    base = tempfile.mkdtemp(prefix=".raptor-etc-", dir="/tmp")
    try:
        src = Path(base) / "src"
        src.mkdir()
        (src / "regular.conf").write_text("x=1\n")
        sock_path = src / "agent.sock"
        # Belt-and-braces: /tmp/.raptor-etc-XXXXXXXX/src/agent.sock is
        # ~40 bytes, comfortably inside both platforms' budgets.
        assert len(str(sock_path).encode()) <= 100, (
            f"socket path {sock_path} exceeds the 100-byte sun_path "
            f"budget; short-base construction is broken"
        )
        s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        s.bind(str(sock_path))
        try:
            dst = tmp_path / "dst"
            _copy(monkeypatch, src, dst, force_byte_copy=True)
            assert not (dst / "agent.sock").exists()
            assert (dst / "regular.conf").exists()
        finally:
            s.close()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_unreadable_entries_skipped_silently(tmp_path, monkeypatch,
                                             src_tree):
    if os.geteuid() == 0:
        pytest.skip("root reads anything; unreadable fixture is moot")
    shadow = src_tree / "shadow"
    shadow.write_text("root:!:19000\n")
    os.chmod(shadow, 0o000)
    dst = tmp_path / "dst"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
    assert not (dst / "shadow").exists()
    # The rest of the tree still copied.
    assert (dst / "restricted.conf").exists()


# ----------------------------------------------------------------------
# /etc/skel skip + total copy budget: the copy is for config files —
# it must never crawl a runner image's toolchain payload (rustup /
# nvm / dotnet stores stuffed into /etc/skel) into the tests' (or a
# run's) timeout, and root-level config files are never the casualty
# when a budget trips.
# ----------------------------------------------------------------------


@pytest.fixture
def phase_trace(tmp_path, monkeypatch):
    trace = tmp_path / "phase-trace.log"
    monkeypatch.setenv("RAPTOR_SANDBOX_PHASE_TRACE", str(trace))
    return trace


def _read_trace(trace) -> str:
    try:
        return trace.read_text()
    except OSError:
        return ""


def test_top_level_skel_never_copied(tmp_path, monkeypatch, phase_trace):
    """/etc/skel is a new-user home TEMPLATE tree no sandboxed target
    consumes; it is skipped entirely, with a loud named trace marker.
    A nested directory that happens to be called 'skel' is NOT
    affected — only the top level of the copied tree."""
    src = tmp_path / "src"
    (src / "skel" / ".cargo" / "bin").mkdir(parents=True)
    (src / "skel" / ".cargo" / "bin" / "rustup").write_bytes(b"\x7fELF" * 4)
    (src / "sub" / "skel").mkdir(parents=True)
    (src / "sub" / "skel" / "keep.conf").write_text("kept\n")
    (src / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    dst = tmp_path / "dst"
    _copy(monkeypatch, src, dst, force_byte_copy=True)

    assert not (dst / "skel").exists()
    assert (dst / "passwd").exists()
    assert (dst / "sub" / "skel" / "keep.conf").read_text() == "kept\n"
    trace = _read_trace(phase_trace)
    assert "etc copy skip: " in trace
    assert str(src / "skel") in trace
    assert "never copied" in trace


def test_entry_budget_stops_copy_root_files_survive(
        tmp_path, monkeypatch, phase_trace):
    """Hitting the entry budget stops the copy loudly and setup
    continues — and breadth-first ordering means every root-level
    file is already in place when it trips."""
    import core.sandbox.mount_ns as mns

    src = tmp_path / "src"
    src.mkdir()
    root_files = [f"conf{i:02d}" for i in range(8)]
    for name in root_files:
        (src / name).write_text(f"{name}\n")
    deep = src / "payload" / "store" / "tree"
    deep.mkdir(parents=True)
    for i in range(64):
        (deep / f"blob{i:03d}").write_text("x" * 32)

    monkeypatch.setattr(mns, "_ETC_COPY_MAX_ENTRIES", 24)
    dst = tmp_path / "dst"
    _copy(monkeypatch, src, dst, force_byte_copy=True)

    for name in root_files:
        assert (dst / name).exists(), (
            f"root-level {name} lost to the budget — ordering broken")
    copied_blobs = list((dst / "payload" / "store" / "tree").glob("blob*")) \
        if (dst / "payload" / "store" / "tree").is_dir() else []
    assert len(copied_blobs) < 64, "budget did not stop the deep copy"
    trace = _read_trace(phase_trace)
    assert "etc copy budget exceeded (entries=" in trace
    assert "skipping remaining entries" in trace


def test_byte_budget_skips_oversized_file_and_continues(
        tmp_path, monkeypatch, phase_trace):
    """A file larger than the remaining byte budget is skipped
    individually (loud marker); smaller entries keep copying."""
    import core.sandbox.mount_ns as mns

    src = tmp_path / "src"
    src.mkdir()
    (src / "aa-small.conf").write_text("ok\n")
    (src / "bb-huge.bin").write_bytes(b"\x00" * 4096)
    (src / "cc-small.conf").write_text("also ok\n")

    monkeypatch.setattr(mns, "_ETC_COPY_MAX_BYTES", 1024)
    dst = tmp_path / "dst"
    _copy(monkeypatch, src, dst, force_byte_copy=True)

    assert (dst / "aa-small.conf").exists()
    assert not (dst / "bb-huge.bin").exists()
    assert (dst / "cc-small.conf").exists(), (
        "copy stopped at the oversized file instead of skipping it")
    trace = _read_trace(phase_trace)
    assert "etc copy skip (size budget): " in trace
    assert "bb-huge.bin" in trace


def test_trace_cap_marker_names_why_entries_stop(
        tmp_path, monkeypatch, phase_trace):
    """The 4096 per-entry trace cap bounds TRACE LINES, not the copy:
    past it a single marker records that markers stopped while the
    copy continues."""
    import core.sandbox.mount_ns as mns

    src = tmp_path / "src"
    src.mkdir()
    for i in range(12):
        (src / f"f{i:02d}").write_text("x\n")
    monkeypatch.setattr(mns, "_PHASE_TRACE_MAX_ENTRIES", 5)
    dst = tmp_path / "dst"
    _copy(monkeypatch, src, dst, force_byte_copy=True)

    # ALL files copied — the cap must not bound the copy itself.
    for i in range(12):
        assert (dst / f"f{i:02d}").exists()
    trace = _read_trace(phase_trace)
    assert trace.count("etc copy entry: ") == 5
    assert "per-entry markers capped at 5 (copy continues)" in trace


def test_runner_shaped_etc_completes_fast(tmp_path, monkeypatch,
                                          phase_trace):
    """A runner-image-shaped /etc — config files plus a toolchain-
    stuffed skel (many entries, multi-MB binaries) — copies in
    milliseconds: skel is never entered, so its size is irrelevant.
    (Locally proven against a planted 100k-entry / 200MB skel; the
    committed fixture keeps CI runtime negligible while exercising
    the same code path.)"""
    from core.testing.wallclock import cpu_budget

    src = tmp_path / "src"
    (src / "ssl" / "certs").mkdir(parents=True)
    (src / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    (src / "hosts").write_text("127.0.0.1 localhost\n")
    (src / "resolv.conf").write_text("nameserver 127.0.0.53\n")
    (src / "ssl" / "certs" / "ca-certificates.crt").write_text("PEM\n")
    skel = src / "skel"
    for sub in (".cargo/bin", ".dotnet/tools/.store", ".nvm/test"):
        (skel / sub).mkdir(parents=True)
    for i in range(400):
        (skel / ".nvm" / "test" / f"case-{i:04d}").write_text("t\n")
    for name in ("rustup", "cargo", "rustc"):
        (skel / ".cargo" / "bin" / name).write_bytes(b"\x7fELF" + b"\x00" * (2 << 20))

    dst = tmp_path / "dst"
    # CPU budget, not wall clock: a disengaged skel skip/budget shows
    # up as CPU+sys time walking and copying the toolchain-stuffed
    # skel; a loaded runner only stalls wall time.
    with cpu_budget(2.0, what="runner-shaped /etc copy"):
        _copy(monkeypatch, src, dst, force_byte_copy=True)
    assert not (dst / "skel").exists()
    for f in ("passwd", "hosts", "resolv.conf"):
        assert (dst / f).exists()
    assert (dst / "ssl" / "certs" / "ca-certificates.crt").exists()
