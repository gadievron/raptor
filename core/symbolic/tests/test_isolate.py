"""Regression pins for the isolated-child symex sandbox.

The Landlock ruleset ``_apply_symex_sandbox`` installs must keep
``import angr`` working in the child: pyvex resolves
``tempfile.gettempdir()`` at import time (a probe that CREATES a
file) and unconditionally writes its ffi-parser cache there when
absent. A blanket write deny makes that import raise, the child's
availability guard then reports angr as uninstalled, and every
isolated primitive — overflow, reach, fmtstr, heap-mismatch —
degrades to an 'unavailable' result on hosts where angr IS
installed, while the parent-process probe keeps passing.

These tests run the sandbox in a real child process and pin the
contract: angr stays importable (the private-temp-dir write grant
works), scratch writes land inside the private directory, and —
when Landlock is engaged — file creation is denied both outside
the temp tree and in the SHARED system temp dir (a compromised
lifter/solver must not tamper with other same-user temp content).
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

#: Child probe: apply the sandbox exactly as ``_child_entry`` does
#: (private dir created by the parent, argv[1]), then report what the
#: resulting process can still do. argv[2] is a parent-created
#: directory OUTSIDE the temp tree, or the sentinel ``SKIP``. Runs as
#: ``python -c`` so no multiprocessing pickling is involved and the
#: sandbox never touches the pytest process itself.
_CHILD_PROBE = r"""
import json, os, sys, tempfile
sys.path.insert(0, os.environ["RAPTOR_DIR"])
from core.symbolic._isolate import _apply_symex_sandbox

shared_tmp = os.path.realpath(tempfile.gettempdir())
private_tmp = sys.argv[1]

_apply_symex_sandbox(private_tmp)

report = {"gettempdir": tempfile.gettempdir()}


def _probe_create(directory):
    # Randomised name: a pre-existing file must read as a failed
    # CREATE (O_EXCL), never as a spurious deny.
    name = "symex-sandbox-probe-%d-%s" % (os.getpid(), os.urandom(4).hex())
    path = os.path.join(directory, name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(path)
        return True
    except OSError:
        return False


report["private_write"] = _probe_create(private_tmp)
report["shared_tmp_write"] = _probe_create(shared_tmp)
report["outside_write"] = (
    _probe_create(sys.argv[2]) if sys.argv[2] != "SKIP" else None
)

try:
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"probe")
        report["scratch_in_private"] = f.name.startswith(private_tmp)
except OSError:
    report["scratch_in_private"] = False

try:
    import angr  # noqa: F401
    report["angr_import"] = "ok"
except BaseException as exc:  # noqa: BLE001 — report; parent asserts
    report["angr_import"] = f"{type(exc).__name__}: {exc}"

print(json.dumps(report))
"""


def _landlock_engageable() -> bool:
    """True when the host can actually install the sandbox ruleset
    (arch supported + Landlock ABI >= 1), mirroring the gates in
    ``_apply_symex_sandbox``."""
    if platform.machine() not in (
        "x86_64", "aarch64", "riscv64", "loongarch64", "s390x",
    ):
        return False
    import ctypes
    import ctypes.util
    lib_path = ctypes.util.find_library("c")
    if not lib_path:
        return False
    try:
        libc = ctypes.CDLL(lib_path, use_errno=True)
    except OSError:
        return False
    return libc.syscall(444, None, 0, 1) >= 1


def _outside_tmp_dir() -> str | None:
    """A writable directory OUTSIDE the temp tree, or None.

    pytest's tmp_path lives under the temp directory — inside the
    child's pre-sandbox view of it — so it cannot serve as the
    deny probe.
    """
    tmpdir = os.path.realpath(tempfile.gettempdir())
    home = os.path.realpath(os.path.expanduser("~"))
    if home == "/" or home == tmpdir or home.startswith(tmpdir + os.sep):
        return None
    if not os.access(home, os.W_OK):
        return None
    return home


@pytest.fixture(scope="module")
def sandbox_report() -> dict:
    """Run the child probe once; individual tests assert on slices."""
    outside = _outside_tmp_dir()
    outside_dir: str | None = None
    if outside is not None:
        outside_dir = tempfile.mkdtemp(
            prefix=".symex-isolate-test-", dir=outside,
        )
    private_dir = tempfile.mkdtemp(prefix="raptor-symex-test-")
    env = dict(os.environ)
    env["RAPTOR_DIR"] = str(_REPO_ROOT)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_PROBE,
             private_dir, outside_dir or "SKIP"],
            capture_output=True, text=True, timeout=120, env=env,
        )
    finally:
        import shutil
        shutil.rmtree(private_dir, ignore_errors=True)
        if outside_dir is not None:
            shutil.rmtree(outside_dir, ignore_errors=True)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.splitlines()[-1])


def test_angr_importable_inside_sandboxed_child(sandbox_report: dict):
    """import angr must survive the sandbox — otherwise every
    isolated primitive answers 'angr unavailable' on hosts where
    the parent's availability probe passes."""
    pytest.importorskip("angr")
    assert sandbox_report["angr_import"] == "ok"


def test_scratch_lands_in_private_dir(sandbox_report: dict):
    """The write grant itself: the child's tempfile use must work
    and must land inside the private per-child directory (pyvex's
    import-time cache write is the load-bearing consumer)."""
    assert sandbox_report["private_write"] is True
    assert sandbox_report["scratch_in_private"] is True
    assert sandbox_report["gettempdir"] == os.path.realpath(
        sandbox_report["gettempdir"],
    )


def test_sandbox_denies_shared_tmp_writes(sandbox_report: dict):
    """The deny half, shared-temp edition: with Landlock engaged,
    the child must not be able to create files in the SHARED system
    temp dir — only in its private directory."""
    if not _landlock_engageable():
        pytest.skip("Landlock unavailable on this host")
    assert sandbox_report["shared_tmp_write"] is False


def test_sandbox_denies_writes_outside_tempdir(sandbox_report: dict):
    """The deny half, non-temp edition: file creation outside the
    temp tree fails when Landlock is engaged."""
    if not _landlock_engageable():
        pytest.skip("Landlock unavailable on this host")
    if sandbox_report["outside_write"] is None:
        pytest.skip("no writable directory outside the temp tree")
    assert sandbox_report["outside_write"] is False


def test_private_dir_cleanup_defeats_permission_griefing(tmp_path: Path):
    """The parent's cleanup must survive a hostile child leaving a
    mode-0 subdirectory in its grant — otherwise per-call private
    dirs accumulate without bound."""
    from core.symbolic._isolate import _remove_private_tmp
    victim = tmp_path / "raptor-symex-victim"
    nested = victim / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "f").write_text("x")
    (victim / "a").chmod(0o000)
    try:
        _remove_private_tmp(str(victim))
        assert not victim.exists()
    finally:
        if victim.exists():  # restore perms so pytest tmp cleanup works
            (victim / "a").chmod(0o700)


def test_private_dir_cleanup_never_chmods_through_symlink(tmp_path: Path):
    """A hostile child can leave ``evil -> <outside dir>`` in its
    private tmp. os.walk lists the symlink-to-directory in dirnames
    even with followlinks=False, and os.chmod follows symlinks — so
    the pre-fix permission-restore walk applied 0700 to the symlink's
    TARGET, stripping group/other access from a directory outside the
    sandbox grant. The walk must skip links; the outside dir keeps its
    mode and survives, while the private tmp is still removed."""
    from core.symbolic._isolate import _remove_private_tmp
    outside = tmp_path / "outside"
    outside.mkdir()
    outside.chmod(0o755)
    private = tmp_path / "raptor-symex-private"
    private.mkdir()
    (private / "evil").symlink_to(outside)
    _remove_private_tmp(str(private))
    assert not private.exists()
    assert outside.exists()
    assert (outside.stat().st_mode & 0o777) == 0o755


def test_private_dir_cleanup_still_restores_real_subdir_perms(
        tmp_path: Path):
    """Fix regression guard for the other direction: with a symlink
    present alongside a mode-0 REAL subdirectory, the griefing defense
    must still restore and remove the real one."""
    from core.symbolic._isolate import _remove_private_tmp
    outside = tmp_path / "outside"
    outside.mkdir()
    private = tmp_path / "raptor-symex-private"
    nested = private / "a" / "b"
    nested.mkdir(parents=True)
    (private / "evil").symlink_to(outside)
    (private / "a").chmod(0o000)
    try:
        _remove_private_tmp(str(private))
        assert not private.exists()
        assert outside.exists()
    finally:
        if private.exists():  # restore perms so pytest tmp cleanup works
            (private / "a").chmod(0o700)


def _hang_forever() -> None:
    """Child payload for the budget-kill direction test."""
    import time as _time
    _time.sleep(300)


def test_child_crash_reported_as_crash_not_budget_kill():
    """A child that dies hard (SIGABRT here; segfault in the wild)
    closes the pipe long before the budget elapses — the report must
    say crash, not blame a budget overrun the wall clock contradicts."""
    from core.symbolic._isolate import run_isolated
    r = run_isolated("posix", "abort", {}, timeout=60.0)
    assert r.succeeded is False
    assert r.metadata.get("crashed") is True
    assert r.metadata.get("killed") is False
    assert "crash, not a budget kill" in r.reason
    assert r.wall_seconds < 60.0


def test_budget_overrun_still_reported_as_kill(monkeypatch):
    """Two-direction: a genuinely hung child keeps the hard-kill
    report (killed=True, budget language)."""
    import core.symbolic._isolate as iso
    monkeypatch.setattr(iso, "GRACE_SECONDS", 0.5)
    r = iso.run_isolated(
        "core.symbolic.tests.test_isolate", "_hang_forever", {},
        timeout=0.5,
    )
    assert r.succeeded is False
    assert r.metadata.get("killed") is True
    assert "budget" in r.reason


# ---------------------------------------------------------------------------
# Restricted result decoding (the child's ONE channel into the parent)
# ---------------------------------------------------------------------------
# The child is sandboxed because its inputs are hostile binaries; a
# plain pickle.loads on its output would hand a compromised child code
# execution in the unsandboxed parent — strictly more power than the
# filesystem/network vectors Landlock closes. The parent therefore
# decodes with an unpickler that can construct only SymbolicResult.


def _benign_result() -> "object":
    """Child payload: a representative legitimate result (bytes witness
    + nested builtin metadata, the richest shape engines produce)."""
    from core.symbolic._types import SymbolicResult
    return SymbolicResult(
        succeeded=True,
        reason="found reaching input",
        wall_seconds=0.25,
        concrete_input=b"\x00AAAA\xff",
        states_explored=7,
        metadata={"target_address": 0x401000,
                  "register_snapshot": {"rip": "0x41414141"},
                  "paths": [{"constraints": ["a<b"], "branch_count": 2}]},
    )


def _wrong_type_result() -> dict:
    """Child payload for the shape-check direction: allowed pieces,
    wrong top-level type."""
    return {"succeeded": True, "reason": "not a SymbolicResult"}


class _NotAResult:
    """Child payload whose class the restricted decoder must refuse."""


def _foreign_class_result() -> "_NotAResult":
    return _NotAResult()


def test_legit_result_round_trips_through_restricted_decoder():
    from core.symbolic._isolate import run_isolated
    r = run_isolated(
        "core.symbolic.tests.test_isolate", "_benign_result", {},
        timeout=60.0,
    )
    expected = _benign_result()
    assert r == expected


def test_restricted_decoder_refuses_code_execution_pickle(tmp_path: Path):
    """A crafted pickle whose REDUCE target is a real callable must be
    refused at find_class time — before the callable runs."""
    import pickle

    from core.symbolic._isolate import _loads_result

    canary = tmp_path / "pwned"

    class _Evil:
        def __reduce__(self):
            return (os.mkdir, (str(canary),))

    payload = pickle.dumps(_Evil())
    with pytest.raises(pickle.UnpicklingError, match="refusing to unpickle"):
        _loads_result(payload)
    assert not canary.exists(), (
        "the malicious pickle's callable RAN — the decoder is not "
        "restricting globals")


def test_wrong_type_payload_rejected_end_to_end():
    from core.symbolic._isolate import run_isolated
    r = run_isolated(
        "core.symbolic.tests.test_isolate", "_wrong_type_result", {},
        timeout=60.0,
    )
    assert r.succeeded is False
    assert r.metadata.get("rejected_payload") is True
    assert "refused" in r.reason


def test_foreign_class_payload_rejected_end_to_end():
    from core.symbolic._isolate import run_isolated
    r = run_isolated(
        "core.symbolic.tests.test_isolate", "_foreign_class_result", {},
        timeout=60.0,
    )
    assert r.succeeded is False
    assert r.metadata.get("rejected_payload") is True


# ---------------------------------------------------------------------------
# Deadline-bounded result frame read (hostile-child parent-hang defense)
# ---------------------------------------------------------------------------
# poll() proves ONE byte is readable; Connection.recv_bytes then blocks
# until the whole length-prefixed frame arrives. A compromised child
# (this module's stated adversary) could write a partial frame and
# sleep, parking the unsandboxed parent forever — the hard-kill budget,
# the one guarantee _isolate exists to provide, never fired. The frame
# read is therefore select-gated against the budget deadline.


def _pipe_pair():
    import multiprocessing as _mp
    return _mp.Pipe(duplex=False)


def test_partial_header_read_returns_none_at_deadline():
    import time as _time

    import core.symbolic._isolate as iso
    reader, writer = _pipe_pair()
    try:
        os.write(writer.fileno(), b"\x00\x00")  # half a length header
        payload = iso._recv_frame_deadline(
            reader, _time.monotonic() + 0.2, 1 << 20,
        )
        assert payload is None
    finally:
        reader.close()
        writer.close()


def test_partial_payload_read_returns_none_at_deadline():
    import struct as _struct
    import time as _time

    import core.symbolic._isolate as iso
    reader, writer = _pipe_pair()
    try:
        # Full header declaring 100 bytes, then only 10 arrive.
        os.write(writer.fileno(), _struct.pack("!i", 100) + b"x" * 10)
        payload = iso._recv_frame_deadline(
            reader, _time.monotonic() + 0.2, 1 << 20,
        )
        assert payload is None
    finally:
        reader.close()
        writer.close()


def test_complete_frame_round_trips():
    import time as _time

    import core.symbolic._isolate as iso
    reader, writer = _pipe_pair()
    try:
        writer.send_bytes(b"a" * 100)
        payload = iso._recv_frame_deadline(
            reader, _time.monotonic() + 5.0, 1 << 20,
        )
        assert payload == b"a" * 100
    finally:
        reader.close()
        writer.close()


def test_over_cap_and_malformed_headers_refused():
    import struct as _struct
    import time as _time

    import core.symbolic._isolate as iso
    for header in (
        _struct.pack("!i", 2048),   # over the 1024 cap below
        _struct.pack("!i", -1),     # >2 GiB escape frame
        _struct.pack("!i", -7),     # malformed negative size
    ):
        reader, writer = _pipe_pair()
        try:
            os.write(writer.fileno(), header)
            with pytest.raises(iso._FrameRefused):
                iso._recv_frame_deadline(
                    reader, _time.monotonic() + 5.0, 1024,
                )
        finally:
            reader.close()
            writer.close()


def test_closed_pipe_mid_frame_raises_eoferror():
    import time as _time

    import core.symbolic._isolate as iso
    reader, writer = _pipe_pair()
    try:
        os.write(writer.fileno(), b"\x00\x00")
        writer.close()
        with pytest.raises(EOFError):
            iso._recv_frame_deadline(
                reader, _time.monotonic() + 5.0, 1 << 20,
            )
    finally:
        reader.close()


def test_high_fd_frame_read_bounded_past_fd_setsize():
    """fds at/past FD_SETSIZE (1024) must still get the deadline-bounded
    read: ``select.select()`` raises ValueError there, which would
    escape run_isolated's handler set — the honest result is never
    returned AND the kill escalation is skipped, leaking a live child
    on a fully legitimate many-fd run. The selector-based wait
    (epoll/kqueue) has no such limit."""
    import fcntl
    import resource
    import struct as _struct
    import time as _time
    import types as _types

    import core.symbolic._isolate as iso

    high_fd = 1100  # past FD_SETSIZE (1024)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft <= high_fd + 8:
        if hard != resource.RLIM_INFINITY and hard <= high_fd + 8:
            pytest.skip(
                "RLIMIT_NOFILE hard limit too low to place an fd past "
                "FD_SETSIZE"
            )
        resource.setrlimit(resource.RLIMIT_NOFILE, (high_fd + 64, hard))
    try:
        reader, writer = _pipe_pair()
        try:
            # F_DUPFD (lowest free fd >= high_fd) — never clobbers an
            # fd some other part of the test process owns.
            dup = fcntl.fcntl(reader.fileno(), fcntl.F_DUPFD, high_fd)
            try:
                assert dup >= 1024
                conn = _types.SimpleNamespace(fileno=lambda: dup)
                # A complete frame round-trips at the high fd...
                writer.send_bytes(b"a" * 50)
                payload = iso._recv_frame_deadline(
                    conn, _time.monotonic() + 5.0, 1 << 20,
                )
                assert payload == b"a" * 50
                # ...and a partial frame still takes the deadline lane
                # (None -> the caller's kill escalation), not an
                # escaping ValueError.
                os.write(writer.fileno(), _struct.pack("!i", 100) + b"x")
                assert iso._recv_frame_deadline(
                    conn, _time.monotonic() + 0.2, 1 << 20,
                ) is None
            finally:
                os.close(dup)
        finally:
            reader.close()
            writer.close()
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_mid_frame_deadline_takes_the_kill_lane(monkeypatch):
    """A frame still incomplete at the deadline is a budget overrun:
    run_isolated must fall through to the terminate/kill escalation
    and report the honest timeout result, never hang or mislabel."""
    import core.symbolic._isolate as iso
    monkeypatch.setattr(
        iso, "_recv_frame_deadline",
        lambda conn, deadline, maxlength: None,
    )
    monkeypatch.setattr(iso, "GRACE_SECONDS", 0.5)
    r = iso.run_isolated(
        "core.symbolic.tests.test_isolate", "_benign_result", {},
        timeout=0.5,
    )
    assert r.succeeded is False
    assert r.metadata.get("killed") is True
    assert "budget" in r.reason


def test_oversized_payload_rejected(monkeypatch):
    """Cap direction: a payload over _MAX_RESULT_BYTES is refused
    (the round-trip test above covers the under-cap direction)."""
    import core.symbolic._isolate as iso
    monkeypatch.setattr(iso, "_MAX_RESULT_BYTES", 4096)
    r = iso.run_isolated(
        "core.symbolic.tests.test_isolate", "_benign_result", {},
        timeout=60.0,
    )
    # _benign_result pickles far under 4096 bytes — grow it instead.
    assert r.succeeded is True  # sanity: small result still fits

    monkeypatch.setattr(iso, "_MAX_RESULT_BYTES", 16)
    r = iso.run_isolated(
        "core.symbolic.tests.test_isolate", "_benign_result", {},
        timeout=60.0,
    )
    assert r.succeeded is False
    assert r.metadata.get("rejected_payload") is True
    assert "cap" in r.reason
