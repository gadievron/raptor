"""End-to-end Landlock availability probe: shape parity + regression.

The availability probe exists to predict whether the enforcement
closure's install will succeed. Historically the probe created a
minimal 16-byte, ABI-1-shaped ruleset while the worker installed the
full 24-byte, ABI-masked one — a supervisor (container runtime,
hardened seccomp profile) that admits the small shape but refuses the
full one made the probe say "capable" and the install fail, turning
the fail-closed parser jail into an every-request
ParserJailUnavailable storm.

Two layers pin the fix:

- Shape parity units: the probe and the closure both build their
  masks/structs from the single module-level UAPI block, and those
  values match the kernel UAPI exactly (sizes and bits are
  load-bearing: the syscall takes sizeof(attr) as an argument).
- Regression (linux/x86_64, real-Landlock hosts): under a seccomp
  filter that EPERMs landlock_create_ruleset for any attr larger than
  16 bytes — the exact probe/install-disagreement supervisor shape —
  the probe must now answer False and the parser jail must come up
  DEGRADED and serve, instead of storming.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

from core.sandbox import landlock

# ---------------------------------------------------------------------------
# shape parity: masks
# ---------------------------------------------------------------------------

# Full ABI-1 write mask: WRITE_FILE + REMOVE_* + MAKE_* — everything a
# v1 kernel can handle. Values are the kernel UAPI, so the expected
# constants here are spelled as literals on purpose (a typo in the
# module constants must not self-verify).
_ABI1_WRITE = 0x1FF2


class TestMaskHelpers:
    @pytest.mark.parametrize(
        ("abi", "expected"),
        [
            (1, _ABI1_WRITE),
            (2, _ABI1_WRITE | 0x2000),            # + REFER
            (3, _ABI1_WRITE | 0x2000 | 0x4000),   # + TRUNCATE
            (4, _ABI1_WRITE | 0x2000 | 0x4000),   # net bit is separate
            (5, _ABI1_WRITE | 0x2000 | 0x4000 | 0x8000),  # + IOCTL_DEV
            (8, _ABI1_WRITE | 0x2000 | 0x4000 | 0x8000),
        ],
    )
    def test_write_mask_tracks_abi(self, abi: int, expected: int) -> None:
        assert landlock._write_mask_for_abi(abi) == expected

    def test_read_mask(self) -> None:
        assert landlock._read_mask() == 0xC  # READ_FILE | READ_DIR

    @pytest.mark.parametrize(
        ("abi", "expected"),
        [(1, 0), (3, 0), (4, 0x2), (8, 0x2)],
    )
    def test_net_mask_gated_on_abi4(self, abi: int, expected: int) -> None:
        assert landlock._net_mask_for_abi(abi) == expected

    @pytest.mark.parametrize(
        ("abi", "expected"),
        [(1, 0), (5, 0), (6, 0x3), (8, 0x3)],
    )
    def test_scoped_mask_gated_on_abi6(self, abi: int, expected: int) -> None:
        assert landlock._scoped_mask_for_abi(abi) == expected


# ---------------------------------------------------------------------------
# shape parity: structs (sizeof rides the syscall as an argument — the
# probe/install disagreement WAS a sizeof disagreement)
# ---------------------------------------------------------------------------


class TestStructShapes:
    def test_ruleset_attr_is_full_three_field_shape(self) -> None:
        # 3 x u64: handled_access_fs, handled_access_net, scoped.
        assert ctypes.sizeof(landlock._RulesetAttr) == 24
        assert [f[0] for f in landlock._RulesetAttr._fields_] == [
            "handled_access_fs", "handled_access_net", "scoped",
        ]

    def test_path_beneath_attr(self) -> None:
        # u64 allowed_access + s32 parent_fd. The kernel UAPI struct is
        # packed to 12 bytes; ctypes pads the tail to 16, which is fine
        # because add_rule takes no size argument — the kernel reads
        # exactly its packed 12 bytes, so the FIELD OFFSETS (0 and 8)
        # are what is load-bearing here.
        assert [f[0] for f in landlock._PathBeneathAttr._fields_] == [
            "allowed_access", "parent_fd",
        ]
        assert landlock._PathBeneathAttr.allowed_access.offset == 0
        assert landlock._PathBeneathAttr.parent_fd.offset == 8

    def test_net_port_attr(self) -> None:
        assert ctypes.sizeof(landlock._NetPortAttr) == 16
        assert [f[0] for f in landlock._NetPortAttr._fields_] == [
            "allowed_access", "port",
        ]


# ---------------------------------------------------------------------------
# shape parity: probe vs closure, header-independent
# ---------------------------------------------------------------------------


class _CreateRecorder:
    """libc stand-in that records the landlock_create_ruleset attr and
    refuses it, stopping either installer right after the capture."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.seen: dict[str, int] = {}

    def syscall(self, nr: int, *args: object) -> int:
        if nr == landlock._SYS_LANDLOCK_CREATE:
            attr = args[0]._obj  # type: ignore[attr-defined]
            self.seen["fs"] = attr.handled_access_fs
            self.seen["net"] = attr.handled_access_net
            self.seen["scoped"] = attr.scoped
            self.seen["size"] = args[1]
        return -1

    def prctl(self, *args: object) -> int:
        return -1


class TestProbeClosureParity:
    """Header-independent drift pin: the closure's create-time ruleset
    attr must equal the probe's, field for field, per ABI.

    The UAPI-literal pins above catch a drifted mask only on hosts
    with /usr/include/linux/landlock.h installed, and the live seccomp
    regression cannot catch CLOSURE-side drift by construction (under
    the filter the probe answers False, so the closure never runs).
    This pin needs neither header nor kernel: it records what each
    side actually passes to landlock_create_ruleset and compares. An
    install-side mask ORed with a bit the probe does not carry — the
    probe/install disagreement re-opened from the install side —
    fails here on every host.
    """

    @pytest.mark.parametrize("abi", [1, 4, 8])
    def test_closure_create_attr_equals_probe_attr(
            self, abi: int, tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> None:
        # Probe side: the worker-shaped self-test child under a
        # recorder (create refused -> child reports broken after the
        # capture; the verdict is not under test here).
        probe_file = tmp_path / "probe"
        probe_file.write_text("x")
        grant_dir = tmp_path / "grant"
        grant_dir.mkdir()
        grant_file = grant_dir / "readable"
        grant_file.write_text("x")
        probe_rec = _CreateRecorder()
        assert landlock._run_selftest_in_child(
            probe_rec, abi, str(probe_file), str(grant_dir),
            str(grant_file)) == 0
        assert probe_rec.seen, "recorder never saw the probe's create"

        # Closure side: strictest consumer posture (restricted reads +
        # deny-all TCP — the parser-jail worker's shape), built against
        # the same ABI, create intercepted by the same recorder class.
        closure_recs: "list[_CreateRecorder]" = []

        def _fake_cdll(*args: object, **kwargs: object) -> _CreateRecorder:
            rec = _CreateRecorder()
            closure_recs.append(rec)
            return rec

        monkeypatch.setattr(landlock, "_get_landlock_abi", lambda: abi)
        monkeypatch.setattr(
            landlock, "check_landlock_available", lambda: True)
        monkeypatch.setattr(ctypes, "CDLL", _fake_cdll)
        writable = tmp_path / "out"
        writable.mkdir()
        apply_landlock = landlock._make_landlock_preexec(
            [str(writable)], readable_paths=[str(grant_dir)],
            deny_all_tcp_connect=True, fail_raise=True)
        with pytest.raises(landlock.LandlockInstallError):
            apply_landlock()

        seen = [rec.seen for rec in closure_recs if rec.seen]
        assert len(seen) == 1, "expected exactly one closure create"
        assert seen[0] == probe_rec.seen


# ---------------------------------------------------------------------------
# regression: probe/install disagreement supervisor
# ---------------------------------------------------------------------------

_FILTER_RUNNER = '''\
"""Run under a seccomp filter that EPERMs landlock_create_ruleset(2)
for any ruleset attr larger than 16 bytes, then report what the probe
and the parser jail do. argv[1] = repo dir."""
import ctypes
import ctypes.util
import json
import os
import struct
import sys


def install_filter() -> None:
    PR_SET_NO_NEW_PRIVS = 38
    PR_SET_SECCOMP = 22
    SECCOMP_MODE_FILTER = 2
    AUDIT_ARCH_X86_64 = 0xC000003E
    SYS_LANDLOCK_CREATE = 444
    EPERM = 1
    BPF_LD_W_ABS = 0x20
    BPF_JEQ_K = 0x15
    BPF_JGT_K = 0x25
    BPF_RET_K = 0x06
    RET_ALLOW = 0x7FFF0000
    RET_ERRNO = 0x00050000

    def insn(code: int, jt: int, jf: int, k: int) -> bytes:
        return struct.pack("<HBBI", code, jt, jf, k)

    prog_bytes = b"".join([
        insn(BPF_LD_W_ABS, 0, 0, 4),                 # A = arch
        insn(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        insn(BPF_RET_K, 0, 0, RET_ALLOW),            # foreign arch
        insn(BPF_LD_W_ABS, 0, 0, 0),                 # A = nr
        insn(BPF_JEQ_K, 1, 0, SYS_LANDLOCK_CREATE),
        insn(BPF_RET_K, 0, 0, RET_ALLOW),            # other syscall
        insn(BPF_LD_W_ABS, 0, 0, 16 + 8 * 1),        # A = args[1] lo
        insn(BPF_JGT_K, 1, 0, 16),                   # size > 16 -> +1
        insn(BPF_RET_K, 0, 0, RET_ALLOW),            # minimal shape ok
        insn(BPF_RET_K, 0, 0, RET_ERRNO | EPERM),    # full shape EPERM
    ])
    buf = ctypes.create_string_buffer(prog_bytes, len(prog_bytes))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = SockFprog(len(prog_bytes) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                  ctypes.byref(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def main() -> int:
    repo = sys.argv[1]
    sys.path.insert(0, repo)
    os.environ["RAPTOR_DIR"] = repo
    os.chdir(repo)
    install_filter()

    from core.sandbox.landlock import check_landlock_available
    probe = check_landlock_available()

    from core.sandbox import parser_jail
    result: dict = {"probe": probe}
    try:
        jail = parser_jail.get_parser_jail()
    except parser_jail.ParserJailUnavailable as exc:
        result["storm"] = str(exc)
        print(json.dumps(result))
        return 0
    verdict = jail.parse(b"CONNECT example.com:443 HTTP/1.1")
    result["landlocked"] = jail.landlocked
    result["parse_ok"] = bool(getattr(verdict, "host", None) == "example.com")
    parser_jail._reset_for_tests()
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _repo_dir() -> Path:
    # Test files run outside the launcher (bare pytest, CI) — locate
    # the repo from this file's position, not RAPTOR_DIR.
    return Path(__file__).resolve().parents[3]


@pytest.mark.skipif(sys.platform != "linux", reason="seccomp is Linux-only")
@pytest.mark.skipif(platform.machine() != "x86_64",
                    reason="BPF filter is x86_64-specific")
class TestProbeInstallAgreementUnderSeccomp:
    def test_size_discriminating_filter_yields_degraded_not_storm(
        self, tmp_path: Path,
    ) -> None:
        """The historical failure shape, reproduced: a supervisor that
        admits a 16-byte create and refuses a bigger one. Post-fix the
        probe creates the worker-shaped ruleset, so it must answer
        False here and the jail must serve degraded — a storm
        (ParserJailUnavailable) means the probe and the install have
        drifted apart again."""
        if not landlock.check_landlock_available():
            pytest.skip("host kernel lacks functional Landlock — the "
                        "filter would not discriminate probe vs install")
        import json

        runner = tmp_path / "filter_runner.py"
        runner.write_text(_FILTER_RUNNER, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            [sys.executable, str(runner), str(_repo_dir())],
            capture_output=True, timeout=120, env=env, check=False,
        )
        assert proc.returncode == 0, (
            f"runner failed rc={proc.returncode}\n"
            f"stderr:\n{proc.stderr.decode('utf-8', 'backslashreplace')}")
        result = json.loads(proc.stdout.decode("utf-8"))
        assert "storm" not in result, (
            "probe/install disagreement is back: probe="
            f"{result['probe']} but the jail stormed: {result['storm']}")
        assert result["probe"] is False, (
            "probe claimed capable under a filter that refuses the "
            "worker-shaped create — probe shape has drifted from the "
            "install shape")
        assert result["landlocked"] is False  # degraded tier, honestly
        assert result["parse_ok"] is True     # ...and still serving
