"""WSL Windows-interop/driver masking in the mount-ns profile.

On a WSL host the mount-ns view would otherwise leak the
Windows-interop plumbing: the binfmt_misc registration mount rides
the recursive /proc bind, /usr/lib/wsl rides the /usr system bind,
and — closed structurally rather than by a mask — /run/WSL (fresh
/run tmpfs) and /dev/dxg (minimal /dev) never enter the view at all.
Interop matters because it lets sandboxed code reach WINDOWS-side
process execution that no Linux containment layer governs.

Two test layers:

* Profile-content assertions (in-process, ``_mount`` stubbed to a
  recorder — the same mechanism test_mount_ns_step_diagnostic uses):
  the mask mounts appear in the plan exactly when WSL is detected,
  the plan is unchanged off-WSL (the inertness pin), and the
  masked-path refusal keeps caller readable binds from re-granting
  the masked/structurally-absent surfaces.
* Functional probes (real mount-ns spawn on this host, WSL detection
  mocked at the ``core.startup.wsl`` module attributes, which the
  forked sandbox child inherits): the binfmt_misc view really is
  emptied, and really is host-real off-WSL.

The /usr/lib/wsl mask mount and the on-WSL end-to-end behaviour of
the whole set are additionally [verify-live] on a real WSL2 box —
this host has no /usr/lib/wsl and its kernel is not WSL.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import mount_ns
from core.sandbox.tests.capability import requires_mount
from core.startup import wsl as startup_wsl

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux mount-ns"),
    pytest.mark.wsl,
]

_BINFMT = "/proc/sys/fs/binfmt_misc"
_WSL_LIB = "/usr/lib/wsl"

# A system-dir interpreter: the venv/user python lives outside the
# mount-ns bind tree (see test_mount_ns_minimal_dev for the rationale).
_PY = "/usr/bin/python3"


def _mock_wsl(monkeypatch, *, wsl: bool) -> None:
    """Pin the WSL verdict at the module attributes consumers read.

    Both flavour predicates are pinned coherently (a mocked-WSL host
    is a WSL2 host — is_wsl1() must stay False so the sandbox's WSL1
    refusal never engages in these tests). Mocking the functions
    bypasses their process-wide caches entirely, and the fork-based
    spawn backend carries the mocked module state into the sandbox
    setup child.
    """
    monkeypatch.setattr(startup_wsl, "is_wsl",
                        lambda kernel_id=None: wsl)
    monkeypatch.setattr(startup_wsl, "is_wsl2",
                        lambda kernel_id=None: wsl)


def _plan_mounts(monkeypatch, tmp_path, *, wsl: bool,
                 extra_ro_paths=None, precreate=(), target=None):
    """Run setup_mount_ns in-process with ``_mount`` stubbed.

    Returns the recorded mount plan with ``/proc/self/fd/N`` mount
    targets resolved to their real paths while the fd is still open
    (the O_PATH-pinned mask convention never passes a pathname).
    ``precreate`` materialises in-root directories the stubbed step
    4/6 binds would normally populate, so the 8f mask sites exist.
    """
    mounts: list[tuple] = []

    def _record(source, target, fs_type, flags=0, data=None):
        resolved = target
        if isinstance(target, str) and target.startswith("/proc/self/fd/"):
            try:
                resolved = os.readlink(target)
            except OSError:
                pass
        mounts.append((source, resolved, fs_type, flags, data))

    monkeypatch.setattr(mount_ns, "_mount", _record)
    monkeypatch.setattr(mount_ns, "_pivot_root", lambda *a: None)
    monkeypatch.setattr(mount_ns, "_umount", lambda *a, **k: None)
    _mock_wsl(monkeypatch, wsl=wsl)
    for var in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(var, raising=False)
    root = tmp_path / "sbx-root"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    for rel in precreate:
        (root / rel.lstrip("/")).mkdir(parents=True, exist_ok=True)
    mount_ns.setup_mount_ns(
        target, None,
        extra_ro_paths=extra_ro_paths,
        root_path=str(root),
    )
    return root, mounts


def _mask_entries(root, mounts):
    """The recorded 8f mask mounts (read-only tmpfs over an in-root
    WSL mask path)."""
    prefixes = tuple(f"{root}{p}" for p in (_BINFMT, _WSL_LIB))
    return [m for m in mounts
            if m[0] == "tmpfs" and m[1] in prefixes
            and m[3] & mount_ns.MS_RDONLY]


class TestProfileContent:
    _PRE = (_BINFMT, _WSL_LIB)

    @pytest.mark.linux_native
    def test_masks_present_under_mocked_wsl(self, monkeypatch, tmp_path):
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE)
        masked = {m[1] for m in _mask_entries(root, mounts)}
        assert masked == {f"{root}{_BINFMT}", f"{root}{_WSL_LIB}"}

    @pytest.mark.linux_native
    def test_masks_are_last_mounts_in_plan(self, monkeypatch, tmp_path):
        # Ordering is load-bearing: a mask mounted before a later bind
        # at the same dentry would be covered by it. The 8f masks must
        # be the final mounts of the plan.
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE)
        assert len(_mask_entries(root, mounts[-2:])) == 2

    @pytest.mark.linux_native
    def test_profile_identical_off_wsl(self, monkeypatch, tmp_path):
        # The inertness pin: off-WSL the plan carries no mask mounts,
        # no mount references any WSL mask path, and the plan is the
        # WSL plan minus exactly the two masks.
        root, on_wsl = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE)
        root2, off_wsl = _plan_mounts(
            monkeypatch, tmp_path, wsl=False, precreate=self._PRE)
        assert root == root2
        assert _mask_entries(root, off_wsl) == []
        for path in mount_ns._WSL_MASKED_PATHS:
            assert not any(
                str(m[1]).startswith(f"{root}{path}") for m in off_wsl
            ), f"off-WSL plan touches {path}"
        masks = _mask_entries(root, on_wsl)
        assert [m for m in on_wsl if m not in masks] == off_wsl

    @pytest.mark.linux_native
    def test_readable_bind_refused_at_masked_paths(
            self, monkeypatch, tmp_path, capfd):
        # A caller readable bind at a masked path would stack a live
        # host view over the mask (or re-grant the structurally-absent
        # /run/WSL into the fresh tmpfs). Refused loudly, bind dropped.
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE,
            extra_ro_paths=[_BINFMT, "/run/WSL"])
        assert not any(m[0] in (_BINFMT, "/run/WSL") for m in mounts)
        err = capfd.readouterr().err
        assert err.count("refusing readable bind at masked path") == 2
        assert _BINFMT in err and "/run/WSL" in err
        # The masks themselves still landed.
        assert len(_mask_entries(root, mounts)) == 2

    @pytest.mark.linux_native
    def test_readable_bind_allowed_off_wsl(
            self, monkeypatch, tmp_path, capfd):
        # Same caller input off-WSL: the refusal policy is inert and
        # the (host-existing) path binds as any extra read-only path.
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=False, precreate=self._PRE,
            extra_ro_paths=[_BINFMT])
        assert any(m[0] == _BINFMT for m in mounts)
        err = capfd.readouterr().err
        assert "refusing readable bind at masked path" not in err

    @pytest.mark.linux_native
    def test_symlink_to_masked_binfmt_refused(
            self, monkeypatch, tmp_path, capfd):
        # Destination leg of the masked-path refusal (reviewer
        # repro): a link at an off-mask spelling whose destination
        # is the masked binfmt dir would bind the live host view at
        # the link path. Refused on the resolved destination; the
        # masks still land.
        link = tmp_path / "blink"
        link.symlink_to(_BINFMT)
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE,
            extra_ro_paths=[str(link)])
        assert not any(m[0] == str(link) for m in mounts)
        err = capfd.readouterr().err
        assert "refusing readable bind at masked path" in err
        assert "resolved destination" in err
        assert len(_mask_entries(root, mounts)) == 2

    @pytest.mark.linux_native
    def test_symlink_to_run_wsl_not_bound(
            self, monkeypatch, tmp_path, capfd):
        # /run/WSL re-grant shape through a link. Off-WSL the
        # destination does not exist, so the entry is unclassifiable
        # (neither dir nor file) and is skipped before any bind —
        # already the deny direction; on a real WSL host the
        # destination exists and the resolved-destination refusal
        # fires instead ([verify-live] there). Either way nothing is
        # bound at the link path.
        link = tmp_path / "rlink"
        link.symlink_to("/run/WSL")
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=True, precreate=self._PRE,
            extra_ro_paths=[str(link)])
        assert not any(m[0] == str(link) for m in mounts)

    @pytest.mark.linux_native
    def test_symlink_to_evidence_dir_refused_off_wsl(
            self, monkeypatch, tmp_path, capfd):
        # The destination check is general (bonus closure of the
        # pre-existing evasion): a link to the target's .audit
        # evidence dir is refused on ANY host — no WSL involved.
        target = tmp_path / "tgt"
        (target / ".audit").mkdir(parents=True)
        link = tmp_path / "alink"
        link.symlink_to(target / ".audit")
        root, mounts = _plan_mounts(
            monkeypatch, tmp_path, wsl=False,
            extra_ro_paths=[str(link)], target=str(target))
        assert not any(m[0] == str(link) for m in mounts)
        err = capfd.readouterr().err
        assert "refusing readable bind at masked path" in err
        assert "resolved destination" in err

    @pytest.mark.linux_native
    def test_missing_mask_sites_skipped_silently(
            self, monkeypatch, tmp_path, capfd):
        # No binfmt_misc / wsl-lib dirs in the view (nothing
        # precreated): the mask loop skips without warning — absence
        # IS the masked state.
        root, mounts = _plan_mounts(monkeypatch, tmp_path, wsl=True)
        assert _mask_entries(root, mounts) == []
        assert "WSL" not in capfd.readouterr().err


class TestFunctionalMountNs:
    """Real mount-ns spawns; WSL detection mocked in the test process
    and inherited by the forked sandbox setup child.

    ``skip_pid_ns=True`` on the binfmt probes: the default lane's
    fresh pid-ns procfs replaces the step-6 host /proc bind post-pivot
    and (as a fresh procfs) carries no binfmt_misc submount — the view
    is empty there with or without the mask. The mask is load-bearing
    exactly on the lanes that KEEP the host /proc bind (skip_pid_ns,
    and any fresh-procfs degradation), so that is the shape the
    functional probe pins.
    """

    def _run(self, tmp_path, child_src: str, **kwargs):
        from core.sandbox import run
        target = tmp_path / "target"
        output = tmp_path / "output"
        target.mkdir(exist_ok=True)
        output.mkdir(exist_ok=True)
        return run(
            [_PY, "-c", child_src],
            target=str(target), output=str(output),
            capture_output=True, text=True, timeout=60,
            **kwargs,
        )

    @staticmethod
    def _require_mount_ns_taken(r) -> None:
        info = getattr(r, "sandbox_info", None) or {}
        if not info.get("mount_ns_active"):
            pytest.skip("mount-ns lane not taken on this host")

    @requires_mount
    @pytest.mark.linux_native
    def test_interop_surfaces_absent_under_mocked_wsl(
            self, monkeypatch, tmp_path):
        if not os.path.isdir(_BINFMT):
            pytest.skip("host has no binfmt_misc directory")
        host_entries = set(os.listdir(_BINFMT))
        _mock_wsl(monkeypatch, wsl=True)
        child = textwrap.dedent(f"""
            import os
            print("BINFMT", sorted(os.listdir({_BINFMT!r})))
            try:
                open({_BINFMT!r} + "/probe-entry", "w")
                print("BINFMT_WRITE ok")
            except OSError as e:
                print("BINFMT_WRITE denied", e.errno)
            print("RUN_WSL", os.path.exists("/run/WSL"))
            print("DXG", os.path.exists("/dev/dxg"))
            print("WSL_LIB", os.path.exists({_WSL_LIB!r}))
        """)
        r = self._run(tmp_path, child, skip_pid_ns=True)
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "BINFMT []" in r.stdout, r.stdout
        assert "BINFMT_WRITE denied" in r.stdout, r.stdout
        assert "RUN_WSL False" in r.stdout, r.stdout
        assert "DXG False" in r.stdout, r.stdout
        if not os.path.isdir(_WSL_LIB):
            # Not creatable without root off-WSL; the mask mount for
            # an existing /usr/lib/wsl is [verify-live] on a WSL2 box.
            assert "WSL_LIB False" in r.stdout, r.stdout
        # Meaningful only when the host actually has registrations —
        # the empty listing above proved masking, this proves the
        # host had something to mask.
        if not host_entries:
            pytest.skip("host binfmt_misc is empty; mask assertion "
                        "was vacuous for entries")

    @requires_mount
    @pytest.mark.linux_native
    def test_symlink_readable_grant_cannot_unmask_binfmt(
            self, monkeypatch, tmp_path):
        # Live leg of the reviewer's repro, fixed: a readable grant
        # spelled as a link to the masked binfmt dir must not bind
        # the host view at the link path. restrict_reads=True so the
        # grant actually reaches the mount-ns extra-bind plan.
        if not os.path.isdir(_BINFMT) or not os.listdir(_BINFMT):
            pytest.skip("host binfmt_misc missing or empty")
        _mock_wsl(monkeypatch, wsl=True)
        link = tmp_path / "blink"
        link.symlink_to(_BINFMT)
        child = textwrap.dedent(f"""
            import os
            print("MASKED", sorted(os.listdir({_BINFMT!r})))
            try:
                print("LINK", sorted(os.listdir({str(link)!r})))
            except OSError as e:
                print("LINK_DENIED", e.errno)
        """)
        r = self._run(tmp_path, child, skip_pid_ns=True,
                      restrict_reads=True,
                      readable_paths=[str(link)])
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "MASKED []" in r.stdout, r.stdout
        assert "LINK_DENIED" in r.stdout, r.stdout
        assert "refusing readable bind at masked path" in r.stderr, (
            r.stderr)

    @requires_mount
    @pytest.mark.linux_native
    def test_binfmt_view_host_real_off_wsl(self, monkeypatch, tmp_path):
        # Functional inertness: off-WSL the host /proc bind keeps
        # carrying the host binfmt_misc view unchanged (same
        # skip_pid_ns shape as the masked probe above — the pair
        # proves the mask, not the fresh-procfs replacement, flips
        # the view).
        if not os.path.isdir(_BINFMT):
            pytest.skip("host has no binfmt_misc directory")
        host_entries = sorted(os.listdir(_BINFMT))
        if not host_entries:
            pytest.skip("host binfmt_misc is empty — views "
                        "indistinguishable")
        _mock_wsl(monkeypatch, wsl=False)
        child = textwrap.dedent(f"""
            import os
            print("BINFMT", sorted(os.listdir({_BINFMT!r})))
        """)
        r = self._run(tmp_path, child, skip_pid_ns=True)
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert f"BINFMT {host_entries}" in r.stdout, r.stdout


class TestSafeEnvWslDrops:
    """Belt-and-braces leg of the interop closure: the env allowlist
    scrub already drops the interop variables; pin it so an allowlist
    edit cannot silently re-open the env route."""

    def test_wsl_interop_vars_dropped(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setenv("WSL_INTEROP", "/run/WSL/8_interop")
        monkeypatch.setenv("WSLENV", "PATH/l")
        monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
        env = RaptorConfig.get_safe_env()
        for name in ("WSL_INTEROP", "WSLENV", "WSL_DISTRO_NAME"):
            assert name not in env

    def test_wsl_vars_not_allowlisted(self):
        from core.config import RaptorConfig
        for name in ("WSL_INTEROP", "WSLENV", "WSL_DISTRO_NAME"):
            assert name not in RaptorConfig.SAFE_ENV_ALLOWLIST
            assert not name.startswith(RaptorConfig.SAFE_ENV_PREFIXES)
