"""Robustness tests for the sandbox helper binaries' argument contracts.

The two capability-granted helpers under ``core/sandbox/helpers/`` enforce
strict argument contracts before touching anything privileged:

- ``raptor-coord-launcher`` pins its exec target to its own checkout's
  ``netns_coordinator.py``, requires the interpreter/script/helpers-dir to
  be owned by root or the launcher's owner and not writable by untrusted
  parties (other-write always refused; group-write refused unless the
  group is the file owner's primary group — the user-private-group case,
  so umask-002 checkouts pass with zero configuration), and accepts
  exactly ``[launcher, interpreter, script]``.
- ``raptor-gidmap-allow`` requires the target pid's user namespace to be
  owned by the invoker, confines mapped host gids to gids the invoker
  actually holds, and enforces strictly-numeric, bounded arguments.

Every refusal path exits 3 before any privileged operation, so all of it
is testable here without any capability grant. The contracts themselves
are documented in each helper's .c header; the standalone validation
functions are additionally exercised by the C harness built via
``make test`` (helpers_test.c).

Builds happen in an isolated copy of the sources (never in the checkout)
so the tests stay hermetic and don't race a developer's own build.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

HELPERS_SRC = Path(__file__).resolve().parents[1] / "helpers"

SOURCES = (
    "Makefile",
    "helpers_validate.h",
    "helpers_test.c",
    "raptor-coord-launcher.c",
    "raptor-gidmap-allow.c",
)

# Minimal, fixed environment for every helper invocation: the binaries
# read nothing from the environment, and a stripped env keeps the tests
# independent of the developer's shell.
_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp"}

CLONE_NEWUSER = 0x10000000

pytestmark = [
    # The helpers are Linux userns machinery (prctl, /proc/<pid>/ns
    # inspection, gid_map writes) and their sources include Linux-only
    # headers (<sys/prctl.h>) — they neither build nor mean anything on
    # other platforms, so the whole suite (including the `make` builds
    # its fixtures run) is pinned to Linux rather than made portable.
    pytest.mark.skipif(
        sys.platform != "linux",
        reason="sandbox helper binaries are Linux-only userns machinery",
    ),
    pytest.mark.skipif(
        shutil.which("cc") is None or shutil.which("make") is None,
        reason="C toolchain (cc + make) not available",
    ),
]


def _run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout,
        check=False, env=dict(_ENV),
    )


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    """Copy the helper sources into a tree shaped like the checkout
    (``pkg/helpers/`` next to ``pkg/netns_coordinator.py``) and build
    both production binaries there via the Makefile.

    Modes are pinned to the umask-002 user-private-group layout
    (0775 dirs, 0664 script) that real checkouts carry on Debian/Ubuntu:
    the trusted-path contract must accept these with zero configuration
    because the group is the owner's own primary group.
    """
    base = tmp_path_factory.mktemp("helper-contracts")
    pkg = base / "pkg"
    helpers = pkg / "helpers"
    helpers.mkdir(parents=True)
    for name in SOURCES:
        shutil.copy(HELPERS_SRC / name, helpers / name)
    coord = pkg / "netns_coordinator.py"
    coord.write_text("print('COORD-OK')\n")
    coord.chmod(0o664)
    for p in (base, pkg, helpers):
        p.chmod(0o775)
    # Pin the group to the owner's primary group so the UPG rule applies
    # even on hosts where the tmp tree inherits a setgid group.
    for p in (base, pkg, helpers, coord):
        os.chown(p, -1, _primary_gid())
    r = _run(["make", "-C", str(helpers)], timeout=120)
    if r.returncode != 0:
        pytest.fail(f"helper build failed:\n{r.stdout}\n{r.stderr}")
    for name in ("raptor-coord-launcher", "raptor-gidmap-allow"):
        binary = helpers / name
        assert binary.is_file(), f"{name} not produced by make"
        binary.chmod(0o755)
    return helpers


def _primary_gid() -> int:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_gid


def _shared_gid() -> int | None:
    """A supplementary group distinct from the primary one, if any."""
    primary = _primary_gid()
    for gid in os.getgroups():
        if gid != primary:
            return gid
    return None


def _trusted_interpreter() -> str | None:
    """Pick an interpreter the launcher's trusted-path check accepts:
    root-owned system python, or the current interpreter when it is
    owned by this uid with no group/other write bits."""
    for candidate in ("/usr/bin/python3", sys.executable):
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if st.st_mode & 0o022:
            continue
        if st.st_uid in (0, os.getuid()):
            return candidate
    return None


class TestBuild:
    def test_make_builds_both_production_binaries(self, built: Path) -> None:
        for name in ("raptor-coord-launcher", "raptor-gidmap-allow"):
            binary = built / name
            assert binary.is_file()
            assert os.access(binary, os.X_OK)

    def test_make_test_harness_passes(self, built: Path) -> None:
        r = _run(["make", "-C", str(built), "test"], timeout=120)
        assert r.returncode == 0, f"harness failed:\n{r.stdout}\n{r.stderr}"
        assert "FAIL" not in r.stdout
        assert "all helper contract checks passed" in r.stdout


class TestCoordLauncherContract:
    """Refusal paths of the real binary — none of these need a grant:
    every contract violation exits 3 before the unshare."""

    def test_refuses_no_arguments(self, built: Path) -> None:
        r = _run([str(built / "raptor-coord-launcher")])
        assert r.returncode == 3
        assert "argument contract" in r.stderr

    def test_refuses_extra_argv(self, built: Path) -> None:
        coord = built.parent / "netns_coordinator.py"
        r = _run([
            str(built / "raptor-coord-launcher"),
            "/usr/bin/python3", str(coord), "extra-arg",
        ])
        assert r.returncode == 3
        assert "argument contract" in r.stderr

    def test_refuses_script_pin_mismatch(self, built: Path) -> None:
        other = built.parent / "other.py"
        other.write_text("print('other')\n")
        other.chmod(0o644)
        r = _run([
            str(built / "raptor-coord-launcher"),
            "/usr/bin/python3", str(other),
        ])
        assert r.returncode == 3
        assert "script pin" in r.stderr

    def test_refuses_world_writable_interpreter(
        self, built: Path, tmp_path: Path,
    ) -> None:
        # A mode-0666 file is exactly what another local user could
        # plant; the trusted-path check must refuse it even though it
        # is owned by the invoker.
        interp = tmp_path / "planted-interpreter"
        interp.write_text("#!/bin/false\n")
        interp.chmod(0o666)
        coord = built.parent / "netns_coordinator.py"
        r = _run([
            str(built / "raptor-coord-launcher"),
            str(interp), str(coord),
        ])
        assert r.returncode == 3
        assert "interpreter" in r.stderr
        assert "writable" in r.stderr

    def test_refuses_shared_group_writable_interpreter(
        self, built: Path, tmp_path: Path,
    ) -> None:
        # Group-write is only tolerated for the owner's primary group;
        # a file writable by a SHARED group (here: a supplementary group
        # of this uid) must be refused.
        shared = _shared_gid()
        if shared is None:
            pytest.skip("no supplementary group distinct from the primary")
        interp = tmp_path / "shared-group-interpreter"
        interp.write_text("#!/bin/false\n")
        interp.chmod(0o664)
        os.chown(interp, -1, shared)
        coord = built.parent / "netns_coordinator.py"
        r = _run([
            str(built / "raptor-coord-launcher"),
            str(interp), str(coord),
        ])
        assert r.returncode == 3
        assert "primary group" in r.stderr

    def test_accepts_umask002_checkout_layout(self, built: Path) -> None:
        """The fixture tree carries the user-private-group layout real
        umask-002 checkouts have (0775 dirs, 0664 script). Validation
        must pass with zero configuration: whatever happens later (a
        host may still block unprivileged userns), the contract-refusal
        path (exit 3, "refusing to launch") must not be taken."""
        interp = _trusted_interpreter()
        if interp is None:
            pytest.skip("no interpreter satisfies the trusted-path check")
        coord = built.parent / "netns_coordinator.py"
        r = _run([str(built / "raptor-coord-launcher"), interp, str(coord)])
        assert r.returncode != 3
        assert "refusing to launch" not in r.stderr

    def test_refuses_nonexistent_interpreter(self, built: Path) -> None:
        coord = built.parent / "netns_coordinator.py"
        r = _run([
            str(built / "raptor-coord-launcher"),
            str(built.parent / "no-such-python"), str(coord),
        ])
        assert r.returncode == 3
        assert "interpreter" in r.stderr

    def test_executes_pinned_coordinator_when_host_allows(
        self, built: Path,
    ) -> None:
        """Happy path: canonical argv passes validation and the launcher
        proceeds to the namespace setup. Without a grant this only works
        where the host permits unprivileged userns — skip when blocked."""
        interp = _trusted_interpreter()
        if interp is None:
            pytest.skip("no interpreter satisfies the trusted-path check")
        coord = built.parent / "netns_coordinator.py"
        r = _run([str(built / "raptor-coord-launcher"), interp, str(coord)])
        if r.returncode == 1 and ("unshare" in r.stderr
                                  or "write_id_maps" in r.stderr):
            # Two LSM refusal shapes: unshare(CLONE_NEWUSER) denied
            # outright, or the userns is granted but the uid_map /
            # gid_map write EPERMs (AppArmor unprivileged_userns
            # confinement, SELinux). Both mean the host blocks the
            # setup this happy path needs; the launcher's diagnostic
            # already names the grant to install.
            pytest.skip("host LSM blocks unprivileged userns setup "
                        "for this binary")
        assert r.returncode == 0, r.stderr
        assert "COORD-OK" in r.stdout


class TestGidmapAllowContract:
    """Refusal paths of the real binary — validation precedes the
    gid_map write, so no CAP_SETGID grant is needed."""

    def test_refuses_no_arguments(self, built: Path) -> None:
        r = _run([str(built / "raptor-gidmap-allow")])
        assert r.returncode == 3
        assert "argument hygiene" in r.stderr

    def test_refuses_non_numeric_pid(self, built: Path) -> None:
        r = _run([
            str(built / "raptor-gidmap-allow"),
            "abc", "0", str(os.getgid()), "1",
        ])
        assert r.returncode == 3
        assert "strictly numeric" in r.stderr

    def test_refuses_non_numeric_gid(self, built: Path) -> None:
        r = _run([
            str(built / "raptor-gidmap-allow"),
            str(os.getpid()), "0", "12x4", "1",
        ])
        assert r.returncode == 3
        assert "strictly numeric" in r.stderr

    def test_refuses_gid_the_invoker_does_not_hold(
        self, built: Path,
    ) -> None:
        held = {os.getgid(), os.getegid(), *os.getgroups()}
        foreign = max(held) + 1
        r = _run([
            str(built / "raptor-gidmap-allow"),
            str(os.getpid()), "0", str(foreign), "1",
        ])
        assert r.returncode == 3
        assert "gid confinement" in r.stderr

    @pytest.mark.skipif(
        os.getuid() == 0,
        reason="root owns the init userns; the refusal needs a non-root uid",
    )
    def test_refuses_foreign_pid_namespace(self, built: Path) -> None:
        # pid 1 lives in the init user namespace (owned by root): the
        # ownership check refuses it either at open() or at the owner
        # comparison, even with otherwise-valid mapping arguments.
        r = _run([
            str(built / "raptor-gidmap-allow"),
            "1", "0", str(os.getgid()), "1",
        ])
        assert r.returncode == 3
        assert "namespace ownership" in r.stderr

    def test_refuses_too_many_triples(self, built: Path) -> None:
        triple = ["0", str(os.getgid()), "1"]
        r = _run([
            str(built / "raptor-gidmap-allow"),
            str(os.getpid()), *(triple * 9),
        ])
        assert r.returncode == 3
        assert "triples" in r.stderr

    def test_validation_passes_on_own_namespace(self, built: Path) -> None:
        """The RAPTOR call shape (one triple, own gid, self-created
        userns) must clear every contract check. Without CAP_SETGID the
        subsequent gid_map write fails with EPERM (exit 1) — the key
        assertion is that the refusal exit (3) is NOT taken."""
        libc = ctypes.CDLL(None, use_errno=True)
        child = os.fork()
        if child == 0:
            # Child: create a user namespace this test's uid owns, then
            # linger for the parent to inspect it.
            rc = libc.unshare(CLONE_NEWUSER)
            if rc != 0:
                os._exit(42)
            time.sleep(30)
            os._exit(0)
        try:
            time.sleep(0.3)
            # Distinguish "child failed to unshare" from a live child.
            done, status = os.waitpid(child, os.WNOHANG)
            if done == child:
                code = os.waitstatus_to_exitcode(status)
                pytest.skip(
                    "host blocks unprivileged unshare(CLONE_NEWUSER) "
                    f"(child exit {code})"
                )
            r = _run([
                str(built / "raptor-gidmap-allow"),
                str(child), "0", str(os.getgid()), "1",
            ])
            assert r.returncode != 3, f"contract refusal: {r.stderr}"
            if r.returncode != 0:
                # No grant on the test binary: validation passed, the
                # kernel then rejected the unprivileged gid_map write.
                assert "gid_map" in r.stderr
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass


class TestApparmorProfileTemplate:
    """The AppArmor profile ships as a template whose attachment is
    the unparseable @@RAPTOR_DIR@@ placeholder. AppArmor attaches by
    exact path match — a suffix-wildcard attachment would hand the
    profile's userns + capability grants to any local user who stages
    a binary under a matching path, defeating the system-wide
    apparmor_restrict_unprivileged_userns hardening."""

    HELPERS = Path(__file__).resolve().parents[1] / "helpers"

    def test_template_has_placeholder_attachment(self):
        text = (self.HELPERS / "raptor-coord-launcher.apparmor.template").read_text()
        assert "@@RAPTOR_DIR@@/core/sandbox/helpers/raptor-coord-launcher" in text

    def test_no_wildcard_attachment_anywhere(self):
        """No shipped profile source may attach by path glob."""
        for prof in self.HELPERS.glob("*.apparmor*"):
            text = prof.read_text()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                assert "/**/core/sandbox" not in stripped, (
                    f"{prof.name}: wildcard attachment path — any local "
                    f"user could stage a matching path and inherit the "
                    f"userns grant"
                )

    def test_render_substitutes_absolute_checkout_path(self, tmp_path):
        """`make apparmor-profile` in a copied helpers dir renders the
        attachment to that tree's absolute path and leaves no
        placeholder behind."""
        import shutil as _shutil
        work = tmp_path / "core" / "sandbox" / "helpers"
        work.mkdir(parents=True)
        for name in ("Makefile", "raptor-coord-launcher.apparmor.template"):
            _shutil.copy(self.HELPERS / name, work / name)
        r = subprocess.run(["make", "-C", str(work), "apparmor-profile"],
                           capture_output=True, text=True, timeout=60,
                           check=False)
        assert r.returncode == 0, r.stderr
        rendered = (work / "raptor-coord-launcher.apparmor").read_text()
        assert "@@RAPTOR_DIR@@" not in rendered
        assert (f"{tmp_path}/core/sandbox/helpers/raptor-coord-launcher"
                in rendered)
