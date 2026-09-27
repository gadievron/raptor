"""Fake-home relocation into the per-sandbox private /tmp (mount lane).

On the mount-ns lane the child's HOME must not name the run directory:
``sandbox()`` stages ``HOME=<output>/.home`` at construction, then the
spawn backend COPIES that intake into the private tmpfs at
``/tmp/.home`` (via the ``stage_files``/``stage_dirs`` seam) and
re-points HOME/XDG_* there. A copy — never a bind mount — because a
bind's mountinfo root field re-leaks the bind SOURCE path, handing the
child the run-dir location the relocation exists to hide.

Covered here:

* ``_stage_fake_home_intake`` unit behaviour: faithful staging of
  files + directory skeleton (empty dirs included), both directions of
  the file-count/byte budgets, and refusal (``None``) on any
  non-regular member — the intake dir is writable by an EARLIER
  sandboxed child sharing the output dir, so symlink/FIFO plants must
  never be followed into the next sandbox.
* Live mount-lane contract: HOME/XDG_* == ``/tmp/.home`` inside the
  child, pre-populated intake files readable there, ``/proc/self/
  mountinfo`` carries no ``.home`` entry (nothing ties the home to the
  run dir), and fake-home writes stay in the private tmpfs instead of
  landing in ``<output>/.home``.
* Fallback contracts: an unstageable intake keeps the attributable
  ``<output>/.home`` with a warning (never a hard failure), and the
  skip-mount lane keeps ``<output>/.home`` outright (no private /tmp
  exists there — a host-shared ``/tmp/.home`` would be
  attacker-plantable).
"""

import logging
import os
import sys
from pathlib import Path

import pytest

import core.sandbox.context as _ctx
from core.sandbox.context import (
    _TMP_FAKE_HOME,
    _stage_fake_home_intake,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux-only sandbox lanes")


# ---------------------------------------------------------------------------
# Unit: _stage_fake_home_intake
# ---------------------------------------------------------------------------


class TestStageFakeHomeIntake:

    def test_stages_files_and_directory_skeleton(self, tmp_path: Path) -> None:
        """Files land keyed by in-sandbox path; EMPTY dirs are kept in
        the skeleton (a private $HOME needs its XDG subdirs to exist
        even when no file rides them)."""
        intake = tmp_path / ".home"
        intake.mkdir()
        (intake / ".gitconfig").write_bytes(b"[user]\n\tname = t\n")
        (intake / ".config").mkdir()  # empty — must still be staged
        (intake / ".local").mkdir()
        (intake / ".local" / "share").mkdir()
        (intake / ".local" / "share" / "tool.rc").write_bytes(b"x = 1\n")

        staged = _stage_fake_home_intake(str(intake))
        assert staged is not None
        stage_files, stage_dirs = staged
        assert stage_files == {
            f"{_TMP_FAKE_HOME}/.gitconfig": b"[user]\n\tname = t\n",
            f"{_TMP_FAKE_HOME}/.local/share/tool.rc": b"x = 1\n",
        }
        assert set(stage_dirs) == {
            _TMP_FAKE_HOME,
            f"{_TMP_FAKE_HOME}/.config",
            f"{_TMP_FAKE_HOME}/.local",
            f"{_TMP_FAKE_HOME}/.local/share",
        }
        # mount_ns skips non-absolute stage entries — the helper must
        # only ever emit absolute in-sandbox paths.
        assert all(p.startswith("/") for p in stage_dirs)
        assert all(p.startswith("/") for p in stage_files)

    def test_empty_intake_stages_root_dir_only(self, tmp_path: Path) -> None:
        intake = tmp_path / ".home"
        intake.mkdir()
        assert _stage_fake_home_intake(str(intake)) == ({}, [_TMP_FAKE_HOME])

    def test_file_count_budget_both_directions(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """At the cap stages; one past the cap refuses. Rationale for
        testing both directions: the cap must not silently reject
        legitimate intakes (too low) nor let a hostile prior child
        replay an unbounded plant (too high / unenforced)."""
        monkeypatch.setattr(_ctx, "_FAKE_HOME_INGEST_MAX_FILES", 2)
        intake = tmp_path / ".home"
        intake.mkdir()
        (intake / "a").write_bytes(b"1")
        (intake / "b").write_bytes(b"2")
        staged = _stage_fake_home_intake(str(intake))
        assert staged is not None and len(staged[0]) == 2
        (intake / "c").write_bytes(b"3")
        assert _stage_fake_home_intake(str(intake)) is None

    def test_byte_budget_both_directions(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_ctx, "_FAKE_HOME_INGEST_MAX_BYTES", 10)
        intake = tmp_path / ".home"
        intake.mkdir()
        (intake / "a").write_bytes(b"x" * 6)
        (intake / "b").write_bytes(b"y" * 4)  # total exactly 10
        staged = _stage_fake_home_intake(str(intake))
        assert staged is not None
        assert sum(len(v) for v in staged[0].values()) == 10
        (intake / "c").write_bytes(b"z")  # total 11
        assert _stage_fake_home_intake(str(intake)) is None

    def test_symlink_file_member_refused(self, tmp_path: Path) -> None:
        """A symlink in the intake is a plant from an earlier child —
        following it would copy attacker-chosen host content into the
        next sandbox's home."""
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"HOST-SECRET")
        intake = tmp_path / ".home"
        intake.mkdir()
        (intake / ".gitconfig").write_bytes(b"ok")
        os.symlink(str(victim), str(intake / ".netrc"))
        assert _stage_fake_home_intake(str(intake)) is None

    def test_symlink_dir_member_refused(self, tmp_path: Path) -> None:
        victim_dir = tmp_path / "victim-dir"
        victim_dir.mkdir()
        (victim_dir / "leak.txt").write_bytes(b"HOST-SECRET")
        intake = tmp_path / ".home"
        intake.mkdir()
        os.symlink(str(victim_dir), str(intake / ".config"))
        assert _stage_fake_home_intake(str(intake)) is None

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
    def test_fifo_member_refused(self, tmp_path: Path) -> None:
        """A FIFO is not stageable content — and without O_NONBLOCK the
        open alone would hang the parent until a writer appears."""
        intake = tmp_path / ".home"
        intake.mkdir()
        os.mkfifo(str(intake / "pipe"))
        assert _stage_fake_home_intake(str(intake)) is None

    def test_unreadable_member_refuses(self, tmp_path: Path) -> None:
        if os.geteuid() == 0:
            pytest.skip("root ignores file modes")
        intake = tmp_path / ".home"
        intake.mkdir()
        locked = intake / "locked"
        locked.write_bytes(b"x")
        locked.chmod(0o000)
        try:
            assert _stage_fake_home_intake(str(intake)) is None
        finally:
            locked.chmod(0o600)

    def test_unlistable_subdir_refuses(self, tmp_path: Path) -> None:
        """os.walk swallows listdir errors by default, so an unreadable
        SUBDIR used to stage as an empty directory — its contents
        silently dropped with no warning — while an unreadable FILE
        refused the whole stage. Both shapes must refuse (None →
        caller falls back to the attributable intake with a warning)."""
        if os.geteuid() == 0:
            pytest.skip("root ignores directory modes")
        intake = tmp_path / ".home"
        intake.mkdir()
        (intake / "visible").write_bytes(b"x")
        sealed = intake / ".config"
        sealed.mkdir()
        (sealed / "secret.txt").write_bytes(b"y")
        sealed.chmod(0o000)
        try:
            assert _stage_fake_home_intake(str(intake)) is None
        finally:
            sealed.chmod(0o700)


# ---------------------------------------------------------------------------
# Live lanes
# ---------------------------------------------------------------------------


def _require_mount_lane() -> None:
    from core.sandbox.context import (
        check_landlock_available,
        check_mount_available,
        check_net_available,
    )
    if (not check_net_available() or not check_landlock_available()
            or not check_mount_available()):
        pytest.skip("Needs user-ns + Landlock + mount-ns")


def _run_untrusted_or_skip(cmd: list[str], out: str, **kw: object):
    """Run under run_untrusted, skipping (not failing) when the host
    cannot set the sandbox up — same hermeticity contract as the other
    live sandbox suites."""
    from core.sandbox import SandboxSetupError, run_untrusted
    try:
        return run_untrusted(
            cmd, target=out, output=out,
            capture_output=True, text=True, timeout=90, **kw)
    except SandboxSetupError as exc:
        pytest.skip(f"sandbox setup unavailable: {exc}")


@pytest.mark.integration
class TestMountLanePrivateHome:

    def test_home_is_private_tmp_and_mountinfo_carries_no_home(
            self, tmp_path: Path) -> None:
        """The flagship contract: inside the mount-ns child, HOME and
        XDG_* name ``/tmp/.home``; the pre-populated intake is readable
        there; NO mountinfo entry mentions ``.home`` (a bind would
        re-leak the run-dir source path in its root field); and writes
        to $HOME stay in the private tmpfs."""
        _require_mount_lane()
        out = tmp_path / "out"
        out.mkdir()
        intake = out / ".home"
        intake.mkdir()
        (intake / ".gitconfig").write_text("[user]\n\tname = probe\n")

        r = _run_untrusted_or_skip(
            ["sh", "-c",
             "echo HOME=$HOME; echo XDG=$XDG_CONFIG_HOME; "
             "echo ---GITCONFIG---; cat \"$HOME/.gitconfig\"; "
             "echo w > \"$HOME/child-note\" && echo WRITE-OK; "
             "echo ---MI---; cat /proc/self/mountinfo"],
            str(out))
        if r.returncode != 0:
            pytest.skip(f"probe failed rc={r.returncode}: {r.stderr[:200]!r}")

        body, _, mountinfo = r.stdout.partition("---MI---")
        assert "HOME=/tmp/.home\n" in body
        assert "XDG=/tmp/.home/.config\n" in body
        assert "name = probe" in body
        assert "WRITE-OK" in body
        # No mountinfo record may mention the fake home AT ALL — not
        # the in-sandbox /tmp/.home (it is plain tmpfs content, not a
        # mount) and not the <output>/.home intake (a bind source
        # would surface here).
        leaks = [ln for ln in mountinfo.splitlines() if ".home" in ln]
        assert leaks == [], f"fake home leaked into mountinfo: {leaks}"
        # The child's $HOME write landed in the private tmpfs, not in
        # the run directory's intake.
        assert not (intake / "child-note").exists()
        # And the intake itself was copied, not consumed.
        assert (intake / ".gitconfig").read_text().startswith("[user]")

    def test_unstageable_intake_keeps_attributable_home_with_warning(
            self, tmp_path: Path,
            caplog: pytest.LogCaptureFixture) -> None:
        """A symlink plant in the intake must not abort the run: the
        child keeps ``<output>/.home`` (status quo ante) and the parent
        logs the fallback."""
        _require_mount_lane()
        out = tmp_path / "out"
        out.mkdir()
        intake = out / ".home"
        intake.mkdir()
        os.symlink("/etc/hostname", str(intake / ".netrc"))

        with caplog.at_level(logging.WARNING, logger=_ctx.logger.name):
            r = _run_untrusted_or_skip(["sh", "-c", "echo HOME=$HOME"],
                                       str(out))
        if r.returncode != 0:
            pytest.skip(f"probe failed rc={r.returncode}: {r.stderr[:200]!r}")
        home = r.stdout.split("HOME=", 1)[1].strip()
        assert home.startswith(str(out)), (
            f"fallback must keep the attributable home; got {home!r}")
        assert home.endswith(".home")
        assert "could not be staged" in caplog.text

    def test_skip_mount_lane_keeps_output_home(self, tmp_path: Path) -> None:
        """No private /tmp exists without the mount namespace — a
        host-shared /tmp/.home would be attacker-plantable, so the
        skip-mount lane keeps ``<output>/.home``."""
        from core.sandbox.context import (
            check_landlock_available,
            check_net_available,
        )
        if not check_net_available() or not check_landlock_available():
            pytest.skip("Needs user-ns + Landlock")
        from core.sandbox import SandboxSetupError, run as sandbox_run
        out = tmp_path / "out"
        out.mkdir()
        try:
            # run() (not run_untrusted): skip_mount_ns is an isolation
            # control the untrusted wrapper rightly refuses to vary.
            r = sandbox_run(
                ["sh", "-c", "echo HOME=$HOME"],
                target=str(out), output=str(out),
                fake_home=True, skip_mount_ns=True,
                capture_output=True, text=True, timeout=90)
        except SandboxSetupError as exc:
            pytest.skip(f"sandbox setup unavailable: {exc}")
        if r.returncode != 0:
            pytest.skip(f"probe failed rc={r.returncode}: {r.stderr[:200]!r}")
        home = r.stdout.split("HOME=", 1)[1].strip()
        assert home.startswith(str(out))
        assert home.endswith(".home")

    def test_intake_dir_survives_fresh_home_when_empty(
            self, tmp_path: Path) -> None:
        """No pre-population: the construction-time XDG skeleton alone
        must relocate cleanly (empty dirs staged, HOME private)."""
        _require_mount_lane()
        out = tmp_path / "out"
        out.mkdir()
        r = _run_untrusted_or_skip(
            ["sh", "-c",
             "echo HOME=$HOME; ls -a \"$HOME\""],
            str(out))
        if r.returncode != 0:
            pytest.skip(f"probe failed rc={r.returncode}: {r.stderr[:200]!r}")
        assert "HOME=/tmp/.home\n" in r.stdout
        # Construction seeds .config/.cache/.local under the intake;
        # the skeleton must exist in the private home too.
        assert ".config" in r.stdout
        assert ".cache" in r.stdout
