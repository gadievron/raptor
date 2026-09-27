"""The CLI sandbox-disable consent gate.

`--no-sandbox` / `--sandbox none` is a request for tier NONE, honoured
only with a consent of matching authority: a validated minted nonce
(RAPTOR_NO_SANDBOX_NONCE backed by a mode-0600 uid-owned consent
file). Everything else refuses — fail closed, never a silent
re-enable, never a downgrade.

The nonce is the ONLY consent source. Terminal presence grants
nothing: a pty wrapper (`script -qec …`, `pty.spawn`) hands any
composed child real TTYs on stdin/stderr with no operator present, so
TTY-derived authority is manufacturable — the laundering battery
below pins that real-pty invocations REFUSE without a nonce, wrapper
or not. The invocation-shape battery pins the base regression: a
Bash-tool-composed invocation (piped, non-TTY stdin/stderr, no nonce)
passing `--no-sandbox` REFUSES.
"""

import os
import pty
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.sandbox import disable_consent as dc
from core.sandbox import state
from core.sandbox.errors import (
    SandboxDisableRefusedError,
    SandboxSetupError,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

# Child program for the invocation-shape battery. Argv-driven (repo
# root and flags ride sys.argv), so no dynamic values are pasted into
# the program text. On acceptance it prints the stamped consent source.
_GATE_PROG = """\
import sys
sys.path.insert(0, sys.argv[1])
import argparse
from core.sandbox import add_cli_args, apply_cli_args
from core.sandbox import state
p = argparse.ArgumentParser()
add_cli_args(p)
args = p.parse_args(sys.argv[2:])
apply_cli_args(args, parser=p)
print("DISABLED consent=%s" % state._cli_sandbox_disable_consent)
"""


# Pty-laundering wrapper for the launder battery: pty.fork gives the
# wrapped child a real controlling terminal on fds 0/1/2 with no
# operator anywhere — the exact consent-laundering shape the gate must
# refuse. Argv-driven like _GATE_PROG (the wrapped command rides
# sys.argv); the wrapper relays the child's pty output and exits with
# the child's own exit status.
_PTY_WRAP_PROG = """\
import os
import pty
import sys

pid, master = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
chunks = []
while True:
    try:
        data = os.read(master, 4096)
    except OSError:
        break
    if not data:
        break
    chunks.append(data)
os.close(master)
_, status = os.waitpid(pid, 0)
sys.stdout.write(b"".join(chunks).decode("utf-8", "replace"))
sys.exit(os.waitstatus_to_exitcode(status))
"""


def _child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal, controlled child env — never inherits an ambient nonce."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if extra:
        env.update(extra)
    return env


def _run_gate(flags: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", _GATE_PROG, str(REPO_ROOT), *flags],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        timeout=60,
    )


class TestInvocationShapes:
    """Subprocess battery: real fd shapes, real gate, no monkeypatching."""

    @pytest.mark.parametrize("flags", [["--no-sandbox"],
                                       ["--sandbox", "none"]])
    def test_piped_invocation_refuses(self, flags):
        """THE pinned regression: a Bash-tool-composed invocation
        (piped stdio, no nonce) requesting the disable is REFUSED —
        argparse-style exit 2, single-line refusal naming the flag and
        both escape hatches, and the disable never happens."""
        proc = _run_gate(flags, _child_env())
        assert proc.returncode == 2, proc.stderr
        assert "DISABLED" not in proc.stdout
        assert "refused" in proc.stderr
        assert "--no-sandbox" in proc.stderr
        assert "--audit" in proc.stderr
        assert "RAPTOR_NO_SANDBOX_NONCE" in proc.stderr

    def test_piped_invocation_with_bogus_nonce_refuses(self):
        """An attacker-typed env var without the backing consent file
        grants nothing — that is the whole point of the nonce shape."""
        proc = _run_gate(
            ["--no-sandbox"],
            _child_env({dc.NONCE_ENV_VAR: "0" * dc.NONCE_HEX_LEN}),
        )
        assert proc.returncode == 2, proc.stderr
        assert "refused" in proc.stderr

    def test_minted_nonce_accepts(self, no_sandbox_consent_subprocess):
        """The CI/launcher lane: a nonce backed by a real uid-owned
        consent file consents, and the stamp names the source."""
        nonce = no_sandbox_consent_subprocess
        proc = _run_gate(
            ["--no-sandbox"], _child_env({dc.NONCE_ENV_VAR: nonce}))
        assert proc.returncode == 0, proc.stderr
        assert "DISABLED consent=nonce" in proc.stdout

    def test_nonce_without_flag_has_no_effect(
            self, no_sandbox_consent_subprocess):
        """The nonce consents, it never requests: without the flag the
        sandbox state stays enabled."""
        nonce = no_sandbox_consent_subprocess
        prog = (
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from core.sandbox import state\n"
            "assert not state._cli_sandbox_disabled\n"
            "assert state._cli_sandbox_disable_consent is None\n"
            "print('STILL-SANDBOXED')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", prog, str(REPO_ROOT)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_env({dc.NONCE_ENV_VAR: nonce}),
            text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert "STILL-SANDBOXED" in proc.stdout

    @pytest.mark.skipif(sys.platform != "linux",
                        reason="pty semantics exercised on Linux")
    def test_tty_without_nonce_refuses(self) -> None:
        """A REAL pty on stdin+stderr grants nothing without a nonce.
        Terminal presence is manufacturable (any composer is one pty
        wrapper away from this exact fd shape), so it carries no
        authority — the operator-at-a-terminal lane goes through the
        mint, same as CI."""
        parent_fd, child_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", _GATE_PROG, str(REPO_ROOT),
                 "--no-sandbox"],
                stdin=child_fd,
                stdout=subprocess.PIPE,
                stderr=child_fd,
                env=_child_env(),
                text=True,
            )
            os.close(child_fd)
            child_fd = -1
            out, _ = proc.communicate(timeout=60)
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)
        assert proc.returncode == 2, out
        assert "DISABLED" not in out

    @pytest.mark.skipif(sys.platform != "linux",
                        reason="pty semantics exercised on Linux")
    def test_tty_on_stdin_only_refuses(self):
        """Half a terminal is not a terminal: stdin on a pty but
        stderr piped (the fd shape of a worker whose output is
        captured) refuses. Both fds must be interactive."""
        parent_fd, child_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", _GATE_PROG, str(REPO_ROOT),
                 "--no-sandbox"],
                stdin=child_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_env(),
                text=True,
            )
            os.close(child_fd)
            child_fd = -1
            out, err = proc.communicate(timeout=60)
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)
        assert proc.returncode == 2, err
        assert "refused" in err
        assert "DISABLED" not in out

    @pytest.mark.skipif(sys.platform != "linux",
                        reason="pty semantics exercised on Linux")
    def test_tty_on_stderr_only_refuses(self) -> None:
        """The mirror of the stdin-only shape: stderr on a pty but
        stdin piped refuses too — the stdin leg of the probe must
        carry weight of its own, never ride the stderr result."""
        parent_fd, child_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", _GATE_PROG, str(REPO_ROOT),
                 "--no-sandbox"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=child_fd,
                env=_child_env(),
                text=True,
            )
            os.close(child_fd)
            child_fd = -1
            if proc.stdin is not None:
                proc.stdin.close()
            out, _ = proc.communicate(timeout=60)
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)
        assert proc.returncode == 2
        assert "DISABLED" not in out

    @pytest.mark.skipif(sys.platform != "linux",
                        reason="pty semantics exercised on Linux")
    @pytest.mark.skipif(shutil.which("script") is None,
                        reason="util-linux script(1) not on PATH")
    def test_script_pty_wrap_refuses(self, tmp_path: Path) -> None:
        """The consent-laundering pin, stock-tooling form: `script
        -qec <gate>` runs the gate on a real controlling terminal with
        no operator present. Without a nonce this must REFUSE — a pty
        wrapper is not a consent. (script(1) merges the child's pty
        output — stdout and stderr — into its own stdout, so the
        refusal text is asserted there; `-e` propagates the child's
        exit code.)"""
        prog = tmp_path / "gate_prog.py"
        prog.write_text(_GATE_PROG, encoding="utf-8")
        inner = " ".join(shlex.quote(p) for p in [
            sys.executable, str(prog), str(REPO_ROOT), "--no-sandbox"])
        proc = subprocess.run(
            ["script", "-qec", inner, "/dev/null"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_env(),
            text=True,
            timeout=60,
        )
        assert proc.returncode == 2, proc.stdout
        assert "DISABLED" not in proc.stdout
        assert "refused" in proc.stdout

    @pytest.mark.skipif(sys.platform != "linux",
                        reason="pty semantics exercised on Linux")
    def test_pty_fork_wrap_refuses(self, tmp_path: Path) -> None:
        """The consent-laundering pin, three-lines-of-python form: a
        pty.fork wrapper gives the gate a controlling terminal on all
        three fds. Same verdict as the script(1) form — REFUSE without
        a nonce."""
        prog = tmp_path / "gate_prog.py"
        prog.write_text(_GATE_PROG, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-c", _PTY_WRAP_PROG,
             sys.executable, str(prog), str(REPO_ROOT), "--no-sandbox"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_env(),
            text=True,
            timeout=60,
        )
        assert proc.returncode == 2, proc.stdout
        assert "DISABLED" not in proc.stdout
        assert "refused" in proc.stdout


class TestGateInProcess:
    """Library-caller semantics: the exception type, its lineage, and
    state integrity after a refusal. No fd conditioning is needed —
    the gate never probes the process fds, so these run identically
    under a terminal and under CI capture (the conftest env guard
    strips any ambient nonce)."""

    def test_disable_from_cli_refuses(self):
        from core.sandbox import disable_from_cli
        with pytest.raises(SandboxDisableRefusedError):
            disable_from_cli()

    def test_set_cli_profile_none_refuses(self):
        from core.sandbox import set_cli_profile
        with pytest.raises(SandboxDisableRefusedError):
            set_cli_profile("none")

    def test_refusal_leaves_state_untouched(self):
        """A refused disable must not half-mutate: the prior profile
        stays in force and no consent is stamped."""
        from core.sandbox import set_cli_profile
        set_cli_profile("full")
        with pytest.raises(SandboxDisableRefusedError):
            set_cli_profile("none")
        assert state._cli_sandbox_profile == "full"
        assert not state._cli_sandbox_disabled
        assert state._cli_sandbox_disable_consent is None

    def test_refusal_is_baseexception_grade(self):
        """The refusal must ride the SandboxSetupError lineage
        (BaseException): a broad `except Exception` between the
        argparse boundary and the run must not be able to swallow it
        and proceed at a posture the gate refused to decide."""
        assert issubclass(SandboxDisableRefusedError, SandboxSetupError)
        assert not issubclass(SandboxDisableRefusedError, Exception)

    def test_apply_cli_args_parser_error_exit_2(self, capsys):
        """CLI boundary UX: with a parser, the refusal goes through
        parser.error — single line, exit code 2, no traceback."""
        import argparse

        from core.sandbox import add_cli_args, apply_cli_args
        parser = argparse.ArgumentParser(prog="gate-test")
        add_cli_args(parser)
        args = parser.parse_args(["--no-sandbox"])
        with pytest.raises(SystemExit) as excinfo:
            apply_cli_args(args, parser=parser)
        assert excinfo.value.code == 2
        assert "refused" in capsys.readouterr().err

    def test_apply_cli_args_without_parser_raises_refusal(self):
        """Library callers get the refusal itself — never a ValueError
        downgrade an `except Exception` could eat."""
        import argparse

        from core.sandbox import add_cli_args, apply_cli_args
        parser = argparse.ArgumentParser()
        add_cli_args(parser)
        args = parser.parse_args(["--no-sandbox"])
        with pytest.raises(SandboxDisableRefusedError):
            apply_cli_args(args)

    def test_tty_presence_grants_nothing(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The no-TTY-arm pin, resolver form: even with every fd
        reporting as a terminal, resolution without a nonce is None.
        The resolver must never consult the fds — a reintroduced
        isatty grant turns this red."""
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        assert dc.resolve_disable_consent() is None

    def test_nonce_lane_accepts_in_process(self, no_sandbox_consent):
        assert dc.resolve_disable_consent() == "nonce"

    def test_disabled_run_stamps_consent_in_sandbox_info(
            self, no_sandbox_consent):
        """An accepted disable is attributable on the run result:
        sandbox_info carries the consent source."""
        from core.sandbox import sandbox, set_cli_profile
        set_cli_profile("none")
        with sandbox(profile="full") as run:
            result = run(["echo", "ok"], capture_output=True, text=True)
        assert result.returncode == 0
        assert result.sandbox_info["disable_consent"] == "nonce"


class TestNonceFileValidation:
    """Fail-closed file checks, each exercised in isolation."""

    @pytest.fixture
    def consents(self, monkeypatch, tmp_path):
        d = tmp_path / "consents.d"
        d.mkdir(mode=0o700)
        monkeypatch.setattr(dc, "_consents_dir", lambda: d)
        return d

    def _mint(self, d: Path, nonce: str, *, content: str | None = None,
              mode: int = 0o600) -> Path:
        path = d / dc._nonce_filename(nonce)
        body = content if content is not None else dc._nonce_digest(nonce)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, (body + "\n").encode("ascii"))
        finally:
            os.close(fd)
        # O_CREAT mode is filtered by umask; pin the intended bits.
        os.chmod(path, mode)
        return path

    NONCE = "ab" * 16  # 32 lowercase hex chars

    def test_valid_file_consents(self, consents, monkeypatch):
        self._mint(consents, self.NONCE)
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() == "nonce"

    def test_missing_file_refuses(self, consents, monkeypatch):
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_group_readable_file_refuses(self, consents, monkeypatch):
        self._mint(consents, self.NONCE, mode=0o640)
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_other_readable_file_refuses(self, consents,
                                         monkeypatch) -> None:
        """The OTHER half of the permission check: a world-readable
        file with clean group bits (0o604) is refused just like a
        group-readable one — both legs of the 0o077 mask carry
        weight."""
        self._mint(consents, self.NONCE, mode=0o604)
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_consent_dir_ignores_home_env(self, tmp_path,
                                          monkeypatch) -> None:
        """The claimed "passwd-derived home (never $HOME)" property:
        a composed command line can carry HOME=/attacker/dir, so a
        valid-in-every-other-way consent file planted under $HOME
        must grant nothing — the consent dir comes from the passwd
        database and does not move with the environment. (No
        _consents_dir monkeypatch here: this test exercises the real
        derivation.)"""
        passwd_dir = dc._consents_dir()
        fake_home = tmp_path / "attacker-home"
        planted = fake_home / ".local" / "share" / "raptor" / "consents.d"
        planted.mkdir(parents=True, mode=0o700)
        nonce = secrets.token_hex(dc.NONCE_HEX_LEN // 2)
        self._mint(planted, nonce)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv(dc.NONCE_ENV_VAR, nonce)
        # The derivation itself must not move ...
        assert dc._consents_dir() == passwd_dir
        # ... and the planted file must not consent (the freshly
        # random nonce has no file under the real passwd-derived dir).
        assert dc.resolve_disable_consent() is None

    def test_symlink_refuses(self, consents, tmp_path, monkeypatch):
        real = tmp_path / "elsewhere"
        real.write_text(dc._nonce_digest(self.NONCE) + "\n")
        real.chmod(0o600)
        (consents / dc._nonce_filename(self.NONCE)).symlink_to(real)
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_wrong_content_refuses(self, consents, monkeypatch):
        """Digest-derived filename alone is not consent — the content
        must be the digest of the presented nonce."""
        self._mint(consents, self.NONCE, content="not-the-digest")
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_oversize_file_refuses(self, consents, monkeypatch):
        self._mint(consents, self.NONCE,
                   content=dc._nonce_digest(self.NONCE) + "x" * 4096)
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_expired_file_refuses(self, consents, monkeypatch):
        path = self._mint(consents, self.NONCE)
        past = time.time() - 601.0  # literal: one second past the TTL
        os.utime(path, (past, past))
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    def test_fresh_file_within_ttl_consents(self, consents, monkeypatch):
        path = self._mint(consents, self.NONCE)
        past = time.time() - 599.0  # literal: one second inside the TTL
        os.utime(path, (past, past))
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() == "nonce"

    def test_future_mtime_refuses(self, consents, monkeypatch):
        path = self._mint(consents, self.NONCE)
        future = time.time() + 120.0
        os.utime(path, (future, future))
        monkeypatch.setenv(dc.NONCE_ENV_VAR, self.NONCE)
        assert dc.resolve_disable_consent() is None

    @pytest.mark.parametrize("bad", [
        "",                     # empty
        "ab" * 15,              # too short (30 chars)
        "ab" * 17,              # too long (34 chars)
        "AB" * 16,              # uppercase hex
        "zz" * 16,              # non-hex
        "ab" * 15 + "g1",       # trailing non-hex
    ])
    def test_malformed_nonce_refuses(self, consents, monkeypatch, bad):
        monkeypatch.setenv(dc.NONCE_ENV_VAR, bad)
        assert dc.resolve_disable_consent() is None


class TestConstantsPinned:
    """Literal-pinned expectations — a mutated constant must turn a
    test red, so no expectation below derives from the module."""

    def test_env_var_name(self):
        assert dc.NONCE_ENV_VAR == "RAPTOR_NO_SANDBOX_NONCE"

    def test_nonce_hex_len(self):
        assert dc.NONCE_HEX_LEN == 32

    def test_ttl_seconds(self):
        assert dc.NONCE_FILE_TTL_S == 600.0

    def test_max_file_bytes(self):
        assert dc.NONCE_FILE_MAX_BYTES == 4096

    def test_refusal_message_names_flag_and_hatches(self):
        for needle in ("--no-sandbox", "--sandbox none", "--audit",
                       "RAPTOR_NO_SANDBOX_NONCE",
                       "docs/sandbox.md", "refused"):
            assert needle in dc.REFUSAL_MESSAGE, needle

    def test_refusal_message_is_not_a_recipe(self) -> None:
        """The refusal names the consent route by docs anchor only.
        A runnable mint-script path in the refusal would hand the
        bypass recipe to exactly the composer that was just refused
        — pin the no-recipe direction."""
        assert "mint-no-sandbox-nonce" not in dc.REFUSAL_MESSAGE
        assert "scripts/" not in dc.REFUSAL_MESSAGE

    def test_refusal_message_single_line(self):
        assert "\n" not in dc.REFUSAL_MESSAGE

    def test_consent_labels(self) -> None:
        assert dc.CONSENT_NONCE == "nonce"

    def test_no_interactive_consent_label(self) -> None:
        """The interactive-TTY consent arm is deliberately gone (pty
        wrappers manufacture the signal). Its label must not
        reappear — a resurrected CONSENT_INTERACTIVE constant is the
        first visible symptom of the arm coming back."""
        assert not hasattr(dc, "CONSENT_INTERACTIVE")


class TestExportDisableConsent:
    """Runtime propagation is extension-only: it can carry an accepted
    consent across a spawn boundary, never create one."""

    def test_no_accepted_consent_never_mints(self, monkeypatch, tmp_path):
        d = tmp_path / "consents.d"
        monkeypatch.setattr(dc, "_consents_dir", lambda: d)
        env: dict[str, str] = {}
        dc.export_disable_consent(env)
        assert dc.NONCE_ENV_VAR not in env
        assert not d.exists()  # not even the directory is created

    def test_disabled_without_consent_stamp_never_mints(
            self, monkeypatch, tmp_path):
        """Direct state pokes (no gate) don't earn propagation: both
        the disabled flag AND the consent stamp are required."""
        d = tmp_path / "consents.d"
        monkeypatch.setattr(dc, "_consents_dir", lambda: d)
        monkeypatch.setattr(state, "_cli_sandbox_disabled", True)
        env: dict[str, str] = {}
        dc.export_disable_consent(env)
        assert dc.NONCE_ENV_VAR not in env

    def test_accepted_consent_mints_valid_child_nonce(
            self, no_sandbox_consent, monkeypatch):
        """Aged-out-lane shape: accepted consent, but the parent's own
        env nonce is gone (e.g. its file expired mid-run) — the export
        mints a fresh, valid nonce."""
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        monkeypatch.delenv(dc.NONCE_ENV_VAR)
        env: dict[str, str] = {}
        dc.export_disable_consent(env)
        child_nonce = env[dc.NONCE_ENV_VAR]
        assert child_nonce != no_sandbox_consent
        assert dc._presented_nonce_valid(child_nonce)

    def test_accepted_consent_reuses_valid_env_nonce(
            self, no_sandbox_consent):
        """CI-lane shape: the parent's env nonce is still valid — the
        export forwards it instead of minting."""
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        env: dict[str, str] = {}
        dc.export_disable_consent(env)
        assert env[dc.NONCE_ENV_VAR] == no_sandbox_consent

    def test_mint_sweeps_expired_files(self, no_sandbox_consent,
                                       monkeypatch):
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        monkeypatch.delenv(dc.NONCE_ENV_VAR)
        d = dc._consents_dir()
        stale = d / "no-sandbox.deadbeef"
        stale.write_text("stale\n")
        past = time.time() - 601.0
        os.utime(stale, (past, past))
        dc.export_disable_consent({})
        assert not stale.exists()

    def test_minted_file_mode_0600(self, no_sandbox_consent, monkeypatch):
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        monkeypatch.delenv(dc.NONCE_ENV_VAR)
        env: dict[str, str] = {}
        dc.export_disable_consent(env)
        path = dc._consents_dir() / dc._nonce_filename(env[dc.NONCE_ENV_VAR])
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


class TestEnvPolicy:
    """The nonce var's env-policy posture, both directions pinned.

    Never allowlisted (ambient inheritance would hand consent to every
    scrub-spawned child, including target-adjacent tool children);
    always target-stripped (code executed on behalf of a scanned
    target must not observe or replay a live consent). Propagation
    along RAPTOR's own worker spine is site-specific instead — those
    sites are pinned below so a refactor can't silently drop them.
    """

    def test_nonce_var_never_in_safe_env_allowlist(self):
        from core.config import RaptorConfig
        assert dc.NONCE_ENV_VAR not in RaptorConfig.SAFE_ENV_ALLOWLIST

    def test_nonce_var_in_target_strip_set(self):
        from core.config import RaptorConfig
        assert dc.NONCE_ENV_VAR in RaptorConfig.TARGET_ENV_STRIP_SET

    def test_get_safe_env_drops_ambient_nonce(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setenv(dc.NONCE_ENV_VAR, "ab" * 16)
        assert dc.NONCE_ENV_VAR not in RaptorConfig.get_safe_env()

    def test_seatbelt_shim_keep_arm_strips_nonce(self) -> None:
        """Trust markers and disable-consent nonces are different
        authorities: the shim's keep-trust dispatch arm keeps the
        markers by design, but a live consent nonce must never ride
        that lane into a dispatched child. Pin the KEEP arm tuple."""
        shim = (REPO_ROOT / "libexec" / "raptor-seatbelt-shim"
                ).read_text(encoding="utf-8")
        start = shim.index("_strip = (")
        keep_arm = shim[start:shim.index("if keep_trust_markers", start)]
        assert f'"{dc.NONCE_ENV_VAR}"' in keep_arm, (
            "the seatbelt shim keep-trust arm no longer strips the "
            "disable-consent nonce"
        )

    def test_seatbelt_shim_else_arm_strips_nonce(self) -> None:
        """Arm-scoped twin of the strip-set sync test: with the nonce
        now in BOTH arms of the shim's conditional strip tuple, a
        whole-file needle match would keep passing after the default
        (else) arm lost its copy — so pin the else-arm slice
        itself."""
        shim = (REPO_ROOT / "libexec" / "raptor-seatbelt-shim"
                ).read_text(encoding="utf-8")
        start = shim.index("_strip = (")
        start = shim.index("else (", start)
        else_arm = shim[start:shim.index("\n        )", start)]
        assert f'"{dc.NONCE_ENV_VAR}"' in else_arm, (
            "the seatbelt shim default (else) strip arm no longer "
            "strips the disable-consent nonce"
        )

    def test_context_keep_dispatch_arm_strips_nonce(self) -> None:
        """The Linux twin of the shim keep arm: context.run()'s
        keep-trust dispatch env filter must drop the nonce even
        though it keeps the trust markers."""
        src = (REPO_ROOT / "core" / "sandbox" / "context.py"
               ).read_text(encoding="utf-8")
        start = src.index("if _keep_for_dispatch:")
        arm = src[start:src.index("elif _untrusted_workload:", start)]
        assert f'"{dc.NONCE_ENV_VAR}"' in arm, (
            "context.run()'s keep-trust dispatch arm no longer strips "
            "the disable-consent nonce"
        )

    def test_spine_propagation_sites_present(self):
        """The two spine parents forward consent explicitly: raptor.py
        (argv forwarder, verbatim pass-through) and raptor_agentic.py
        (consent holder, guarded export at both gate-hitting spawns).
        Source pin — the wiring lives inside main() spawn plumbing
        that has no seam for in-process invocation."""
        entry = (REPO_ROOT / "raptor.py").read_text(encoding="utf-8")
        assert "passthrough_nonce_env(worker_env)" in entry
        assert "passthrough_nonce_env(fallback_env)" in entry
        agentic = (REPO_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert "_export_disable_consent(scanner_env)" in agentic
        assert "_export_disable_consent(codeql_env)" in agentic

    def test_mint_script_exists_and_mints_valid_consent(
            self, monkeypatch, tmp_path):
        """The operator/CI mint path named in the operator docs (the
        refusal deliberately points at the docs anchor, never at this
        runnable path) must exist and produce a nonce the real
        validator accepts."""
        script = REPO_ROOT / "core" / "sandbox" / "scripts" / (
            "mint-no-sandbox-nonce")
        assert script.is_file()
        assert os.access(script, os.X_OK)
        proc = subprocess.run(
            [sys.executable, str(script)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        nonce = proc.stdout.strip()
        try:
            assert dc._nonce_format_ok(nonce)
            assert dc._presented_nonce_valid(nonce)
        finally:
            # The script mints into the REAL per-uid consents dir.
            (dc._consents_dir() / dc._nonce_filename(nonce)).unlink()


class TestPassthroughNonceEnv:
    def test_copies_when_present(self, monkeypatch):
        monkeypatch.setenv(dc.NONCE_ENV_VAR, "ab" * 16)
        env: dict[str, str] = {}
        dc.passthrough_nonce_env(env)
        assert env[dc.NONCE_ENV_VAR] == "ab" * 16

    def test_noop_when_absent(self, monkeypatch):
        monkeypatch.delenv(dc.NONCE_ENV_VAR, raising=False)
        env: dict[str, str] = {}
        dc.passthrough_nonce_env(env)
        assert dc.NONCE_ENV_VAR not in env
