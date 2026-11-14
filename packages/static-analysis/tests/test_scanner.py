"""Tests for packages/static-analysis/scanner.py."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import packages.codeql as codeql


# static-analysis has a hyphen — load via importlib

from core.testing.module_bindings import mock_module_attribute

_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location("static_analysis_scanner", _SCANNER_PATH)
_scanner_mod = importlib.util.module_from_spec(_spec)
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
_spec.loader.exec_module(_scanner_mod)

run_codeql = _scanner_mod.run_codeql


# ---------------------------------------------------------------------------
# run_codeql() — post-unification: delegates to packages/codeql/agent.py
# Pre-unification this module shipped its own ~80-LOC WIP CodeQL runner.
# The proper one in packages/codeql/agent.py has auto-detect, build
# synthesis, content-addressed cache, trust check, language alias
# normalisation. Tests below assert the delegation contract: subprocess
# invocation of the agent, SARIF discovery from out_dir, plumbing of
# operator-supplied flags through to the agent's argv.
# ---------------------------------------------------------------------------

def _fake_popen(returncode=0, stdout="", stderr="", communicate_side_effect=None):
    """Build a MagicMock that quacks like subprocess.Popen."""
    fake = MagicMock()
    fake.pid = 12345
    fake.returncode = returncode
    if communicate_side_effect is not None:
        fake.communicate.side_effect = communicate_side_effect
    else:
        fake.communicate.return_value = (stdout, stderr)
    return fake


class TestRunCodeqlDelegation:

    def test_returns_empty_when_codeql_not_installed(self, tmp_path, monkeypatch):
        """No configured or PATH CLI → bail before invoking agent."""
        monkeypatch.delenv("CODEQL_CLI", raising=False)
        with mock_module_attribute(codeql, "shutil", "which", return_value=None):
            result = run_codeql(tmp_path, tmp_path / "out", ["python"])
        assert result == []

    @pytest.mark.parametrize("valid_override", [True, False])
    def test_configured_launcher_without_path_cli(self, tmp_path, monkeypatch, valid_override):
        """An executable override admits dispatch; an invalid file does not."""
        launcher = tmp_path / "configured-codeql"
        launcher.write_text("inert sentinel; never executed\n")
        launcher.chmod(0o700 if valid_override else 0o600)
        monkeypatch.setenv("CODEQL_CLI", str(launcher))
        with mock_module_attribute(codeql, "shutil", "which", return_value=None), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            result = run_codeql(tmp_path, tmp_path / "out", ["python"])
        assert result == []
        assert mock_proc.call_count == int(valid_override)

    def test_creates_output_dir(self, tmp_path):
        """out_dir is created up-front (matches pre-unification
        contract — downstream consumers may glob for SARIFs even
        if the agent never wrote one)."""
        out_dir = tmp_path / "codeql_out"
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen(returncode=1, stderr="agent failed")
            run_codeql(tmp_path, out_dir, ["python"])
        assert out_dir.exists()

    def test_invokes_agent_subprocess_with_repo_and_out(self, tmp_path):
        """The unification contract: subprocess invocation of
        packages/codeql/agent.py with --repo and --out."""
        out_dir = tmp_path / "out"
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, out_dir, languages=None)

        assert mock_proc.called, "subprocess.Popen was not called"
        cmd = mock_proc.call_args.args[0]
        assert cmd[0] == sys.executable
        # Agent script path component.
        assert any("packages/codeql/agent.py" in part for part in cmd), \
            f"agent.py not in cmd: {cmd}"
        # --repo and --out present and pointing at the right dirs.
        assert "--repo" in cmd and str(tmp_path) in cmd
        assert "--out" in cmd and str(out_dir) in cmd

    def test_popen_uses_new_session_for_orphan_cleanup(self, tmp_path):
        """Without start_new_session=True, SIGKILL on the agent
        leaves codeql grandchildren as orphans holding cache locks
        + memory until they finish. The unification PR's bare
        subprocess.run had this bug; the Popen migration fixes it.
        """
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, tmp_path / "out", languages=None)

        kwargs = mock_proc.call_args.kwargs
        assert kwargs.get("start_new_session") is True, (
            f"Popen must be invoked with start_new_session=True for "
            f"orphan-process cleanup; saw {kwargs}"
        )

    def test_languages_forwarded_as_csv(self, tmp_path):
        """An explicit language list flows through as --languages a,b."""
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, tmp_path / "out", languages=["cpp", "java"])

        cmd = mock_proc.call_args.args[0]
        assert "--languages" in cmd
        idx = cmd.index("--languages")
        assert cmd[idx + 1] == "cpp,java"

    def test_no_languages_arg_when_none(self, tmp_path):
        """languages=None ⇒ no --languages flag passed; the agent
        auto-detects. This is the recommended default — the agent
        skips empty languages, vs the pre-unification 'always make
        cpp/java/python/go DBs' behaviour."""
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, tmp_path / "out", languages=None)

        cmd = mock_proc.call_args.args[0]
        assert "--languages" not in cmd

    def test_build_command_forwarded(self, tmp_path):
        """build_command flows through as --build-command for the
        agent's CodeQL DB creation."""
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(
                tmp_path, tmp_path / "out",
                languages=["cpp"], build_command="make -j4",
            )

        cmd = mock_proc.call_args.args[0]
        assert "--build-command" in cmd
        idx = cmd.index("--build-command")
        assert cmd[idx + 1] == "make -j4"

    def test_returns_globbed_sarif_paths(self, tmp_path):
        """After the agent runs, scanner globs out_dir for
        codeql_*.sarif. Naming matches pre-unification convention."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        # Simulate the agent having written two language SARIFs.
        def complete(**kwargs):
            (out_dir / "codeql_cpp.sarif").write_text("{}")
            (out_dir / "codeql_python.sarif").write_text("{}")
            return "", ""
        # And a non-matching file we must NOT pick up.
        (out_dir / "scan_metrics.json").write_text("{}")

        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen(communicate_side_effect=complete)
            result = run_codeql(tmp_path, out_dir, languages=None)

        assert sorted(result) == sorted([
            str(out_dir / "codeql_cpp.sarif"),
            str(out_dir / "codeql_python.sarif"),
        ])

    def test_partial_success_returns_what_agent_wrote(self, tmp_path):
        """Agent rc != 0 doesn't void the SARIFs that DID land.
        One language extraction failing shouldn't drop the
        successful one's findings."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        def complete(**kwargs):
            (out_dir / "codeql_python.sarif").write_text("{}")
            return "", "cpp build failed"

        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen(
                returncode=1, communicate_side_effect=complete,
            )
            result = run_codeql(tmp_path, out_dir, languages=["python", "cpp"])

        assert result == [str(out_dir / "codeql_python.sarif"),
                          str(out_dir / "codeql_stage_diagnostics.sarif")]

    def test_subprocess_timeout_killpgs_and_returns_empty(self, tmp_path):
        """Agent timeout: SIGKILL the entire process group (so
        codeql grandchildren die with the agent) and return empty
        rather than raise. Matches the no-raise contract scanner
        expects from every stage AND prevents orphan codeql holding
        cache locks."""
        import subprocess
        fake = _fake_popen(
            communicate_side_effect=subprocess.TimeoutExpired(
                cmd="codeql", timeout=3600,
            ),
        )
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_popen, \
             mock_module_attribute(_scanner_mod, 'os', "killpg") as mock_killpg, \
             mock_module_attribute(_scanner_mod, 'os', "getpgid", return_value=12345):
            mock_popen.return_value = fake
            result = run_codeql(tmp_path, tmp_path / "out", languages=None)

        assert result == []
        # killpg must have been called with the agent's PGID +
        # SIGKILL — anything less leaves codeql running.
        assert mock_killpg.called, (
            "killpg not invoked on TimeoutExpired — codeql will orphan"
        )
        args = mock_killpg.call_args.args
        assert args[0] == 12345
        assert args[1] == _scanner_mod.signal.SIGKILL

    def test_killpg_swallows_processlookup_when_child_already_died(self, tmp_path):
        """If the agent died on its own between communicate() and
        our killpg, ProcessLookupError must not propagate as an
        uncaught exception."""
        import subprocess
        fake = _fake_popen(
            communicate_side_effect=subprocess.TimeoutExpired(
                cmd="codeql", timeout=3600,
            ),
        )
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_popen, \
             mock_module_attribute(_scanner_mod, 'os', "killpg",
                          side_effect=ProcessLookupError()), \
             mock_module_attribute(_scanner_mod, 'os', "getpgid", return_value=12345):
            mock_popen.return_value = fake
            # Should not raise; should still return [].
            result = run_codeql(tmp_path, tmp_path / "out", languages=None)
        assert result == []

    def test_subprocess_oserror_returns_empty(self, tmp_path):
        """Popen itself failing to spawn (ENOEXEC etc.) is caught."""
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen",
                          side_effect=OSError("ENOEXEC")):
            result = run_codeql(tmp_path, tmp_path / "out", languages=None)
        assert result == []


_compute_python_tool_paths = _scanner_mod._compute_python_tool_paths


class TestComputePythonToolPaths:
    """Tool-path inference for Python tools. Reads cmd[0]'s shebang to
    find the interpreter, then derives the stdlib dir from interp
    path + version. Used as tool_paths kwarg so mount-ns can engage
    for pip --user installed Python tools (semgrep is the original
    case). The result is speculative — context.py's speculative-C
    retry catches misses and falls back to Landlock-only."""

    def test_empty_cmd_returns_empty(self):
        assert _compute_python_tool_paths([]) == []

    def test_unreadable_path_still_includes_bin_dir(self, tmp_path):
        """Path doesn't exist as a file → no shebang, but the bin
        dir IS still added (absolute path is recoverable)."""
        bogus = tmp_path / "subdir" / "bogus-binary"
        bogus.parent.mkdir()
        result = _compute_python_tool_paths([str(bogus)])
        # Subdir is the bin dir.
        assert any(p == str(tmp_path / "subdir") for p in result), \
            f"expected bin dir in result, got {result!r}"

    def test_skips_system_paths(self):
        """Paths already in the mount-ns bind tree (/usr, /bin, etc.)
        should be skipped — no point asking for a redundant bind."""
        # /usr/bin/python3 → bin dir /usr/bin (skip), interp lib at
        # /usr/lib/python3.X (skip). Net: should be empty.
        result = _compute_python_tool_paths(["/usr/bin/python3"])
        for path in result:
            assert not path.startswith(("/usr/", "/lib/", "/lib64/")), \
                f"{path!r} should have been filtered out"

    def test_python_tool_with_shebang_returns_bin_and_stdlib(
            self, tmp_path):
        """A pip-style Python tool: bin/script with #!python shebang,
        interpreter in same bin dir, stdlib at ../lib/pythonX.Y.
        Synthesise this layout in tmp_path and verify both dirs
        come back."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        lib_dir = tmp_path / "lib" / "python3.13"
        lib_dir.mkdir(parents=True)
        # Synthesise a Python interpreter file (need not be runnable;
        # is_file() check is what the helper uses).
        py = bin_dir / "python3.13"
        py.write_text("#!/bin/sh\necho fake python\n")
        py.chmod(0o755)
        # Synthesise the script with shebang pointing at our fake.
        script = bin_dir / "myscript"
        script.write_text(f"#!{py}\nprint('hi')\n")
        script.chmod(0o755)
        result = _compute_python_tool_paths([str(script)])
        assert str(bin_dir) in result, \
            f"bin dir missing from {result!r}"
        assert str(lib_dir) in result, \
            f"stdlib dir missing from {result!r}"

    def _fake_prefix_layout(self, root, with_pyvenv_cfg):
        """Synthesise a Python prefix layout under ``root``:
        bin/python3.13 (fake interpreter file), lib/python3.13/,
        and a console script whose shebang points at the fake
        interpreter. With ``with_pyvenv_cfg`` the layout is a PEP
        405 venv (pyvenv.cfg at the root); without it, a plain
        prefix install. Returns (script, bin_dir, lib_dir)."""
        bin_dir = root / "bin"
        bin_dir.mkdir()
        lib_dir = root / "lib" / "python3.13"
        lib_dir.mkdir(parents=True)
        py = bin_dir / "python3.13"
        py.write_text("#!/bin/sh\necho fake python\n")
        py.chmod(0o755)
        script = bin_dir / "sometool"
        script.write_text(f"#!{py}\nprint('hi')\n")
        script.chmod(0o755)
        if with_pyvenv_cfg:
            (root / "pyvenv.cfg").write_text(
                "home = /usr/bin\n"
                "include-system-site-packages = false\n"
            )
        return script, bin_dir, lib_dir

    def test_venv_layout_binds_cfg_without_whole_prefix(
            self, tmp_path):
        """pyvenv.cfg visibility is the PEP 405 venv-activation
        toggle; without it the interpreter falls back to the base
        prefix and drops the venv site-packages. A layout WITH
        pyvenv.cfg gets its own exact bind alongside bin/ and libraries;
        the prefix itself must not be exposed."""
        venv = tmp_path / "venv"
        venv.mkdir()
        script, bin_dir, lib_dir = self._fake_prefix_layout(
            venv, with_pyvenv_cfg=True)
        result = _compute_python_tool_paths([str(script)])
        assert str(venv) not in result
        assert str(venv / 'pyvenv.cfg') in result
        assert str(bin_dir) in result, \
            f"bin dir missing from {result!r}"
        assert str(lib_dir) in result, \
            f"stdlib dir missing from {result!r}"

    def test_layout_without_pyvenv_cfg_excludes_root(self, tmp_path):
        """Identical layout but NO pyvenv.cfg → a plain prefix
        install, not a venv; the root holds nothing Python needs and
        must stay OUT of the bind set (least privilege for the mount
        namespace). bin/ and lib/pythonX.Y/ keep their binds."""
        prefix = tmp_path / "prefix"
        prefix.mkdir()
        script, bin_dir, lib_dir = self._fake_prefix_layout(
            prefix, with_pyvenv_cfg=False)
        result = _compute_python_tool_paths([str(script)])
        assert str(prefix) not in result, \
            f"non-venv root wrongly bound: {result!r}"
        assert str(bin_dir) in result, \
            f"bin dir regressed: {result!r}"
        assert str(lib_dir) in result, \
            f"stdlib dir regressed: {result!r}"

    def test_system_prefix_venv_root_is_skipped(self, tmp_path):
        """A /usr-rooted layout adds nothing: even when pyvenv.cfg
        appears to exist at the system prefix root, /usr is already
        in the mount-ns bind tree and must not enter the bind set.
        The venv root is the only derived path that can land ON a
        skip prefix (bin/stdlib dirs are always deeper), so fake the
        cfg's existence to make the prefix skip the deciding gate."""
        script = tmp_path / "tool"
        script.write_text("#!/usr/bin/python3\nprint('hi')\n")
        script.chmod(0o755)
        real_is_file = Path.is_file

        def fake_is_file(self):
            # Fake interp + cfg so the venv-root branch runs without
            # needing writable /usr; everything else stays real.
            if str(self) in ("/usr/bin/python3", "/usr/pyvenv.cfg"):
                return True
            return real_is_file(self)

        with patch.object(Path, "is_file", fake_is_file):
            result = _compute_python_tool_paths([str(script)])
        assert "/usr" not in result, \
            f"system prefix root wrongly bound: {result!r}"
        for p in result:
            assert not p.startswith("/usr/"), \
                f"{p!r} should have been filtered out"
        # Sanity: the function did run past the interp branch — the
        # script's own bin dir (interesting) is still returned.
        assert str(tmp_path.resolve()) in result, \
            f"script bin dir missing from {result!r}"


class TestValidatePolicyGroups:
    """Unknown policy groups are an argparse-level hard error, not a
    mid-scan warning — operators copying a bad example must find out
    before the scan silently runs without the intended rules."""

    def _parser(self):
        import argparse
        return argparse.ArgumentParser(prog="scanner-test")

    def _rules_base(self, tmp_path, groups=("injection", "crypto")):
        base = tmp_path / "rules"
        for g in groups:
            (base / g).mkdir(parents=True)
        (base / "registry-cache").mkdir()
        return base

    def test_unknown_group_is_hard_error(self, tmp_path, capsys):
        import pytest
        base = self._rules_base(tmp_path)
        with patch.object(
            _scanner_mod.RaptorConfig, "SEMGREP_RULES_DIR", base,
        ):
            with pytest.raises(SystemExit) as exc:
                _scanner_mod._validate_policy_groups(
                    self._parser(), "injction",
                )
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "injction" in err
        assert "injection" in err  # valid groups are listed
        assert "crypto" in err

    def test_reserved_group_is_hard_error(self, tmp_path):
        import pytest
        base = self._rules_base(tmp_path)
        with patch.object(
            _scanner_mod.RaptorConfig, "SEMGREP_RULES_DIR", base,
        ):
            with pytest.raises(SystemExit):
                _scanner_mod._validate_policy_groups(
                    self._parser(), "registry-cache",
                )

    def test_valid_groups_pass(self, tmp_path):
        base = self._rules_base(tmp_path)
        with patch.object(
            _scanner_mod.RaptorConfig, "SEMGREP_RULES_DIR", base,
        ):
            _scanner_mod._validate_policy_groups(
                self._parser(), "injection, crypto",
            )
            _scanner_mod._validate_policy_groups(self._parser(), "all")

    def test_unreadable_rules_dir_does_not_error(self, tmp_path):
        with patch.object(
            _scanner_mod.RaptorConfig, "SEMGREP_RULES_DIR",
            tmp_path / "missing",
        ):
            _scanner_mod._validate_policy_groups(
                self._parser(), "whatever",
            )


# ---------------------------------------------------------------------------
# _CodeQLStageHandle — abort kill switch for the concurrent stage
# ---------------------------------------------------------------------------
# An exception between the stage submit and its join (semgrep's
# fail-loud SandboxSetupError, KeyboardInterrupt) used to reach
# sys.exit while concurrent.futures joined the non-daemon worker:
# "scan aborted" then hung up to 1h on the agent's communicate.


class TestCodeQLStageHandle:

    def test_abort_kills_registered_process_group(self):
        import subprocess as sp
        handle = _scanner_mod._CodeQLStageHandle()
        proc = sp.Popen(["sleep", "60"], start_new_session=True)
        try:
            handle.register(proc)
            handle.abort()
            # The join the abort exists to unwedge: must return
            # promptly, not after sleep's 60s.
            rc = proc.wait(timeout=10)
            assert rc != 0
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_abort_before_register_kills_at_registration(self):
        import subprocess as sp
        handle = _scanner_mod._CodeQLStageHandle()
        handle.abort()
        proc = sp.Popen(["sleep", "60"], start_new_session=True)
        try:
            handle.register(proc)  # abort raced the spawn
            rc = proc.wait(timeout=10)
            assert rc != 0
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_run_codeql_skips_spawn_after_abort(self, tmp_path):
        handle = _scanner_mod._CodeQLStageHandle()
        handle.abort()
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_proc:
            result = run_codeql(
                tmp_path, tmp_path / "out", ["python"],
                stage_handle=handle,
            )
        assert result == []
        mock_proc.assert_not_called()

    def test_run_codeql_reports_abort_not_agent_rc(self, tmp_path):
        # The agent was SIGKILLed by the abort path mid-communicate:
        # run_codeql must report the abort and return [], not warn
        # about a mysterious nonzero agent rc or glob half-written
        # SARIFs into the merge.
        handle = _scanner_mod._CodeQLStageHandle()
        (tmp_path / "out").mkdir()
        (tmp_path / "out" / "codeql_python.sarif").write_text("{}")

        fake = _fake_popen(returncode=-9)

        def _communicate(timeout=None):
            handle.abort()  # abort lands while communicate is blocked
            return ("", "")

        fake.communicate.side_effect = _communicate
        fake.poll.return_value = -9
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen",
                          return_value=fake):
            result = run_codeql(
                tmp_path, tmp_path / "out", ["python"],
                stage_handle=handle,
            )
        assert result == []


class TestJoinCodeQLStage:
    """The concurrent stage's JOIN carries the abort discipline too.

    The guarded semgrep region only covers exceptions raised BEFORE
    the join; a KeyboardInterrupt while the main thread is blocked in
    future.result() — the single longest wait of the run once semgrep
    finishes — is not an Exception, so it skipped the stage-isolation
    handler and wedged interpreter shutdown on the non-daemon
    worker's 3600s communicate.
    """

    @staticmethod
    def _future(target):
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            return pool.submit(target)
        finally:
            pool.shutdown(wait=False)

    def test_keyboard_interrupt_runs_abort_and_reraises(self):
        def _stage():
            raise KeyboardInterrupt

        aborted = []
        future = self._future(_stage)
        with pytest.raises(KeyboardInterrupt):
            _scanner_mod._join_codeql_stage(
                future, lambda: aborted.append(True),
            )
        assert aborted, (
            "abort not invoked on KeyboardInterrupt — the codeql "
            "agent's process group stays alive and the shutdown join "
            "wedges"
        )

    def test_stage_exception_demoted_no_abort(self, capsys):
        def _stage():
            raise RuntimeError("db build failed")

        aborted = []
        future = self._future(_stage)
        result = _scanner_mod._join_codeql_stage(
            future, lambda: aborted.append(True),
        )
        assert result == []
        assert not aborted
        assert "CodeQL stage failed" in capsys.readouterr().err

    def test_success_passes_sarifs_through(self):
        def _fail_abort():
            raise AssertionError("abort must not run on a successful join")

        future = self._future(lambda: ["a.sarif", "b.sarif"])
        result = _scanner_mod._join_codeql_stage(future, _fail_abort)
        assert result == ["a.sarif", "b.sarif"]

    def test_run_codeql_interrupt_mid_communicate_killpgs_and_reraises(
        self, tmp_path,
    ):
        # Sequential sibling: only TimeoutExpired killed the group, so
        # Ctrl-C during communicate orphaned the agent's whole process
        # tree (codeql grandchildren burning CPU and holding cache
        # locks).
        fake = _fake_popen(
            communicate_side_effect=KeyboardInterrupt(),
        )
        with mock_module_attribute(codeql, "shutil", "which", return_value="/usr/bin/codeql"), \
             mock_module_attribute(_scanner_mod, "subprocess", "Popen") as mock_popen, \
             mock_module_attribute(_scanner_mod, 'os', "killpg") as mock_killpg, \
             mock_module_attribute(_scanner_mod, 'os', "getpgid", return_value=12345):
            mock_popen.return_value = fake
            with pytest.raises(KeyboardInterrupt):
                run_codeql(tmp_path, tmp_path / "out", languages=None)

        assert mock_killpg.called, (
            "killpg not invoked on KeyboardInterrupt — codeql will orphan"
        )
        args = mock_killpg.call_args.args
        assert args[0] == 12345
        assert args[1] == _scanner_mod.signal.SIGKILL
        # Reap parity with the TimeoutExpired arm: without the wait,
        # the direct child lingers as a zombie for as long as an
        # interrupt-catching caller lives.
        assert fake.wait.called, (
            "child not reaped after killpg — zombie until the "
            "interrupt-catching caller exits"
        )


@pytest.mark.parametrize('merge_fails,removed_lines,failed_count,dropped,gaps,offline,stage_mode,metadata_state', [
    (merge_fails, removed_lines, 0, False, {}, False, False, None)
    for merge_fails in (False, True) for removed_lines in ([], [1], [1, 2])
] + [
    (True, [], 0, False, {}, False, 'merge-log-refused', None),
    (False, [], 0, False, {}, False, 'config-error', None),
    (False, [], 0, False, {}, False, 'config-write-refused', None),
    (False, [], 1, False, {}, False, False, None),
    (False, [], 2, False, {}, False, False, None),
    (False, [], 1, False, {}, True, False, None),
    (False, [], 0, True, {}, False, False, None),
    (False, [], 0, False, {'timeout': 1}, False, False, None),
    (False, [], 0, False, {}, False, 'empty', None),
    (False, [], 0, False, {}, False, 'multi', None),
    (False, [], 0, False, {}, False, 'configuration', None),
    (False, [], 0, False, {}, False, 'cocci', None),
    (False, [], 0, False, {}, False, False, 'missing'),
    (False, [], 0, False, {}, False, False, 'partial'),
    (False, [], 0, False, {}, False, False, 'incompatible'),
    (False, [], 0, False, {}, False, False, 'incompatible-path'),
])
def test_scan_metrics_follow_committed_report_or_raw_fallback(
    tmp_path, monkeypatch, capsys, merge_fails, removed_lines, failed_count, dropped, gaps, offline, stage_mode, metadata_state,
):
    import json
    import core.project.trust
    import core.run.pin
    import core.run.gaps
    import core.sandbox
    import core.sandbox.summary
    from core.sarif.parser import parse_sarif_findings

    repo = tmp_path / 'target'
    repo.mkdir()
    (repo / 'source.py').write_text('first() # nosemgrep\nsecond() # nosemgrep\n')
    out = tmp_path / 'out'
    out.mkdir()
    inputs = []
    for index in range(2):
        rows = [{'ruleId': 'rule-a', 'level': 'error', 'message': {'text': 'finding'},
                 'locations': [{'physicalLocation': {
                     'artifactLocation': {'uri': 'source.py'}, 'region': {'startLine': line},
                 }}]} for line in (1, 2)]
        path = out / f'pack-{index}.sarif'
        path.write_text(json.dumps({'version': '2.1.0', 'runs': [{
            'tool': {'driver': {'name': 'Semgrep', 'rules': [{'id': 'rule-a'}]}},
            'artifacts': [{'location': {'uri': f'pack-{index}.py'}}], 'results': rows,
        }]}))
        if metadata_state != 'missing':
            metadata = {'paths': {'scanned': []}, 'errors': [{
                'path': 'source.py', 'type': 'PartialParsing', 'level': 'warn', 'message': 'partial parse',
            }]} if metadata_state == 'partial' else {}
            if metadata_state in ('incompatible', 'incompatible-path'):
                notice = {'type': ['IncompatibleRule', {'rule_id': 'new-rule'}],
                          'level': 'info', 'message': 'Rule requires newer Semgrep'}
                if metadata_state == 'incompatible-path':
                    notice['path'] = 'rules/custom.yml'
                metadata = {'paths': {'scanned': [f'pack-{index}.py']}, 'errors': [notice]}
            path.with_suffix('.json').write_text(json.dumps(metadata))
        inputs.append(str(path))
    codeql_reports = []
    has_codeql_reports = stage_mode in ('multi', 'configuration')
    if has_codeql_reports:
        (repo / 'Other.java').write_text('class Other {}')
        for path in inputs:
            Path(path).with_suffix('.json').write_text(json.dumps({
                'paths': {'scanned': [str(repo / 'source.py')]},
            }))
        for language, file in [('python', 'source.py'), ('java', 'Other.java')]:
            path = out / f'codeql_{language}.sarif'
            path.write_text(json.dumps({'version': '2.1.0', 'runs': [{
                'originalUriBaseIds': {'ROOT': {'uri': repo.as_uri() + '/'}},
                'tool': {'driver': {'name': 'CodeQL', 'version': '2.16.0'},
                         'extensions': [{'name': language, 'version': '1',
                                         'rules': [{'id': f'{language}/example'}]}]},
                'artifacts': [{'location': {'uri': file, 'uriBaseId': 'ROOT'}}],
                'results': [],
                'invocations': [{'executionSuccessful': True, 'toolConfigurationNotifications': [
                    {'level': 'error'},
                ]}] if stage_mode == 'configuration' and language == 'python' else [],
            }]}))
            codeql_reports.append(str(path))
        import core.coverage.record as coverage
        original_load = coverage.load_json
        def forbid_sarif_reopen(path, **kwargs):
            assert Path(path).suffix != '.sarif', 'coverage must reuse decoded metrics inputs'
            return original_load(path, **kwargs)
        monkeypatch.setattr(coverage, 'load_json', forbid_sarif_reopen)
    # Prior coverage from disabled tools and nested runs must not enter this scan.
    stale_coverage = {'tool': 'coccinelle', 'files_examined': ['old.c'], 'rules_applied': 999}
    (out / 'coverage-coccinelle.json').write_text(json.dumps(stale_coverage))
    (out / 'checklist.json').write_text(json.dumps({'files': [{
        'path': 'old.c', 'lines': 5,
        'items': [{'name': 'old_fn', 'kind': 'function', 'line_start': 1, 'line_end': 5}],
    }]}))
    (out / 'scan').mkdir()
    (out / 'scan' / 'coverage-sca.json').write_text(json.dumps({
        'tool': 'sca', 'files_examined': ['old-dependency.json'],
    }))
    if stage_mode == 'merge-log-refused':
        (out / 'sarif_merge.stderr.log').mkdir()
    if stage_mode in ('config-error', 'config-write-refused'):
        from core.analysis import config_resolved_findings as config_stage

        monkeypatch.setattr(_scanner_mod.RaptorConfig, 'CONFIG_RESOLVED_ENABLED', True)
        def forbidden_parser(*args, **kwargs):
            pytest.fail('config failure controls must not parse Java')
        monkeypatch.setattr(config_stage, '_parser', forbidden_parser)
        monkeypatch.setattr(config_stage, 'scan_java_source', forbidden_parser)
        if stage_mode == 'config-error':
            def fail_config(*args, **kwargs):
                raise OSError('owned config stage refusal')
            monkeypatch.setattr(config_stage, 'run_config_resolved_stage', fail_config)
        else:
            (out / 'config-resolved.sarif').mkdir()
    # An earlier run's report must not become authoritative on merge failure.
    (out / 'combined.sarif').write_text(json.dumps({'version': '2.1.0', 'runs': []}))
    monkeypatch.setattr(core.sandbox, 'apply_cli_args', lambda *a, **kw: None)
    monkeypatch.setattr(core.project.trust, 'apply_project_sandbox_floor', lambda *a: None)
    monkeypatch.setattr(core.run.pin, 'bootstrap_process_pin', lambda *a: None)
    monkeypatch.setattr(core.sandbox.summary, 'set_active_run_dir', lambda *a: None)
    monkeypatch.setattr(core.sandbox.summary, 'summarize_and_write', lambda *a: None)
    monkeypatch.setattr(_scanner_mod, 'maybe_start_orphan_watchdog', lambda *a: None)
    monkeypatch.setattr(_scanner_mod, '_resolve_baseline_packs', lambda *a: [])
    monkeypatch.setattr(_scanner_mod, 'semgrep_scan_sequential',
                        lambda *a, **kw: (inputs, ['failed'] * failed_count))
    monkeypatch.setattr(_scanner_mod, '_dropped_registry_packs', ['uncached'] if dropped else [])
    monkeypatch.setattr(_scanner_mod.RaptorConfig, 'SEMGREP_OFFLINE', offline)
    monkeypatch.setattr(core.run.gaps, 'gap_summary', lambda *a: gaps)
    monkeypatch.setattr(_scanner_mod, 'run_codeql', lambda *a, **kw: codeql_reports)
    def current_cocci(repo_path, out_dir, *, on_coverage):
        on_coverage({'tool': 'coccinelle', 'files_examined': ['source.py'],
                     'rules_applied': ['current-rule']})
        return []
    monkeypatch.setattr(_scanner_mod, 'run_cocci', current_cocci)
    monkeypatch.setattr(_scanner_mod, '_finalize_scan_artifacts', lambda *a, **kw: None)
    if merge_fails:
        def fail_merge(*a):
            raise ValueError('planted merge failure')
        monkeypatch.setattr(_scanner_mod, 'merge_sarif', fail_merge)
    import core.analysis.sanitizer_cut_postpass as postpass
    monkeypatch.setattr(_scanner_mod.RaptorConfig, 'SANITIZER_CUT_POSTPASS_ENABLED', True)
    monkeypatch.setattr(_scanner_mod.RaptorConfig, 'SANITIZER_CUT_ENFORCE_ENABLED', True)
    monkeypatch.setattr(postpass, 'run_postpass', lambda *a, **kw: {
        'enforced_findings': [{'rule_id': 'rule-a', 'file': 'source.py', 'line': line}
                              for line in removed_lines],
    })
    monkeypatch.setattr(sys, 'argv', ['scanner', '--repo', str(repo), '--out', str(out),
                                     '--sequential', '--codeql' if stage_mode in ('multi', 'empty', 'configuration') else '--no-codeql',
                                     *([] if stage_mode == 'cocci' else ['--no-cocci']),
                                     '--no-source-wrappers',
                                     *([] if stage_mode in ('config-error', 'config-write-refused') else ['--no-config-resolved']),
                                     '--no-graduated-rules'])
    with pytest.raises(SystemExit) as exit_info:
        _scanner_mod.main()
    expected_exit = 4 if failed_count == 2 or (offline and failed_count) else 0
    assert exit_info.value.code == expected_exit
    metrics = json.loads((out / 'scan_metrics.json').read_text())
    status = 'error' if expected_exit else 'partial' if merge_fails or failed_count or dropped or gaps or stage_mode in ('empty', 'configuration', 'config-error', 'config-write-refused') or metadata_state else 'ok'
    assert metrics['execution_status'] == status
    stdout = capsys.readouterr().out
    result = json.loads(stdout[stdout.rfind('\n{') + 1:])
    assert result['status'] == result['metrics']['execution_status'] == status
    assert metrics['sarif_merge_failed'] is merge_fails
    assert metrics['analysis_gaps'] == gaps
    assert metrics['codeql_no_output'] is (stage_mode == 'empty')
    assert metrics['tool_execution_failures'] == ({'codeql': 1} if stage_mode == 'configuration' else
                                                  {'raptor-config-resolved': 1} if stage_mode in ('config-error', 'config-write-refused') else {})
    if stage_mode in ('config-error', 'config-write-refused'):
        assert metrics['config_resolved']['stage_error'] == 1
    assert metrics['semgrep_metadata_errors'] == (2 if metadata_state == 'missing' else 0)
    assert metrics['semgrep_partial_files'] == (1 if metadata_state == 'partial' else 0)
    assert metrics['semgrep_skipped_rules'] == (2 if metadata_state in ('incompatible', 'incompatible-path') else 0)
    expected_count = 4 if merge_fails else 2 - len(removed_lines)
    expected_suppressed = 0 if merge_fails else expected_count
    assert metrics['nosemgrep_suppressed_count'] == expected_suppressed
    assert metrics['total_files_scanned'] == (1 if stage_mode == 'cocci' else 2)
    assert set(metrics['tool_coverage']) == ({'semgrep', 'codeql'} if has_codeql_reports
                                             else {'coccinelle'} if stage_mode == 'cocci'
                                             else {'semgrep'} if metadata_state in ('incompatible', 'incompatible-path')
                                             else set())
    assert json.loads((out / 'coverage-coccinelle.json').read_text()) == stale_coverage
    if stage_mode == 'cocci':
        assert metrics['tool_coverage']['coccinelle'] == {'rules_applied': 1}
        assert '1 rule group' in stdout
        assert '999 rule groups' not in stdout
    else:
        assert 'Coccinelle' not in stdout
    assert 'Coverage (current scan — file-level)' in stdout
    assert 'Coverage (persistent store)' not in stdout
    assert 'old.c' not in stdout and 'old-dependency.json' not in stdout
    assert metrics['total_findings'] == expected_count
    expected_tools = {'semgrep': expected_count}
    if has_codeql_reports:
        expected_tools['codeql'] = 0
    if metadata_state in ('missing', 'incompatible', 'incompatible-path'):
        # Recovery loss is disclosed even when it contributes no findings.
        expected_tools['semgrep-python-sql'] = 0
        recovery = json.loads((out / 'python-sql.sarif').read_text())['runs'][0]
        assert recovery['results'] == []
        notifications = recovery['invocations'][0]['toolExecutionNotifications']
        assert notifications
        assert all(note['properties']['coverage_limitation'] for note in notifications)
        assert metrics['tool_coverage_limitations']['semgrep-python-sql'] > 0
    assert metrics['findings_by_tool'] == expected_tools
    if has_codeql_reports:
        record = json.loads((out / 'coverage-codeql.json').read_text())
        assert record['files_examined'] == ['Other.java', 'source.py']
        assert record['packs'] == ['java@1', 'python@1']
        assert record['rules_applied'] == ['java/example', 'python/example']
    assert metrics['findings_by_rule'] == ({'rule-a': expected_count} if expected_count else {})
    assert metrics['findings_by_severity']['error'] == expected_count
    if not merge_fails:
        assert len(parse_sarif_findings(out / 'combined.sarif')) == expected_count
    assert all(Path(path).exists() for path in inputs)


@pytest.mark.parametrize("returncode", [0, 1])
def test_codeql_excludes_unchanged_prior_reports(tmp_path, returncode):
    out = tmp_path / "out"
    out.mkdir()
    report = out / "codeql_python.sarif"
    report.write_text('{"version":"2.1.0","runs":[]}')
    before = report.read_bytes()
    with mock_module_attribute(codeql, "shutil", "which", return_value="/owned/codeql"), \
         mock_module_attribute(_scanner_mod, "subprocess", "Popen",
                               return_value=_fake_popen(returncode=returncode)) as spawn:
        paths = run_codeql(tmp_path, out)
        assert str(report) not in paths
        assert paths == ([str(out / "codeql_stage_diagnostics.sarif")] if returncode else [])
    spawn.assert_called_once()
    assert report.read_bytes() == before


@pytest.mark.parametrize("returncode", [0, 1])
def test_codeql_accepts_replaced_report_with_same_bytes(tmp_path, returncode):
    out = tmp_path / "out"
    out.mkdir()
    report = out / "codeql_python.sarif"
    content = '{"version":"2.1.0","runs":[]}'
    report.write_text(content)
    replacement = out / "replacement"
    replacement.write_text(content)
    def complete(**kwargs):
        replacement.replace(report)
        return "", ""
    with mock_module_attribute(codeql, "shutil", "which", return_value="/owned/codeql"), \
         mock_module_attribute(_scanner_mod, "subprocess", "Popen", return_value=_fake_popen(
             returncode=returncode, communicate_side_effect=complete)) as spawn:
        paths = run_codeql(tmp_path, out)
        assert str(report) in paths
        assert len(paths) == 1 + bool(returncode)
    spawn.assert_called_once()
    assert report.read_text() == content


@pytest.mark.parametrize("returncode", [0, 1])
def test_codeql_accepts_report_rewritten_in_place(tmp_path, returncode):
    out = tmp_path / "out"
    out.mkdir()
    report = out / "codeql_python.sarif"
    report.write_text("old")
    inode = report.stat().st_ino
    content = '{"version":"2.1.0","runs":[]}'
    def complete(**kwargs):
        report.write_text(content)
        return "", ""
    with mock_module_attribute(codeql, "shutil", "which", return_value="/owned/codeql"), \
         mock_module_attribute(_scanner_mod, "subprocess", "Popen", return_value=_fake_popen(
             returncode=returncode, communicate_side_effect=complete)) as spawn:
        paths = run_codeql(tmp_path, out)
        assert str(report) in paths
        assert len(paths) == 1 + bool(returncode)
    spawn.assert_called_once()
    assert report.stat().st_ino == inode
    assert report.read_text() == content


@pytest.mark.parametrize("with_findings", [False, True])
def test_codeql_agent_failure_retains_execution_diagnostic(tmp_path, with_findings):
    import json
    from core.sarif.parser import generate_scan_metrics, merge_sarif
    from core.reporting.scan_coverage import scan_execution_status

    out = tmp_path / "out"
    out.mkdir()
    report = out / "codeql_python.sarif"
    def complete(**kwargs):
        if with_findings:
            report.write_text(json.dumps({"version": "2.1.0", "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [{"ruleId": "owned/rule", "message": {"text": "owned finding"},
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "Owned.py"},
                                 "region": {"startLine": 1}}}]}],
            }]}))
        return "", "owned other-language failure"
    with mock_module_attribute(codeql, "shutil", "which", return_value="/owned/codeql"), \
         mock_module_attribute(_scanner_mod, "subprocess", "Popen", return_value=_fake_popen(
             returncode=1, communicate_side_effect=complete)) as spawn:
        paths = run_codeql(tmp_path, out)
    spawn.assert_called_once()
    metrics = generate_scan_metrics(paths)
    assert metrics["total_findings"] == int(with_findings)
    assert metrics["tool_execution_failures"] == {"codeql": 1}
    assert scan_execution_status(metrics) == "partial"
    diagnostic = out / "codeql_stage_diagnostics.sarif"
    assert str(diagnostic) in paths
    assert _scanner_mod._pack_provenance_from_sarif(diagnostic, out)["exit"] == 1
    combined = out / "combined.sarif"
    combined.write_text(json.dumps(merge_sarif(paths)))
    merged_metrics = generate_scan_metrics([str(combined)])
    assert merged_metrics["total_findings"] == int(with_findings)
    assert merged_metrics["tool_execution_failures"] == {"codeql": 1}
    assert scan_execution_status(merged_metrics) == "partial"
    if with_findings:
        assert str(report) in paths


def test_codeql_diagnostic_write_failure_retains_recovered_report(tmp_path, monkeypatch, caplog):
    out = tmp_path / "out"
    out.mkdir()
    report = out / "codeql_python.sarif"
    def complete(**kwargs):
        report.write_text('{"version":"2.1.0","runs":[]}')
        return "", "owned agent failure"
    def fail_write(*args, **kwargs):
        raise OSError("owned diagnostic write failure")
    monkeypatch.setattr(_scanner_mod, "_write_stage_report", fail_write)
    with mock_module_attribute(codeql, "shutil", "which", return_value="/owned/codeql"), \
         mock_module_attribute(_scanner_mod, "subprocess", "Popen", return_value=_fake_popen(
             returncode=1, communicate_side_effect=complete)):
        assert run_codeql(tmp_path, out) == [str(report)]
    assert "Could not persist CodeQL execution diagnostic" in caplog.text


@pytest.mark.parametrize("refused_suffix", ["stderr.log", "exit", "sarif", "scan-error"])
def test_semgrep_secondary_artifact_refusal_retains_current_sarif(tmp_path, monkeypatch, refused_suffix):
    import json

    payload = json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "owned"}]}]})
    if refused_suffix == "scan-error":
        (tmp_path / "semgrep_owned.sarif").write_text(payload)
    else:
        (tmp_path / f"semgrep_owned.{refused_suffix}").mkdir()
    monkeypatch.setattr(_scanner_mod.RaptorConfig, "SEMGREP_OFFLINE", True)
    monkeypatch.setattr(_scanner_mod.RaptorConfig, "get_semgrep_config", lambda value: value)
    monkeypatch.setattr(_scanner_mod.semgrep_pkg, "scope_isolation_available", lambda *a: True)
    monkeypatch.setattr(_scanner_mod.semgrep_pkg, "build_cmd", lambda *a, **kw: ["/owned/unexecuted"])
    def fake_run(*args, **kwargs):
        if refused_suffix == "scan-error":
            raise OSError("owned execution refusal")
        return 0, payload, "owned stderr"

    monkeypatch.setattr(_scanner_mod, "run", fake_run)
    with mock_module_attribute(_scanner_mod, "shutil", "which", return_value="/owned/unexecuted"):
        path, success = _scanner_mod.run_single_semgrep("owned", "owned.yaml", tmp_path, tmp_path, 1)
    assert success is False
    if refused_suffix == "sarif":
        assert Path(path).is_dir()
    elif refused_suffix == "scan-error":
        assert json.loads(Path(path).read_text()) == {"runs": []}
    else:
        assert Path(path).read_text() == payload
    if refused_suffix != "exit":
        assert (tmp_path / "semgrep_owned.exit").read_text() == "-1"


@pytest.mark.parametrize('stage', ['cocci', 'compiler-scan', 'expanded-semgrep'])
@pytest.mark.parametrize('nested', [False, True])
def test_c_family_probe_enumeration_refusal_is_visible(tmp_path, monkeypatch, capsys, stage, nested):
    import os

    denied_root = tmp_path / 'blocked' if nested else tmp_path
    denied_root.mkdir(exist_ok=True)
    (denied_root / 'owned.c').write_text('/* inert; never compiled */\n')
    original = os.scandir
    refused = []

    def scoped_scandir(path):
        if os.path.normpath(os.fspath(path)) == str(denied_root):
            refused.append(str(path))
            raise PermissionError('owned presence-probe refusal')
        return original(path)

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    assert _scanner_mod._skip_stage_without_c_cpp_source(stage, tmp_path) is True
    assert refused
    error = capsys.readouterr().err
    assert stage in error
    assert 'enumeration failed' in error
    assert 'coverage gap' in error


@pytest.mark.parametrize('case', ['found', 'negative', 'budget'])
def test_c_family_probe_preserves_admission_controls(tmp_path, capsys, case):
    if case == 'found':
        (tmp_path / 'owned.c').write_text('/* inert */\n')
    elif case == 'negative':
        (tmp_path / 'only.py').write_text('# inert\n')
    else:
        for index in range(201):
            (tmp_path / f'a{index:03}.txt').write_text('inert\n')
        (tmp_path / 'z.c').write_text('/* inert */\n')
    assert _scanner_mod._skip_stage_without_c_cpp_source('owned-stage', tmp_path) is (case != 'found')
    error = capsys.readouterr().err
    assert ('probe budget exhausted' in error) is (case == 'budget')
    assert 'enumeration failed' not in error


def test_c_family_probe_readable_sibling_still_admits_stage(tmp_path, monkeypatch, capsys):
    import os

    blocked = tmp_path / 'a_blocked'
    readable = tmp_path / 'z_readable'
    for directory in (blocked, readable):
        directory.mkdir()
        (directory / 'owned.c').write_text('/* inert; never compiled */\n')
    original = os.scandir
    refused = []

    def scoped_scandir(path):
        if os.path.normpath(os.fspath(path)) == str(blocked):
            refused.append(str(path))
            raise PermissionError('owned subtree refusal')
        return original(path)

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    assert _scanner_mod._skip_stage_without_c_cpp_source('cocci', tmp_path) is False
    assert refused
    assert 'enumeration failed' not in capsys.readouterr().err


@pytest.mark.parametrize('refuse_report', [False, True])
def test_config_stage_empty_repo_report_status(tmp_path, monkeypatch, refuse_report):
    from core.analysis import config_resolved_findings as stage

    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir()
    out.mkdir()
    if refuse_report:
        (out / 'config-resolved.sarif').mkdir()

    def forbidden_parser(*args, **kwargs):
        pytest.fail('empty repository must not invoke Java parsing')

    monkeypatch.setattr(stage, '_parser', forbidden_parser)
    monkeypatch.setattr(stage, 'scan_java_source', forbidden_parser)
    path, stats = stage.run_config_resolved_stage(repo, out)
    assert stats.get('stage_error', 0) == int(refuse_report)
    if refuse_report:
        assert path is None
    else:
        assert path is not None and path.is_file()


@pytest.mark.parametrize('nested', [False, True])
def test_config_stage_listing_refusal_reports_failure(tmp_path, monkeypatch, nested):
    import os
    from core.analysis import config_resolved_findings as stage

    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir()
    out.mkdir()
    denied_root = repo / 'blocked' if nested else repo
    denied_root.mkdir(exist_ok=True)
    (denied_root / 'Owned.java').write_text('// inert\n')
    original = os.scandir
    denied = []

    def scoped_scandir(path):
        if os.path.normpath(os.fspath(path)) == str(denied_root):
            denied.append(str(path))
            raise PermissionError('owned Java enumeration refusal')
        return original(path)

    def forbidden_parser(*args, **kwargs):
        pytest.fail('enumeration control must not parse Java')

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    monkeypatch.setattr(stage, '_parser', forbidden_parser)
    monkeypatch.setattr(stage, 'scan_java_source', forbidden_parser)
    path, stats = stage.run_config_resolved_stage(repo, out)
    assert denied
    assert path is None
    assert stats['stage_error'] == 1


@pytest.mark.parametrize('relative', [False, True])
def test_config_source_selection_preserves_glob_and_prunes_exclusions(tmp_path, monkeypatch, relative):
    import os
    from core.analysis import config_resolved_findings as stage

    repo = tmp_path / 'repo'
    repo.mkdir()
    for name in ('Owned.java', 'UPPER.JAVA', 'literal[1].java', 'skip.txt'):
        (repo / name).write_text('// inert\n')
    for name in ('directory.java', '.hidden', 'build', 'out'):
        directory = repo / name
        directory.mkdir()
        (directory / 'Child.java').write_text('// inert\n')
    if relative:
        monkeypatch.chdir(tmp_path)
        repo = Path('repo')
    expected = {p for p in repo.rglob('*.java')
                if not any(part in stage._SKIP_DIR_PARTS for part in p.relative_to(repo).parts)}
    excluded = {(repo / name).absolute() for name in ('build', 'out')}
    original = os.scandir

    def scoped_scandir(path):
        assert Path(path).absolute() not in excluded, 'excluded subtree was enumerated'
        return original(path)

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    assert set(stage._java_source_paths(repo)) == expected


@pytest.mark.parametrize('count', [0, 1, 2])
def test_config_source_cap_counts_only_eligible_entries(tmp_path, monkeypatch, count):
    from core.analysis import config_resolved_findings as stage

    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir()
    out.mkdir()
    for index in range(count):
        (repo / f'Owned{index}.java').write_text('// inert\n')
    (repo / 'build').mkdir()
    (repo / 'build' / 'Ignored.java').write_text('// inert\n')

    def forbidden_parser(*args, **kwargs):
        pytest.fail('selection controls must not parse Java')

    monkeypatch.setattr(stage, '_FILE_CAP', 1)
    monkeypatch.setattr(stage, '_parser', forbidden_parser)
    monkeypatch.setattr(stage, 'scan_java_source', forbidden_parser)
    path, stats = stage.run_config_resolved_stage(repo, out)
    assert path is not None
    assert bool(stats.get('file_cap_hit')) is (count > 1)
    assert stats.get('stage_error', 0) == 0


def test_config_index_discards_partial_listing_candidates(tmp_path, monkeypatch):
    import os
    from core.analysis import config_resolve_java as resolver

    visible = tmp_path / 'a_visible'
    blocked = tmp_path / 'z_blocked'
    deeper = blocked / 'deeper'
    visible.mkdir()
    deeper.mkdir(parents=True)
    for directory, value in ((visible, 'left'), (deeper, 'right')):
        (directory / 'owned.properties').write_text(f'owned_key={value}\n')
    original = os.scandir
    denied = []

    def scoped_scandir(path):
        if os.path.normpath(os.fspath(path)) == str(blocked):
            denied.append(str(path))
            raise PermissionError('owned nested property-index refusal')
        return original(path)

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    index = resolver._FileIndex(tmp_path)
    assert index.locate('owned.properties') == ([], False)
    assert denied
    calls = len(denied)
    assert index.locate('owned.properties') == ([], False)
    assert len(denied) == calls


@pytest.mark.parametrize('relative', [False, True])
def test_config_index_preserves_literal_basename_and_prunes(tmp_path, monkeypatch, relative):
    import os
    from glob import escape
    from core.analysis import config_resolve_java as resolver

    root = tmp_path / 'repo'
    root.mkdir()
    for dirname in ('a', 'b', 'build'):
        directory = root / dirname
        directory.mkdir()
        for name in ('owned[1].properties', 'owned1.properties'):
            (directory / name).write_text('owned_key=value\n')
    if relative:
        monkeypatch.chdir(tmp_path)
        root = Path('repo')
    expected = {p for p in root.rglob(escape('owned[1].properties'))
                if p.is_file() and not any(part in resolver._SKIP_DIR_PARTS for part in p.relative_to(root).parts)}
    excluded = (root / 'build').absolute()
    original = os.scandir

    def scoped_scandir(path):
        assert Path(path).absolute() != excluded, 'excluded property subtree was enumerated'
        return original(path)

    monkeypatch.setattr(os, 'scandir', scoped_scandir)
    matches, capped = resolver._FileIndex(root).locate('owned[1].properties')
    assert not capped
    assert set(matches) == expected


@pytest.mark.parametrize('count', [0, 1, 3])
def test_config_index_candidate_cap_still_refuses_excess(tmp_path, monkeypatch, count):
    from core.analysis import config_resolve_java as resolver

    for index in range(count):
        directory = tmp_path / f'branch{index}'
        directory.mkdir()
        (directory / 'owned.properties').write_text('owned_key=value\n')
    monkeypatch.setattr(resolver, '_CANDIDATE_CAP', 1)
    matches, capped = resolver._FileIndex(tmp_path).locate('owned.properties')
    assert len(matches) == min(count, 2)
    assert capped is (count > 1)


@pytest.mark.parametrize('failure', [PermissionError, FileNotFoundError, NotADirectoryError])
def test_config_index_distinguishes_unknown_metadata_from_absence(tmp_path, monkeypatch, failure):
    import os
    from core.analysis import config_resolve_java as resolver

    visible, refused = tmp_path / 'a', tmp_path / 'b'
    for directory in (visible, refused):
        directory.mkdir()
        (directory / 'owned.properties').write_text('owned_key=value\n')
    blocked = refused / 'owned.properties'
    original = os.stat
    calls = []

    def scoped_stat(path, *args, **kwargs):
        if os.path.normpath(os.fspath(path)) == str(blocked):
            calls.append(str(path))
            raise failure('owned candidate metadata refusal')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, 'stat', scoped_stat)
    matches, capped = resolver._FileIndex(tmp_path).locate('owned.properties')
    assert calls
    assert not capped
    assert matches == ([] if failure is PermissionError else [visible / 'owned.properties'])


def test_config_index_ignores_known_nonfile_candidate(tmp_path):
    from core.analysis import config_resolve_java as resolver

    visible, directory_candidate = tmp_path / 'a', tmp_path / 'b'
    visible.mkdir()
    directory_candidate.mkdir()
    (visible / 'owned.properties').write_text('owned_key=value\n')
    (directory_candidate / 'owned.properties').mkdir()
    assert resolver._FileIndex(tmp_path).locate('owned.properties') == ([visible / 'owned.properties'], False)
