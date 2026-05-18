"""Tests for packages/static-analysis/scanner.py."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock


# static-analysis has a hyphen — load via importlib
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location("static_analysis_scanner", _SCANNER_PATH)
_scanner_mod = importlib.util.module_from_spec(_spec)
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

    def test_returns_empty_when_codeql_not_installed(self, tmp_path):
        """No codeql CLI on PATH → bail before invoking agent."""
        with patch("shutil.which", return_value=None):
            result = run_codeql(tmp_path, tmp_path / "out", ["python"])
        assert result == []

    def test_creates_output_dir(self, tmp_path):
        """out_dir is created up-front (matches pre-unification
        contract — downstream consumers may glob for SARIFs even
        if the agent never wrote one)."""
        out_dir = tmp_path / "codeql_out"
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen(returncode=1, stderr="agent failed")
            run_codeql(tmp_path, out_dir, ["python"])
        assert out_dir.exists()

    def test_invokes_agent_subprocess_with_repo_and_out(self, tmp_path):
        """The unification contract: subprocess invocation of
        packages/codeql/agent.py with --repo and --out."""
        out_dir = tmp_path / "out"
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
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
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, tmp_path / "out", languages=None)

        kwargs = mock_proc.call_args.kwargs
        assert kwargs.get("start_new_session") is True, (
            f"Popen must be invoked with start_new_session=True for "
            f"orphan-process cleanup; saw {kwargs}"
        )

    def test_languages_forwarded_as_csv(self, tmp_path):
        """An explicit language list flows through as --languages a,b."""
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
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
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
            run_codeql(tmp_path, tmp_path / "out", languages=None)

        cmd = mock_proc.call_args.args[0]
        assert "--languages" not in cmd

    def test_build_command_forwarded(self, tmp_path):
        """build_command flows through as --build-command for the
        agent's CodeQL DB creation."""
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
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
        (out_dir / "codeql_cpp.sarif").write_text("{}")
        (out_dir / "codeql_python.sarif").write_text("{}")
        # And a non-matching file we must NOT pick up.
        (out_dir / "scan_metrics.json").write_text("{}")

        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen()
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
        (out_dir / "codeql_python.sarif").write_text("{}")

        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_proc:
            mock_proc.return_value = _fake_popen(
                returncode=1, stderr="cpp build failed",
            )
            result = run_codeql(tmp_path, out_dir, languages=["python", "cpp"])

        assert result == [str(out_dir / "codeql_python.sarif")]

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
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_popen, \
             patch.object(_scanner_mod.os, "killpg") as mock_killpg, \
             patch.object(_scanner_mod.os, "getpgid", return_value=12345):
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
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen") as mock_popen, \
             patch.object(_scanner_mod.os, "killpg",
                          side_effect=ProcessLookupError()), \
             patch.object(_scanner_mod.os, "getpgid", return_value=12345):
            mock_popen.return_value = fake
            # Should not raise; should still return [].
            result = run_codeql(tmp_path, tmp_path / "out", languages=None)
        assert result == []

    def test_subprocess_oserror_returns_empty(self, tmp_path):
        """Popen itself failing to spawn (ENOEXEC etc.) is caught."""
        with patch("shutil.which", return_value="/usr/bin/codeql"), \
             patch.object(_scanner_mod.subprocess, "Popen",
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

