"""Tests for packages/fuzzing/afl_runner.py."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.fuzzing.afl_runner import AFLRunner


class TestAFLRunnerStatsParsing(unittest.TestCase):

    def test_parse_afl_int_tolerates_stale_stats_formats(self):
        self.assertEqual(AFLRunner._parse_afl_int("56269"), 56269)
        self.assertEqual(AFLRunner._parse_afl_int("51000.00"), 51000)
        self.assertEqual(AFLRunner._parse_afl_int("100.00%"), 100)
        self.assertEqual(AFLRunner._parse_afl_int("N/A"), 0)

    def test_max_crash_execs_uses_afl_filename_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crashes = Path(tmpdir)
            (crashes / "README.txt").write_text("ignored")
            (crashes / "id:000000,sig:11,src:000000,time:284,execs:562,op:havoc,rep:3").write_bytes(b"a")
            (crashes / "id:000001,sig:06,src:000020,time:31644,execs:56269,op:havoc,rep:6").write_bytes(b"b")

            self.assertEqual(AFLRunner._max_crash_execs(crashes), 56269)

    def test_paths_found_falls_back_to_current_afl_corpus_fields(self):
        self.assertEqual(AFLRunner._afl_paths_found({"paths_found": "3"}), 3)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_found": "7"}), 7)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_count": "8"}), 8)

    def test_sanitizer_detection_ignores_afl_weak_asan_symbol(self):
        self.assertFalse(AFLRunner._has_runtime_sanitizer("__asan_region_is_poisoned", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__asan_init\n__asan_report_store1", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__ubsan_handle_add_overflow", "ubsan"))


# ---------------------------------------------------------------------------
# _create_default_corpus()
# ---------------------------------------------------------------------------

class TestCreateDefaultCorpus:
    """The default-corpus path must be anchored to ``self.output_dir``,
    NOT to the current working directory.

    Regression: previously ``Path("out/corpus_default")`` was CWD-relative,
    so running ``/fuzz`` from inside a target tree planted seed files in
    ``<target>/out/corpus_default/``.
    """

    def _make_runner(self, output_dir: Path) -> AFLRunner:
        # Bypass __init__ — we don't need a real binary or AFL on PATH
        # for this unit test. Only output_dir matters for the method
        # under test.
        runner = AFLRunner.__new__(AFLRunner)
        runner.output_dir = output_dir
        return runner

    def test_corpus_anchored_to_output_dir_not_cwd(self, tmp_path):
        # Two distinct directories: where the runner lives vs the
        # operator's CWD when they invoke /fuzz.
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()
        cwd = tmp_path / "operator_cwd"
        cwd.mkdir()

        # Plain os.chdir + try/finally instead of monkeypatch.chdir():
        # monkeypatch.chdir calls os.getcwd() to remember the original
        # cwd, which fails in CI when a prior test left cwd dangling.
        # Anchor restoration to Path(__file__) (always absolute, no
        # cwd dependency).
        safe_restore = Path(__file__).resolve().parent
        os.chdir(cwd)
        try:
            runner = self._make_runner(output_dir)
            result = runner._create_default_corpus()
        finally:
            os.chdir(safe_restore)

        # Seeds land under output_dir.
        expected = output_dir / "corpus_default"
        assert result == expected
        assert expected.is_dir()
        assert (expected / "manifest.json").is_file()
        assert (expected / "seed-0006-http-get").is_file()

        # CWD is NOT polluted.
        assert not (cwd / "out").exists()
        assert not (cwd / "out" / "corpus_default").exists()

    def test_corpus_returns_absolute_path_under_output_dir(self, tmp_path):
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()

        runner = self._make_runner(output_dir)
        result = runner._create_default_corpus()

        # Path must be absolute and a child of output_dir (not
        # interpreted relative to CWD by some downstream consumer).
        assert result.is_absolute()
        assert output_dir in result.parents or result.parent == output_dir

    def test_seeds_have_expected_content(self, tmp_path):
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()

        runner = self._make_runner(output_dir)
        corpus = runner._create_default_corpus()

        assert (corpus / "seed-0001-text-small").read_bytes() == b"test\n"
        assert b"GET /search" in (corpus / "seed-0006-http-get").read_bytes()
        assert b"STACK:" in (corpus / "seed-0014-command-prefixes").read_bytes()
        assert (corpus / "manifest.json").is_file()


# ---------------------------------------------------------------------------
# _merge_crash_files()
# ---------------------------------------------------------------------------

class TestMergeCrashFiles:
    """Crashes found by secondary instances must reach the returned
    crashes dir.

    Regression: run_fuzzing counted crashes across all parallel
    instances but returned only ``main/crashes``, so secondary-instance
    crashes were reported in the total yet never analysed.
    """

    def _make_runner(self, output_dir: Path) -> AFLRunner:
        runner = AFLRunner.__new__(AFLRunner)
        runner.output_dir = output_dir
        return runner

    def _plant_crash(self, output_dir: Path, instance: str, name: str,
                     payload: bytes) -> Path:
        crashes = output_dir / instance / "crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        f = crashes / name
        f.write_bytes(payload)
        return f

    def test_main_only_crashes_keep_main_dir(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")

        crash_files = runner._collect_all_crash_files()
        result = runner._merge_crash_files(crash_files)

        assert result == tmp_path / "main" / "crashes"
        assert not (tmp_path / "merged_crashes").exists()

    def test_secondary_crashes_are_merged(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")
        # Same AFL id in a secondary — must not collide away.
        self._plant_crash(tmp_path, "secondary1",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"b")
        self._plant_crash(tmp_path, "secondary1",
                          "id:000001,sig:06,src:000002,op:havoc,rep:2", b"c")

        crash_files = runner._collect_all_crash_files()
        assert len(crash_files) == 3

        result = runner._merge_crash_files(crash_files)
        assert result == tmp_path / "merged_crashes"

        merged = sorted(result.iterdir())
        assert len(merged) == 3
        # CrashCollector filters on the id: prefix — every merged file
        # must keep it.
        assert all(f.name.startswith("id:") for f in merged)
        assert sorted(f.read_bytes() for f in merged) == [b"a", b"b", b"c"]

    def test_no_crashes_returns_none_when_main_dir_missing(self, tmp_path):
        # Regression: all() over the empty crash list returned a
        # nonexistent main/crashes path; CrashCollector then raised
        # FileNotFoundError on a perfectly healthy zero-crash campaign.
        runner = self._make_runner(tmp_path)
        assert runner._merge_crash_files([]) is None

    def test_no_crashes_returns_main_dir_when_it_exists(self, tmp_path):
        runner = self._make_runner(tmp_path)
        main_crashes = tmp_path / "main" / "crashes"
        main_crashes.mkdir(parents=True)
        assert runner._merge_crash_files([]) == main_crashes

    def test_merge_is_idempotent(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")
        self._plant_crash(tmp_path, "secondary1",
                          "id:000001,sig:06,src:000002,op:havoc,rep:2", b"b")

        crash_files = runner._collect_all_crash_files()
        first = runner._merge_crash_files(crash_files)
        second = runner._merge_crash_files(crash_files)

        assert first == second
        assert len(list(second.iterdir())) == 2


# ---------------------------------------------------------------------------
# run_fuzzing() — sandboxed campaign
# ---------------------------------------------------------------------------

class TestSandboxedCampaign:
    """The afl-fuzz campaign executes the untrusted target, so it must
    run under ``core.sandbox.run`` (network deny, Landlock writes
    confined to the output dir) — never a plain ``subprocess.Popen``.

    Regression: the campaign historically ran unsandboxed while
    afl-showmap and the libFuzzer runner were already sandboxed.
    """

    @staticmethod
    def _make_runner(tmp_path: Path) -> AFLRunner:
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF-not-really")
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "seed0").write_bytes(b"A")

        runner = AFLRunner.__new__(AFLRunner)
        runner.binary = binary
        runner.corpus_dir = corpus
        runner.output_dir = tmp_path / "afl_out"
        runner.dict_path = None
        runner.input_mode = "stdin"
        runner.check_sanitizers = False
        runner.recompile_guide = False
        runner.use_showmap = False
        runner.extra_afl_flags = []
        runner.cmplog_binary = None
        runner.power_schedule = "fast"
        runner.use_laf_intel = True
        runner.deterministic = False
        runner.custom_mutator = None
        runner.seed_profile = "default"
        runner.telemetry = None
        runner.afl_fuzz = "/usr/bin/afl-fuzz"
        runner.sandbox_rootfs = None
        runner.binary_in_rootfs = None
        runner.cmplog_in_rootfs = None
        return runner

    @staticmethod
    def _instrumented(monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod

        def fake_trusted(cmd, **kwargs):
            return sp.CompletedProcess(cmd, 0, stdout="__AFL_SHM_ID", stderr="")

        monkeypatch.setattr(mod, "_run_trusted", fake_trusted)

    def test_campaign_routed_through_sandbox(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod

        self._instrumented(monkeypatch)
        calls = []

        def fake_sandbox_run(cmd, **kwargs):
            calls.append((list(cmd), dict(kwargs)))
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)

        def popen_tripwire(*args, **kwargs):
            raise AssertionError(
                "afl-fuzz must not run via plain subprocess.Popen"
            )

        monkeypatch.setattr(mod.subprocess, "Popen", popen_tripwire)

        runner = self._make_runner(tmp_path)
        crashes, _crashes_dir = runner.run_fuzzing(duration=0, parallel_jobs=2)

        assert crashes == 0
        assert len(calls) == 2
        for cmd, kwargs in calls:
            assert Path(cmd[0]).name == "afl-fuzz"
            assert kwargs["block_network"] is True
            assert kwargs["target"] == str(runner.output_dir)
            assert kwargs["output"] == str(runner.output_dir)
            assert str(runner.binary.parent) in kwargs["readable_paths"]
            assert str(runner.corpus_dir) in kwargs["readable_paths"]
            # afl-fuzz must be self-terminating: the sandbox call blocks.
            v_idx = cmd.index("-V")
            assert cmd[v_idx + 1] == "0"
            assert kwargs["timeout"] >= 300

        # Instances start on supervising threads, so the mock's append
        # order is nondeterministic — identify each command by its role
        # flag instead of by position.
        main_cmds = [c for c, _ in calls if "-M" in c]
        secondary_cmds = [c for c, _ in calls if "-S" in c]
        assert len(main_cmds) == 1 and "main" in main_cmds[0]
        assert len(secondary_cmds) == 1 and "secondary1" in secondary_cmds[0]

    def test_sandbox_setup_error_fails_loud(self, tmp_path, monkeypatch):
        from core.sandbox import SandboxSetupError
        from packages.fuzzing import afl_runner as mod

        self._instrumented(monkeypatch)

        def raising_run(cmd, **kwargs):
            raise SandboxSetupError("isolation unavailable")

        monkeypatch.setattr(mod, "_sandbox_run", raising_run)

        runner = self._make_runner(tmp_path)
        with pytest.raises(SandboxSetupError):
            runner.run_fuzzing(duration=0, parallel_jobs=1)


if __name__ == "__main__":
    unittest.main()


class TestRootfsMode:
    """S5.5 env-built campaigns: afl-fuzz and the target come from the
    exported AFL++ image rootfs; the sandbox call gains rootfs=."""

    @staticmethod
    def _rootfs(tmp_path: Path) -> Path:
        rootfs = tmp_path / "afl-rootfs"
        (rootfs / "usr/local/bin").mkdir(parents=True)
        (rootfs / "usr/local/bin/afl-fuzz").write_bytes(b"\x7fELF")
        (rootfs / "src").mkdir(parents=True)
        binary = rootfs / "src/app"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 12)
        binary.chmod(0o755)
        return rootfs

    def _make(self, tmp_path: Path, monkeypatch) -> AFLRunner:
        from packages.fuzzing import afl_runner as mod
        rootfs = self._rootfs(tmp_path)
        # Prove the host toolchain is NOT consulted in rootfs mode.
        monkeypatch.setattr(mod.shutil, "which",
                            lambda *_a, **_k: None)
        return AFLRunner(
            binary_path=rootfs / "src/app",
            corpus_dir=tmp_path / "corpus",
            output_dir=tmp_path / "out",
            sandbox_rootfs=rootfs,
            binary_in_rootfs="/src/app",
            afl_fuzz_path="/usr/local/bin/afl-fuzz",
        )

    def test_constructor_skips_host_afl(self, tmp_path, monkeypatch):
        (tmp_path / "corpus").mkdir()
        runner = self._make(tmp_path, monkeypatch)
        assert runner.afl_fuzz == "/usr/local/bin/afl-fuzz"
        assert runner.sandbox_rootfs == tmp_path / "afl-rootfs"

    def test_command_targets_in_rootfs_binary(self, tmp_path, monkeypatch):
        (tmp_path / "corpus").mkdir()
        runner = self._make(tmp_path, monkeypatch)
        cmd = runner._build_afl_command(
            instance_name="main", is_main=True, timeout_ms=1000)
        assert cmd[-1] == "/src/app"
        assert not any(str(tmp_path) in c for c in cmd[cmd.index("--"):])

    def test_missing_rootfs_dir_refuses(self, tmp_path):
        rootfs = self._rootfs(tmp_path)
        import pytest as _pytest
        with _pytest.raises(FileNotFoundError, match="rootfs"):
            AFLRunner(
                binary_path=rootfs / "src/app",
                corpus_dir=tmp_path,
                output_dir=tmp_path / "out",
                sandbox_rootfs=tmp_path / "nope",
                binary_in_rootfs="/src/app",
            )

    def test_instance_passes_rootfs_to_sandbox(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        seen = {}

        def fake_run(cmd, **kwargs):
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_run)
        inst = mod._SandboxedAFLInstance(
            name="main", cmd=["afl-fuzz"], env={},
            stdout_path=tmp_path / "o.log", stderr_path=tmp_path / "e.log",
            output_dir=tmp_path, readable_paths=[], timeout_s=5,
            rootfs=tmp_path / "afl-rootfs",
        )
        inst._run()
        assert seen["rootfs"] == str(tmp_path / "afl-rootfs")
        assert seen["block_network"] is True

    def test_host_mode_instance_omits_rootfs(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        seen = {}

        def fake_run(cmd, **kwargs):
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_run)
        inst = mod._SandboxedAFLInstance(
            name="main", cmd=["afl-fuzz"], env={},
            stdout_path=tmp_path / "o.log", stderr_path=tmp_path / "e.log",
            output_dir=tmp_path, readable_paths=[], timeout_s=5,
        )
        inst._run()
        assert "rootfs" not in seen


class TestRootfsCorpusStaging:
    """Rootfs-mode campaigns can only see the output bind — corpus and
    dictionary at arbitrary host paths must be staged under output_dir
    (regression: afl-fuzz died with 'Unable to open <corpus>')."""

    def _runner(self, tmp_path, monkeypatch, **kw):
        from packages.fuzzing import afl_runner as mod
        rootfs = TestRootfsMode._rootfs(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda *_a, **_k: None)
        return AFLRunner(
            binary_path=rootfs / "src/app",
            output_dir=tmp_path / "out",
            sandbox_rootfs=rootfs,
            binary_in_rootfs="/src/app",
            **kw,
        )

    def test_external_corpus_is_staged(self, tmp_path, monkeypatch):
        ext = tmp_path / "elsewhere" / "corpus"
        ext.mkdir(parents=True)
        (ext / "seed0").write_bytes(b"A")
        runner = self._runner(tmp_path, monkeypatch, corpus_dir=ext)
        assert runner.corpus_dir == tmp_path / "out" / "corpus-staged"
        assert (runner.corpus_dir / "seed0").read_bytes() == b"A"

    def test_corpus_already_under_output_not_copied(self, tmp_path,
                                                    monkeypatch):
        inside = tmp_path / "out" / "seeds"
        inside.mkdir(parents=True)
        (inside / "seed0").write_bytes(b"A")
        runner = self._runner(tmp_path, monkeypatch, corpus_dir=inside)
        assert runner.corpus_dir == inside

    def test_external_dict_is_staged(self, tmp_path, monkeypatch):
        ext = tmp_path / "elsewhere" / "corpus"
        ext.mkdir(parents=True)
        (ext / "seed0").write_bytes(b"A")
        d = tmp_path / "elsewhere" / "fuzz.dict"
        d.write_text('kw="RAP"\n')
        runner = self._runner(tmp_path, monkeypatch,
                              corpus_dir=ext, dict_path=d)
        assert runner.dict_path == (
            tmp_path / "out" / "dict-staged" / "fuzz.dict")
        assert runner.dict_path.read_text() == 'kw="RAP"\n'

    def test_host_mode_never_stages(self, tmp_path, monkeypatch):
        from packages.fuzzing import afl_runner as mod
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        ext = tmp_path / "elsewhere" / "corpus"
        ext.mkdir(parents=True)
        monkeypatch.setattr(mod.shutil, "which",
                            lambda *_a, **_k: "/usr/bin/afl-fuzz")
        monkeypatch.setattr(AFLRunner, "_validate_afl_command",
                            lambda self: None)
        runner = AFLRunner(binary_path=binary, corpus_dir=ext,
                           output_dir=tmp_path / "out")
        assert runner.corpus_dir == ext


class TestRootfsStagingHardening:
    """Adversarial-review fixes: hostile symlink seeds, stale staging
    dirs, and unsupported host-path params in rootfs mode."""

    def test_symlink_seeds_are_skipped_not_dereferenced(self, tmp_path,
                                                        monkeypatch):
        secret = tmp_path / "host-secret"
        secret.write_text("HOSTSECRET")
        ext = tmp_path / "corpus"
        ext.mkdir()
        (ext / "seed0").write_bytes(b"A")
        (ext / "evil").symlink_to(secret)
        runner = TestRootfsCorpusStaging()._runner(
            tmp_path, monkeypatch, corpus_dir=ext)
        staged = sorted(p.name for p in runner.corpus_dir.iterdir())
        assert staged == ["seed0"]

    def test_subdirectories_are_skipped(self, tmp_path, monkeypatch):
        ext = tmp_path / "corpus"
        (ext / "sub").mkdir(parents=True)
        (ext / "sub" / "nested").write_bytes(b"B")
        (ext / "seed0").write_bytes(b"A")
        runner = TestRootfsCorpusStaging()._runner(
            tmp_path, monkeypatch, corpus_dir=ext)
        assert [p.name for p in runner.corpus_dir.iterdir()] == ["seed0"]

    def test_stale_staged_seeds_cleared_between_runs(self, tmp_path,
                                                     monkeypatch):
        stale = tmp_path / "out" / "corpus-staged"
        stale.mkdir(parents=True)
        (stale / "old-seed").write_bytes(b"STALE")
        ext = tmp_path / "corpus"
        ext.mkdir()
        (ext / "seed0").write_bytes(b"A")
        runner = TestRootfsCorpusStaging()._runner(
            tmp_path, monkeypatch, corpus_dir=ext)
        assert [p.name for p in runner.corpus_dir.iterdir()] == ["seed0"]

    def test_ancestor_corpus_does_not_recurse(self, tmp_path, monkeypatch):
        # corpus dir is an ancestor of output_dir: the flat copy takes
        # only its top-level regular files, no self-recursion.
        ext = tmp_path  # output_dir tmp_path/out is inside it
        (ext / "seed0").write_bytes(b"A")
        runner = TestRootfsCorpusStaging()._runner(
            tmp_path, monkeypatch, corpus_dir=ext)
        names = [p.name for p in runner.corpus_dir.iterdir()]
        assert "seed0" in names
        assert "corpus-staged" not in names

    def test_cmplog_refused_in_rootfs_mode(self, tmp_path, monkeypatch):
        from packages.fuzzing import afl_runner as mod
        rootfs = TestRootfsMode._rootfs(tmp_path)
        cmplog = tmp_path / "cmplog-bin"
        cmplog.write_bytes(b"\x7fELF")
        monkeypatch.setattr(mod.shutil, "which", lambda *_a, **_k: None)
        import pytest as _pytest
        with _pytest.raises(ValueError, match="cmplog"):
            AFLRunner(
                binary_path=rootfs / "src/app",
                output_dir=tmp_path / "out",
                sandbox_rootfs=rootfs,
                binary_in_rootfs="/src/app",
                cmplog_binary=cmplog,
            )


class TestCampaignFailureVerdict:
    """A campaign whose every instance died without a clean exit and
    found nothing must not read as a clean no-findings result."""

    def _run(self, tmp_path, monkeypatch, returncode, plant_crash=False):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        TestSandboxedCampaign._instrumented(monkeypatch)

        def fake_sandbox_run(cmd, **kwargs):
            return sp.CompletedProcess(cmd, returncode,
                                       stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)
        runner = TestSandboxedCampaign._make_runner(tmp_path)
        runner.campaign_failed = False
        if plant_crash:
            crashes = runner.output_dir / "main" / "crashes"
            crashes.mkdir(parents=True)
            (crashes / "id:000000,sig:11").write_bytes(b"x")
        runner.run_fuzzing(duration=0, parallel_jobs=1)
        return runner

    def test_all_instances_dead_no_crashes_is_failed(self, tmp_path,
                                                     monkeypatch):
        runner = self._run(tmp_path, monkeypatch, returncode=1)
        assert runner.campaign_failed is True

    def test_clean_exit_is_not_failed(self, tmp_path, monkeypatch):
        runner = self._run(tmp_path, monkeypatch, returncode=0)
        assert runner.campaign_failed is False

    def test_crashes_override_dirty_exits(self, tmp_path, monkeypatch):
        runner = self._run(tmp_path, monkeypatch, returncode=1,
                           plant_crash=True)
        assert runner.campaign_failed is False


class TestCampaignEnvHygiene:
    def test_identity_vars_stripped_from_campaign_env(self, tmp_path,
                                                      monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        TestSandboxedCampaign._instrumented(monkeypatch)
        seen_envs = []

        def fake_sandbox_run(cmd, **kwargs):
            seen_envs.append(dict(kwargs.get("env") or {}))
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)
        for var in ("USER", "HOSTNAME", "LOGNAME", "PWD"):
            monkeypatch.setenv(var, "leak-probe")
        runner = TestSandboxedCampaign._make_runner(tmp_path)
        runner.campaign_failed = False
        runner.run_fuzzing(duration=0, parallel_jobs=1)
        assert seen_envs
        for env in seen_envs:
            for var in ("USER", "LOGNAME", "HOSTNAME", "PWD", "OLDPWD",
                        "RAPTOR_DIR", "RAPTOR_OUT_DIR",
                        "_RAPTOR_TRUSTED", "CLAUDECODE"):
                assert var not in env
            assert env.get("AFL_SKIP_CPUFREQ") == "1"


class TestCampaignEnvHygieneCompletion:
    """Follow-up leak closure: XDG_* dropped, HOME neutralised, PATH
    scrubbed of /home components, persona overlay on the campaign."""

    def _campaign_kwargs(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        TestSandboxedCampaign._instrumented(monkeypatch)
        seen = {}

        def fake_sandbox_run(cmd, **kwargs):
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)
        monkeypatch.setenv("XDG_CACHE_HOME", "/home/someone/.cache")
        monkeypatch.setenv("HOME", "/home/someone")
        monkeypatch.setenv(
            "PATH", "/home/someone/bin:/usr/local/bin:/usr/bin")
        runner = TestSandboxedCampaign._make_runner(tmp_path)
        runner.campaign_failed = False
        runner.run_fuzzing(duration=0, parallel_jobs=1)
        return seen

    def test_username_bearing_vars_neutralised(self, tmp_path, monkeypatch):
        kwargs = self._campaign_kwargs(tmp_path, monkeypatch)
        env = kwargs["env"]
        assert not any(k.startswith("XDG_") for k in env)
        assert env["HOME"] == "/tmp"
        if "PATH" in env:
            assert "/home/someone/bin" not in env["PATH"]
            assert "/usr/local/bin" in env["PATH"]

    def test_campaign_gets_persona_overlay(self, tmp_path, monkeypatch):
        kwargs = self._campaign_kwargs(tmp_path, monkeypatch)
        assert kwargs["sanitise_host_fingerprint"] is True


class TestScrubIdentityEnv:
    def test_scrub_function_contract(self, monkeypatch):
        from packages.fuzzing.afl_runner import scrub_identity_env
        env = {
            "USER": "someone", "LOGNAME": "someone", "HOSTNAME": "h",
            "PWD": "/home/someone/x", "XDG_CACHE_HOME": "/home/someone/.c",
            "HOME": "/home/someone", "TERM": "xterm",
            "PATH": "/home/someone/bin:/usr/bin",
            "RAPTOR_DIR": "/r", "CLAUDECODE": "1",
        }
        out = scrub_identity_env(env)
        assert out is env  # in-place contract
        assert "someone" not in " ".join(f"{k}={v}" for k, v in env.items())
        assert env["HOME"] == "/tmp"
        assert env["PATH"] == "/usr/bin"
        assert env["TERM"] == "xterm"  # non-identity vars untouched

    def test_showmap_env_is_scrubbed(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        seen = {}

        def fake_sandbox_run(cmd, **kwargs):
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)
        monkeypatch.setenv("USER", "someone")
        runner = TestSandboxedCampaign._make_runner(tmp_path)
        runner.use_showmap = True
        runner.run_showmap()
        assert seen, "showmap did not reach the sandbox"
        assert "USER" not in seen["env"]
        assert seen["env"]["HOME"] == "/tmp"


class TestNoAffinity:
    def test_campaign_skips_afl_core_binding(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing import afl_runner as mod
        TestSandboxedCampaign._instrumented(monkeypatch)
        seen = {}

        def fake_sandbox_run(cmd, **kwargs):
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        monkeypatch.setattr(mod, "_sandbox_run", fake_sandbox_run)
        runner = TestSandboxedCampaign._make_runner(tmp_path)
        runner.campaign_failed = False
        runner.run_fuzzing(duration=0, parallel_jobs=1)
        # Private PID namespaces make AFL's free-core scan blind, so
        # every parallel instance would bind the same lowest CPU; the
        # scheduler spreads them instead.
        assert seen["env"]["AFL_NO_AFFINITY"] == "1"


class TestCmplogInRootfs:
    def test_main_instance_gets_in_rootfs_cmplog(self, tmp_path,
                                                 monkeypatch):
        from packages.fuzzing import afl_runner as mod
        rootfs = TestRootfsMode._rootfs(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda *_a, **_k: None)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "seed0").write_bytes(b"A")
        runner = AFLRunner(
            binary_path=rootfs / "src/app",
            corpus_dir=corpus,
            output_dir=tmp_path / "out",
            sandbox_rootfs=rootfs,
            binary_in_rootfs="/src/app",
            cmplog_in_rootfs="/src-cmplog/app",
        )
        main_cmd = runner._build_afl_command(
            instance_name="main", is_main=True, timeout_ms=1000)
        sec_cmd = runner._build_afl_command(
            instance_name="secondary1", is_main=False, timeout_ms=1000)
        assert main_cmd[main_cmd.index("-c") + 1] == "/src-cmplog/app"
        assert "-c" not in sec_cmd

    def test_host_mode_ignores_cmplog_in_rootfs(self, tmp_path,
                                                monkeypatch):
        from packages.fuzzing import afl_runner as mod
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        (tmp_path / "corpus").mkdir()
        monkeypatch.setattr(mod.shutil, "which",
                            lambda *_a, **_k: "/usr/bin/afl-fuzz")
        monkeypatch.setattr(AFLRunner, "_validate_afl_command",
                            lambda self: None)
        runner = AFLRunner(binary_path=binary,
                           corpus_dir=tmp_path / "corpus",
                           output_dir=tmp_path / "out",
                           cmplog_in_rootfs="/src-cmplog/app")
        assert runner.cmplog_in_rootfs is None
