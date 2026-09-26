"""Tests for the cargo-fuzz runner's process contract.

Hermetic: both sandbox calls (build and campaign) are faked at the
same seam the libFuzzer runner tests use, emitting realistic
cargo/libFuzzer output and exit shapes; the toolchain probes are faked
at the runner module's seams. CI runners have no cargo-fuzz — the
live end-to-end lives in ``test_cargofuzz_live_e2e.py`` behind the
toolchain gate.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.cargofuzz_runner import (
    CARGO_FUZZ_INSTALL_HINT,
    CARGO_INSTALL_HINT,
    CargoFuzzResult,
    CargoFuzzRunner,
    crate_corpus_dir,
    nightly_toolchain_arg,
    parse_rust_panic,
)

# Realistic streams. The campaign side is libFuzzer's own grammar
# (cargo-fuzz targets ARE libFuzzer binaries); the panic block is
# rustc's >=1.73 two-line format with RUST_BACKTRACE=1 frames.
_CARGOFUZZ_CRASH_STDERR = """\
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 12345
#2\tINITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 40Mb
#100\tNEW    cov: 12 ft: 24 corp: 5/16b lim: 4 exec/s: 100 rss: 41Mb
thread '<unnamed>' panicked at fuzz_targets/fuzz_boom.rs:6:9:
boom: 7
stack backtrace:
   0: rust_begin_unwind
             at /rustc/abcdef/library/std/src/panicking.rs:645:5
   1: core::panicking::panic_fmt
   2: boomcrate::boom
==12345== ERROR: libFuzzer: deadly signal
SUMMARY: libFuzzer: deadly signal
Test unit written to ./crash-da39a3ee5e6b
stat::number_of_executed_units: 113
stat::average_exec_per_sec:     0
stat::peak_rss_mb:              40
"""

_BUILD_OK_STDERR = """\
   Compiling boomcrate v0.0.0
   Compiling boomcrate-fuzz v0.0.0
    Finished `release` profile [optimized] target(s) in 3.21s
"""


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _make_crate(tmp: Path, targets: tuple[str, ...] = ("fuzz_boom",)) -> Path:
    crate = tmp / "crate"
    (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname='boomcrate'\n")
    (crate / "fuzz" / "Cargo.toml").write_text(
        "[package]\nname='boomcrate-fuzz'\n"
        "[package.metadata]\ncargo-fuzz = true\n")
    for name in targets:
        (crate / "fuzz" / "fuzz_targets" / f"{name}.rs").write_text("// ft\n")
    return crate


def _toolchain_patches(nightly: str | None = "+nightly"):
    """Patch the runner's toolchain seams: cargo present, cargo-fuzz
    present, nightly availability as given, no host cargo/rustup home
    coupling."""
    return [
        patch("packages.fuzzing.cargofuzz_runner.cargo_executable",
              return_value="/usr/bin/cargo"),
        patch("packages.fuzzing.cargofuzz_runner.cargo_fuzz_available",
              return_value=True),
        patch("packages.fuzzing.cargofuzz_runner.nightly_toolchain_arg",
              return_value=nightly),
        patch("packages.fuzzing.cargofuzz_runner._resolve_cargo_home",
              return_value=None),
        patch("packages.fuzzing.cargofuzz_runner._resolve_rustup_home",
              return_value=None),
    ]


class TestCargoFuzzRunnerContract(unittest.TestCase):

    def _runner(self, tmp: Path, nightly: str | None = "+nightly",
                **kwargs) -> CargoFuzzRunner:
        crate = _make_crate(tmp)
        patches = _toolchain_patches(nightly)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return CargoFuzzRunner(
            crate,
            "fuzz_boom",
            output_dir=tmp / "out",
            max_total_time=1,
            **kwargs,
        )

    @staticmethod
    def _fake_sandbox(runner_box: dict, captured: dict,
                      build_rc: int = 0, run_rc: int = 77,
                      build_stderr: str = _BUILD_OK_STDERR,
                      make_binary: bool = True):
        """One side-effect serving both phases: the build call (cmd
        carries 'fuzz'/'build') plants the built binary; the campaign
        call writes libFuzzer streams."""

        def fake(cmd, **kwargs):
            class Result:
                pass

            if "build" in cmd and "fuzz" in cmd:
                captured["build_cmd"] = cmd
                captured["build_kwargs"] = kwargs
                kwargs["stderr"].write(build_stderr.encode())
                if make_binary and build_rc == 0:
                    runner = runner_box["runner"]
                    release = (runner.output_dir / "cargo-target"
                               / "x86_64-unknown-linux-gnu" / "release")
                    release.mkdir(parents=True, exist_ok=True)
                    binary = release / "fuzz_boom"
                    binary.write_bytes(b"\x7fELF fake")
                    binary.chmod(0o755)
                Result.returncode = build_rc
                return Result()

            captured["run_cmd"] = cmd
            captured["run_kwargs"] = kwargs
            kwargs["stderr"].write(_CARGOFUZZ_CRASH_STDERR.encode())
            # The artifact the fake campaign "wrote".
            runner = runner_box["runner"]
            (runner.crashes_dir / "crash-da39a3ee5e6b").write_bytes(b"\x00A")
            Result.returncode = run_rc
            return Result()

        return fake

    def test_build_then_run_under_sandbox_with_scrubbed_env(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(runner_box, captured)

        with patch.dict(os.environ, {"LD_PRELOAD": "evil.so"},
                        clear=False), \
             patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            result = runner.run()

        # Build phase: list-based cargo invocation, network denied,
        # offline cargo, artifacts routed into the run dir.
        build_cmd = captured["build_cmd"]
        self.assertEqual(
            build_cmd,
            ["/usr/bin/cargo", "+nightly", "fuzz", "build", "fuzz_boom",
             "--sanitizer", "address"],
        )
        bk = captured["build_kwargs"]
        self.assertTrue(bk["block_network"])
        self.assertTrue(bk["restrict_reads"])
        self.assertEqual(bk["cwd"], str(runner.crate_dir))
        self.assertIn(str(runner.fuzz_dir), bk["writable_paths"])
        benv = bk["env"]
        self.assertEqual(benv["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(benv["CARGO_TARGET_DIR"],
                         str(runner.output_dir / "cargo-target"))
        # ALWAYS the hermetic run-local cargo home — never the host
        # cache, never the scrubbed HOME fallback.
        self.assertEqual(benv["CARGO_HOME"],
                         str(runner.output_dir / "cargo-home"))
        self.assertNotIn("LD_PRELOAD", benv)

        # Campaign phase: the BUILT binary runs directly (cargo never
        # enters the campaign sandbox), libFuzzer flags via the parent.
        run_cmd = captured["run_cmd"]
        self.assertEqual(run_cmd[0], str(runner.harness))
        self.assertTrue(run_cmd[0].endswith("release/fuzz_boom"))
        self.assertEqual(run_cmd[1], str(runner.corpus_dir))
        self.assertIn("-max_total_time=1", run_cmd)
        rk = captured["run_kwargs"]
        self.assertTrue(rk["block_network"])
        renv = rk["env"]
        self.assertEqual(renv["RUST_BACKTRACE"], "1")
        self.assertNotIn("LD_PRELOAD", renv)
        for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD"):
            self.assertNotIn(ident, renv)
        self.assertEqual(renv.get("HOME"), "/tmp")

        # Stats parsed from the libFuzzer grammar — incl. the
        # -print_final_stats count a crash-terminated campaign prints.
        self.assertIsInstance(result, CargoFuzzResult)
        self.assertEqual(result.stats.total_executions, 113)
        self.assertEqual(result.stats.coverage_features, 24)

        # Crash artifact collected; the panic is the triage signal.
        self.assertEqual(len(result.crashes), 1)
        self.assertIsNotNone(result.rust_panic)
        self.assertEqual(result.rust_panic.message, "boom: 7")
        self.assertEqual(result.rust_panic.location,
                         "fuzz_targets/fuzz_boom.rs:6:9")
        self.assertEqual(result.rust_panic.frames,
                         ["rust_begin_unwind",
                          "core::panicking::panic_fmt",
                          "boomcrate::boom"])
        self.assertEqual(len(result.rust_panic.stack_key), 16)
        self.assertTrue(result.built_binary.endswith("release/fuzz_boom"))

        # Normalized crash records persisted beside the campaign.
        records_path = runner.output_dir / "cargofuzz-crashes.json"
        self.assertTrue(records_path.is_file())
        records = json.loads(records_path.read_text())
        self.assertEqual(records[0]["engine"], "cargo-fuzz")
        self.assertEqual(records[0]["fuzz_target"], "fuzz_boom")
        self.assertEqual(records[0]["panic_message"], "boom: 7")
        self.assertEqual(records[0]["stack_hash"],
                         result.rust_panic.stack_key)

        # A dirty exit WITH a finding is a normal crash-terminated
        # campaign, not a failed one.
        self.assertFalse(result.campaign_failed)

    def test_no_nightly_degrades_to_sanitizer_none(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(runner_box, captured, run_rc=0)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, nightly=None)
            runner_box["runner"] = runner
            self.assertEqual(runner.sanitizer, "none")
            runner.run()

        self.assertEqual(
            captured["build_cmd"],
            ["/usr/bin/cargo", "fuzz", "build", "fuzz_boom",
             "--sanitizer", "none"],
        )

    def test_build_failure_raises_with_bounded_hinted_excerpt(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        hostile = ("error: failed to download `libfuzzer-sys`\n"
                   "\x1b]0;owned\x07network access blocked\n" + "x" * 5000)
        fake = self._fake_sandbox(runner_box, captured, build_rc=101,
                                  build_stderr=hostile)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()

        message = str(ctx.exception)
        self.assertIn("cargo fuzz build failed", message)
        self.assertIn("cargo fetch", message)          # offline remedy
        self.assertNotIn("\x1b", message)              # controls stripped
        self.assertNotIn("\x07", message)
        self.assertLess(len(message), 2500)            # excerpt bounded
        self.assertIn("build-stderr.log", message)     # full log named

    def test_erofs_failure_names_the_lane_masking_and_remedy(self):
        # mount-ns lane: writable entries under the read-only target
        # bind are masked, so fuzz/Cargo.lock generation fails EROFS —
        # the hint must name the trusted-context remedy.
        from packages.fuzzing.cargofuzz_runner import _build_failure_hints
        hints = " ".join(_build_failure_hints(
            "error: failed to write /repo/fuzz/Cargo.lock: "
            "Read-only file system (os error 30)"))
        self.assertIn("cargo fetch", hints)
        self.assertIn("read-only target bind", hints)

    def test_build_success_without_binary_raises(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(runner_box, captured, make_binary=False)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()
        self.assertIn("no 'fuzz_boom' binary was found", str(ctx.exception))

    def test_build_timeout_raises_cleanly(self):
        tmp = _tmpdir(self)

        def fake(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, build_timeout=1)
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()
        self.assertIn("exceeded 1s", str(ctx.exception))

    def test_startup_death_is_campaign_failed(self):
        tmp = _tmpdir(self)
        runner_box: dict = {}

        def fake(cmd, **kwargs):
            class Result:
                pass

            if "build" in cmd and "fuzz" in cmd:
                runner = runner_box["runner"]
                release = (runner.output_dir / "cargo-target" / "release")
                release.mkdir(parents=True, exist_ok=True)
                binary = release / "fuzz_boom"
                binary.write_bytes(b"\x7fELF fake")
                binary.chmod(0o755)
                Result.returncode = 0
                return Result()
            kwargs["stderr"].write(b"error while loading shared libraries\n")
            Result.returncode = 127
            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            result = runner.run()

        self.assertTrue(result.campaign_failed)
        self.assertEqual(len(result.crashes), 0)
        self.assertIsNone(result.rust_panic)

    def test_planted_crash_sidecar_is_replaced_on_crashless_run(self):
        # The output dir is inside the campaign's sandbox write scope:
        # a hostile harness can plant cargofuzz-crashes.json mid-run.
        # A crash-less campaign must still overwrite it (and a planted
        # symlink must be unlinked, not written through).
        tmp = _tmpdir(self)
        runner_box: dict = {}

        def fake(cmd, **kwargs):
            class Result:
                pass

            runner = runner_box["runner"]
            if "build" in cmd and "fuzz" in cmd:
                release = (runner.output_dir / "cargo-target" / "release")
                release.mkdir(parents=True, exist_ok=True)
                binary = release / "fuzz_boom"
                binary.write_bytes(b"\x7fELF fake")
                binary.chmod(0o755)
                Result.returncode = 0
                return Result()
            outside = tmp / "outside.txt"
            outside.write_text("precious")
            (runner.output_dir / "cargofuzz-crashes.json").symlink_to(
                outside)
            kwargs["stderr"].write(
                b"#100\tDONE   cov: 1 ft: 1 corp: 1/1b exec/s: 50\n")
            Result.returncode = 0
            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            result = runner.run()

        self.assertEqual(len(result.crashes), 0)
        sidecar = runner.output_dir / "cargofuzz-crashes.json"
        self.assertFalse(sidecar.is_symlink())
        self.assertEqual(json.loads(sidecar.read_text()), [])
        self.assertEqual((tmp / "outside.txt").read_text(), "precious")


class TestHermeticCargoHome(unittest.TestCase):
    """The host cargo cache is never in the build's write scope; the
    build gets a run-local cargo home seeded by COPY from the host
    cache's index + .crate archives only."""

    def _runner_with_host_home(self, tmp: Path,
                               host_home: Path | None) -> CargoFuzzRunner:
        crate = _make_crate(tmp)
        patches = [
            patch("packages.fuzzing.cargofuzz_runner.cargo_executable",
                  return_value="/usr/bin/cargo"),
            patch("packages.fuzzing.cargofuzz_runner.cargo_fuzz_available",
                  return_value=True),
            patch("packages.fuzzing.cargofuzz_runner.nightly_toolchain_arg",
                  return_value="+nightly"),
            patch("packages.fuzzing.cargofuzz_runner._resolve_cargo_home",
                  return_value=host_home),
            patch("packages.fuzzing.cargofuzz_runner._resolve_rustup_home",
                  return_value=None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return CargoFuzzRunner(crate, "fuzz_boom", output_dir=tmp / "out")

    @staticmethod
    def _fake_host_cache(tmp: Path) -> Path:
        host = tmp / "host-cargo"
        (host / "registry" / "index" / "idx").mkdir(parents=True)
        (host / "registry" / "index" / "idx" / "dep1").write_text("{}\n")
        (host / "registry" / "cache" / "idx").mkdir(parents=True)
        (host / "registry" / "cache" / "idx" / "dep1-0.1.0.crate"
         ).write_bytes(b"crate-bytes")
        # The poisoning surface and ambient state that must NOT ride
        # into the run-local home:
        (host / "registry" / "src" / "idx" / "dep1-0.1.0" / "src"
         ).mkdir(parents=True)
        (host / "registry" / "src" / "idx" / "dep1-0.1.0" / "src"
         / "lib.rs").write_text("pub fn t() {}\n")
        (host / "bin").mkdir()
        (host / "bin" / "cargo-something").write_text("#!/bin/sh\n")
        (host / "config.toml").write_text("[net]\n")
        return host

    def test_writable_set_never_contains_the_host_cargo_home(self):
        # BOTH branches: host cache present and absent. This is the
        # standing regression for the shared-cache poisoning class —
        # an offline build extracts into registry/src and cargo never
        # re-verifies extracted sources, so ANY write grant on the
        # host cargo home hands a hostile build.rs durable poison.
        for with_host in (True, False):
            tmp = _tmpdir(self)
            host = self._fake_host_cache(tmp) if with_host else None
            runner = self._runner_with_host_home(tmp, host)
            writable = [Path(p) for p in runner._build_writable_paths()]
            if host is not None:
                resolved_host = host.resolve()
                for path in writable:
                    resolved = path.resolve()
                    self.assertNotEqual(resolved, resolved_host)
                    self.assertNotIn(resolved_host, resolved.parents)
            env = runner._build_env()
            self.assertEqual(env["CARGO_HOME"],
                             str(runner.output_dir / "cargo-home"))
            # The host cache stays READ-allowed (rustup/cargo shims).
            if host is not None:
                self.assertIn(str(host), runner._rust_tool_paths())

    def test_seed_copies_index_and_cache_only(self):
        tmp = _tmpdir(self)
        host = self._fake_host_cache(tmp)
        runner = self._runner_with_host_home(tmp, host)
        runner._seed_run_cargo_home()
        run_home = runner.output_dir / "cargo-home"
        self.assertTrue(
            (run_home / "registry" / "index" / "idx" / "dep1").is_file())
        self.assertEqual(
            (run_home / "registry" / "cache" / "idx"
             / "dep1-0.1.0.crate").read_bytes(),
            b"crate-bytes")
        # Never seeded: pre-extracted sources (the poisoning surface),
        # shims, config.
        self.assertFalse((run_home / "registry" / "src").exists())
        self.assertFalse((run_home / "bin").exists())
        self.assertFalse((run_home / "config.toml").exists())
        # Seeded files are real copies, not hardlinks to the host
        # cache: shared inodes would let an in-place write through.
        seeded = (run_home / "registry" / "cache" / "idx"
                  / "dep1-0.1.0.crate")
        original = (host / "registry" / "cache" / "idx"
                    / "dep1-0.1.0.crate")
        self.assertNotEqual(seeded.stat().st_ino, original.stat().st_ino)

    def test_seed_is_idempotent_and_tolerates_missing_host_cache(self):
        tmp = _tmpdir(self)
        host = self._fake_host_cache(tmp)
        runner = self._runner_with_host_home(tmp, host)
        runner._seed_run_cargo_home()
        marker = (runner.output_dir / "cargo-home" / "registry" / "index"
                  / "idx" / "dep1")
        marker.write_text("run-local edit\n")
        runner._seed_run_cargo_home()   # existing subtree kept
        self.assertEqual(marker.read_text(), "run-local edit\n")

        tmp2 = _tmpdir(self)
        runner2 = self._runner_with_host_home(tmp2, None)
        runner2._seed_run_cargo_home()  # no host cache: dir only
        self.assertTrue((runner2.output_dir / "cargo-home").is_dir())


class TestBuiltBinaryLocation(unittest.TestCase):
    """Run-dir artifacts always beat the crate's fuzz/target — a
    hostile build.rs can plant a future-mtime binary there during the
    build, so cross-root recency must never decide."""

    def _runner(self, tmp: Path) -> CargoFuzzRunner:
        crate = _make_crate(tmp)
        patches = _toolchain_patches()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return CargoFuzzRunner(crate, "fuzz_boom", output_dir=tmp / "out")

    @staticmethod
    def _plant(root: Path, mtime: float | None = None) -> Path:
        release = root / "release"
        release.mkdir(parents=True, exist_ok=True)
        binary = release / "fuzz_boom"
        binary.write_bytes(b"\x7fELF fake")
        binary.chmod(0o755)
        if mtime is not None:
            os.utime(binary, (mtime, mtime))
        return binary

    def test_run_dir_artifact_beats_future_mtime_fuzz_target_plant(self):
        import time as _time
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        fresh = self._plant(runner.output_dir / "cargo-target")
        self._plant(runner.fuzz_dir / "target",
                    mtime=_time.time() + 10_000)
        self.assertEqual(runner._locate_built_binary(), fresh.resolve())

    def test_fuzz_target_dir_is_fallback_only(self):
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        pinned = self._plant(runner.fuzz_dir / "target")
        self.assertEqual(runner._locate_built_binary(), pinned.resolve())

    def test_newest_wins_within_one_root(self):
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        root = runner.output_dir / "cargo-target"
        self._plant(root / "old-triple", mtime=1_000_000)
        newer = self._plant(root / "new-triple", mtime=2_000_000)
        # per-triple layout: <root>/<triple>/release/<name>
        self.assertEqual(runner._locate_built_binary(), newer.resolve())


class TestConstructionRefusals(unittest.TestCase):

    def test_missing_cargo_refuses_with_install_hint(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        with patch("packages.fuzzing.cargofuzz_runner.cargo_executable",
                   return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                CargoFuzzRunner(crate, "fuzz_boom", output_dir=tmp / "out")
        self.assertEqual(str(ctx.exception), CARGO_INSTALL_HINT)

    def test_missing_cargo_fuzz_refuses_with_install_hint(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        with patch("packages.fuzzing.cargofuzz_runner.cargo_executable",
                   return_value="/usr/bin/cargo"), \
             patch("packages.fuzzing.cargofuzz_runner.cargo_fuzz_available",
                   return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                CargoFuzzRunner(crate, "fuzz_boom", output_dir=tmp / "out")
        self.assertEqual(str(ctx.exception), CARGO_FUZZ_INSTALL_HINT)
        self.assertIn("cargo install cargo-fuzz", str(ctx.exception))

    def test_hostile_target_name_is_refused_before_any_use(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        for name in ("a; rm -rf /", "../escape", "a b", "", "x" * 65):
            with self.assertRaises(ValueError):
                CargoFuzzRunner(crate, name, output_dir=tmp / "out")

    def test_unknown_target_lists_available(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp, targets=("fuzz_a", "fuzz_b"))
        with self.assertRaises(ValueError) as ctx:
            CargoFuzzRunner(crate, "fuzz_c", output_dir=tmp / "out")
        self.assertIn("fuzz_a", str(ctx.exception))
        self.assertIn("fuzz_b", str(ctx.exception))

    def test_missing_layout_refuses_with_scaffold_hint(self):
        tmp = _tmpdir(self)
        crate = tmp / "crate"
        crate.mkdir()
        (crate / "Cargo.toml").write_text("[package]\n")
        with self.assertRaises(FileNotFoundError) as ctx:
            CargoFuzzRunner(crate, "fuzz_boom", output_dir=tmp / "out")
        self.assertIn("cargo fuzz init", str(ctx.exception))


class TestNightlyProbe(unittest.TestCase):

    @staticmethod
    def _completed(stdout: str):
        class Completed:
            pass

        Completed.stdout = stdout
        Completed.stderr = ""
        return Completed()

    def test_nightly_default_cargo_needs_no_prefix(self):
        with patch("packages.fuzzing.cargofuzz_runner.subprocess.run",
                   return_value=self._completed(
                       "cargo 1.99.0-nightly (abc 2026-01-01)")):
            self.assertEqual(nightly_toolchain_arg("/usr/bin/cargo"), "")

    def test_rustup_nightly_selects_plus_nightly(self):
        def fake_run(cmd, **kwargs):
            if cmd[0].endswith("cargo"):
                return self._completed("cargo 1.93.1 (stable)")
            return self._completed(
                "stable-x86_64-unknown-linux-gnu (default)\n"
                "nightly-x86_64-unknown-linux-gnu\n")

        with patch("packages.fuzzing.cargofuzz_runner.subprocess.run",
                   side_effect=fake_run), \
             patch("packages.fuzzing.cargofuzz_runner.shutil.which",
                   return_value="/usr/bin/rustup"):
            self.assertEqual(nightly_toolchain_arg("/usr/bin/cargo"),
                             "+nightly")

    def test_no_rustup_no_nightly(self):
        with patch("packages.fuzzing.cargofuzz_runner.subprocess.run",
                   return_value=self._completed("cargo 1.93.1 (stable)")), \
             patch("packages.fuzzing.cargofuzz_runner.shutil.which",
                   return_value=None):
            self.assertIsNone(nightly_toolchain_arg("/usr/bin/cargo"))

    def test_probe_failure_reads_as_no_nightly(self):
        with patch("packages.fuzzing.cargofuzz_runner.subprocess.run",
                   side_effect=OSError("boom")):
            self.assertIsNone(nightly_toolchain_arg("/usr/bin/cargo"))

    def test_no_cargo_is_no_nightly(self):
        with patch("packages.fuzzing.cargofuzz_runner.cargo_executable",
                   return_value=None):
            self.assertIsNone(nightly_toolchain_arg())


class TestCrateCorpusDir(unittest.TestCase):

    def test_non_empty_conventional_corpus_found(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        corpus = crate / "fuzz" / "corpus" / "fuzz_boom"
        corpus.mkdir(parents=True)
        (corpus / "seed").write_bytes(b"hi")
        self.assertEqual(crate_corpus_dir(crate, "fuzz_boom"), corpus)

    def test_empty_or_symlink_only_corpus_is_none(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        corpus = crate / "fuzz" / "corpus" / "fuzz_boom"
        corpus.mkdir(parents=True)
        self.assertIsNone(crate_corpus_dir(crate, "fuzz_boom"))
        outside = tmp / "outside"
        outside.write_bytes(b"x")
        (corpus / "link").symlink_to(outside)
        self.assertIsNone(crate_corpus_dir(crate, "fuzz_boom"))

    def test_hostile_target_name_is_none(self):
        tmp = _tmpdir(self)
        crate = _make_crate(tmp)
        self.assertIsNone(crate_corpus_dir(crate, "../../etc"))


class TestRustPanicParsing(unittest.TestCase):

    def test_no_panic_returns_none(self):
        self.assertIsNone(parse_rust_panic("#1 NEW cov: 1\n"))

    def test_new_two_line_format(self):
        panic = parse_rust_panic(
            "thread '<unnamed>' panicked at src/lib.rs:10:5:\n"
            "attempt to add with overflow\n"
        )
        self.assertEqual(panic.location, "src/lib.rs:10:5")
        self.assertEqual(panic.message, "attempt to add with overflow")
        self.assertEqual(panic.thread, "<unnamed>")
        self.assertEqual(len(panic.stack_key), 16)

    def test_old_single_line_format(self):
        panic = parse_rust_panic(
            "thread 'main' panicked at 'boom happened', src/lib.rs:3:9\n"
            "note: run with `RUST_BACKTRACE=1` for a backtrace\n"
        )
        self.assertEqual(panic.message, "boom happened")
        self.assertEqual(panic.location, "src/lib.rs:3:9")
        self.assertEqual(panic.thread, "main")

    def test_last_panic_wins(self):
        panic = parse_rust_panic(
            "thread 'main' panicked at 'first', a.rs:1:1\n"
            "thread 'main' panicked at 'second', b.rs:2:2\n"
        )
        self.assertEqual(panic.message, "second")
        self.assertEqual(panic.location, "b.rs:2:2")

    def test_terminal_controls_stripped_from_message(self):
        panic = parse_rust_panic(
            "thread 'main' panicked at src/lib.rs:1:1:\n"
            "\x1b]0;owned\x07bad\n"
        )
        self.assertNotIn("\x1b", panic.message)
        self.assertNotIn("\x07", panic.message)

    def test_garbage_after_marker_is_not_misattributed(self):
        self.assertIsNone(parse_rust_panic(
            "we panicked at the disco tonight\n"))

    def test_frame_count_is_bounded(self):
        frames = "".join(f"   {i}: some::frame_{i}\n" for i in range(500))
        panic = parse_rust_panic(
            "thread 'main' panicked at src/lib.rs:1:1:\n"
            "deep\n"
            "stack backtrace:\n" + frames
        )
        self.assertLessEqual(len(panic.frames), 40)

    def test_stack_key_depends_on_location_and_frames(self):
        one = parse_rust_panic(
            "thread 'main' panicked at 'x', a.rs:1:1\n"
            "stack backtrace:\n   0: f::g\n")
        two = parse_rust_panic(
            "thread 'main' panicked at 'x', a.rs:1:1\n"
            "stack backtrace:\n   0: f::h\n")
        self.assertNotEqual(one.stack_key, two.stack_key)

    def test_hostile_long_lines_are_bounded(self):
        # A crafted megabyte-long "panic" line must neither blow up
        # the parse nor land unbounded in the records.
        blob = ("thread 'main' panicked at src/lib.rs:1:1:\n"
                + "A" * (1024 * 1024) + "\n")
        panic = parse_rust_panic(blob)
        self.assertIsNotNone(panic)
        self.assertLessEqual(len(panic.message), 300)


if __name__ == "__main__":
    unittest.main()
