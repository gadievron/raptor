"""Tests for the jazzer runner's process contract.

Hermetic: both sandbox calls (build and campaign) are faked at the
same seam the libFuzzer runner tests use, emitting realistic
jazzer/libFuzzer output and exit shapes; the toolchain probes are
faked at the runner module's seams. CI runners have no jazzer — the
live end-to-end lives in ``test_jazzer_live_e2e.py`` behind the
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

from packages.fuzzing.jazzer_runner import (
    JAVA_INSTALL_HINT,
    JAZZER_INSTALL_HINT,
    JazzerResult,
    JazzerRunner,
    parse_java_exception,
    project_corpus_dir,
)

# Realistic streams. The campaign side is libFuzzer's own grammar
# (jazzer IS libFuzzer driving the JVM — its stderr uses the exact
# format); the finding report is jazzer's documented
# `== Java Exception:` block with JVM stack frames.
_JAZZER_CRASH_STDERR = """\
INFO: Instrumented com.example.ParserFuzz
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 12345
#2\tINITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 40Mb
#100\tNEW    cov: 12 ft: 24 corp: 5/16b lim: 4 exec/s: 100 rss: 41Mb

== Java Exception: java.lang.IllegalStateException: boom: 7
\tat com.example.ParserFuzz.parse(ParserFuzz.java:9)
\tat com.example.ParserFuzz.fuzzerTestOneInput(ParserFuzz.java:5)
\tat java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
DEDUP_TOKEN: 28cbcefbc6cf9d92
== libFuzzer crashing input ==
MS: 1 ChangeByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
Test unit written to ./crash-da39a3ee5e6b
stat::number_of_executed_units: 113
stat::average_exec_per_sec:     0
stat::peak_rss_mb:              40
"""

_BUILD_OK_STDERR = "note: build fine\n"

_HARNESS = """\
package com.example;
public class ParserFuzz {
    static void parse(byte[] d) {}
    public static void fuzzerTestOneInput(byte[] data) { parse(data); }
}
"""


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _make_project(tmp: Path, layout: str = "bare") -> Path:
    project = tmp / "proj"
    (project / "src").mkdir(parents=True)
    (project / "src" / "ParserFuzz.java").write_text(_HARNESS)
    if layout == "maven":
        (project / "pom.xml").write_text("<project/>\n")
    elif layout == "gradle":
        (project / "build.gradle").write_text("// build\n")
    return project


def _fake_jazzer(tmp: Path, with_jar: bool = False) -> Path:
    install = tmp / "jazzer-install"
    install.mkdir(parents=True, exist_ok=True)
    jazzer = install / "jazzer"
    jazzer.write_bytes(b"\x7fELF fake jazzer")
    jazzer.chmod(0o755)
    if with_jar:
        (install / "jazzer_standalone.jar").write_bytes(b"PK jar")
    return jazzer


def _fake_java_home(tmp: Path) -> Path:
    home = tmp / "jdk"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    (home / "bin" / "java").write_text("")
    return home


def _toolchain_patches(tmp: Path, *, with_jar: bool = False,
                       build_tool: str = "/usr/bin/javac",
                       host_m2: Path | None = None,
                       host_gradle: Path | None = None) -> list:
    jazzer = _fake_jazzer(tmp, with_jar=with_jar)
    java_home = _fake_java_home(tmp)
    return [
        patch("packages.fuzzing.jazzer_runner.jazzer_executable",
              return_value=str(jazzer)),
        patch("packages.fuzzing.jazzer_runner._resolve_java_home",
              return_value=java_home),
        patch("packages.fuzzing.jazzer_runner.build_tool_executable",
              return_value=build_tool),
        patch("packages.fuzzing.jazzer_runner._resolve_host_m2_repo",
              return_value=host_m2),
        patch("packages.fuzzing.jazzer_runner._resolve_host_gradle_home",
              return_value=host_gradle),
    ]


class _RunnerCase(unittest.TestCase):
    """Shared construction and sandbox fakes."""

    def _runner(self, tmp: Path, layout: str = "bare",
                **toolchain_kwargs) -> JazzerRunner:
        project = _make_project(tmp, layout)
        build_tool = {
            "bare": "/usr/bin/javac",
            "maven": "/usr/bin/mvn",
            "gradle": "/usr/bin/gradle",
        }[layout]
        toolchain_kwargs.setdefault("build_tool", build_tool)
        for p in _toolchain_patches(tmp, **toolchain_kwargs):
            p.start()
            self.addCleanup(p.stop)
        return JazzerRunner(
            project,
            "com.example.ParserFuzz",
            output_dir=tmp / "out",
            max_total_time=1,
        )

    @staticmethod
    def _fake_sandbox(runner_box: dict, captured: dict,
                      build_rc: int = 0, run_rc: int = 77,
                      build_stderr: str = _BUILD_OK_STDERR,
                      build_stdout: str = "",
                      run_stderr: str = _JAZZER_CRASH_STDERR,
                      classpath_entries=None,
                      make_classes: bool = True):
        """One side-effect serving both phases: the build call (argv[0]
        is the build tool) plants classes / the classpath file; the
        campaign call (argv[0] is jazzer) writes libFuzzer streams."""

        def fake(cmd, **kwargs):
            class Result:
                pass

            runner = runner_box["runner"]
            if cmd[0] != str(runner.harness):
                captured["build_cmd"] = cmd
                captured["build_kwargs"] = kwargs
                kwargs["stderr"].write(build_stderr.encode())
                kwargs["stdout"].write(build_stdout.encode())
                if build_rc == 0:
                    if make_classes and runner.build_tool == "maven":
                        (runner.project_dir / "target" / "classes"
                         ).mkdir(parents=True, exist_ok=True)
                    if classpath_entries is not None:
                        runner._classpath_file.write_text(
                            os.pathsep.join(classpath_entries))
                Result.returncode = build_rc
                return Result()

            captured["run_cmd"] = cmd
            captured["run_kwargs"] = kwargs
            kwargs["stderr"].write(run_stderr.encode())
            if "crash-da39a3ee5e6b" in run_stderr:
                (runner.crashes_dir / "crash-da39a3ee5e6b"
                 ).write_bytes(b"\x00A")
            Result.returncode = run_rc
            return Result()

        return fake


class TestJazzerRunnerContract(_RunnerCase):

    def test_build_then_run_under_sandbox_with_scrubbed_env(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(runner_box, captured)

        with patch.dict(os.environ, {"LD_PRELOAD": "evil.so"},
                        clear=False), \
             patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, layout="bare", with_jar=True)
            runner_box["runner"] = runner
            result = runner.run()

        # Build phase (bare lane): list-based javac invocation into
        # the run dir, network denied, no in-project write grant at
        # all, jazzer-adjacent api jar on the compile classpath.
        build_cmd = captured["build_cmd"]
        self.assertEqual(build_cmd[0], "/usr/bin/javac")
        self.assertEqual(build_cmd[1:3],
                         ["-d", str(runner.output_dir / "classes")])
        self.assertEqual(build_cmd[3], "-cp")
        self.assertIn("jazzer_standalone.jar", build_cmd[4])
        self.assertTrue(build_cmd[-1].endswith("ParserFuzz.java"))
        bk = captured["build_kwargs"]
        self.assertTrue(bk["block_network"])
        self.assertTrue(bk["restrict_reads"])
        self.assertEqual(bk["cwd"], str(runner.project_dir))
        self.assertEqual(bk["writable_paths"], [])
        benv = bk["env"]
        self.assertEqual(benv["JAVA_HOME"], str(runner._java_home))
        self.assertNotIn("LD_PRELOAD", benv)

        # Campaign phase: jazzer runs DIRECTLY (the build tool never
        # enters the campaign sandbox) with the vetted classpath and
        # the charset-vetted target class; libFuzzer flags via the
        # parent contract.
        run_cmd = captured["run_cmd"]
        self.assertEqual(run_cmd[0], str(runner.harness))
        self.assertTrue(run_cmd[0].endswith("jazzer"))
        self.assertEqual(run_cmd[1],
                         f"--cp={runner.output_dir / 'classes'}")
        self.assertEqual(run_cmd[2],
                         "--target_class=com.example.ParserFuzz")
        self.assertEqual(run_cmd[3], str(runner.corpus_dir))
        self.assertIn("-max_total_time=1", run_cmd)
        rk = captured["run_kwargs"]
        self.assertTrue(rk["block_network"])
        renv = rk["env"]
        self.assertEqual(renv["JAVA_HOME"], str(runner._java_home))
        self.assertNotIn("LD_PRELOAD", renv)
        for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD"):
            self.assertNotIn(ident, renv)
        self.assertEqual(renv.get("HOME"), "/tmp")

        # Stats parsed from the libFuzzer grammar — incl. the
        # -print_final_stats count a crash-terminated campaign prints.
        self.assertIsInstance(result, JazzerResult)
        self.assertEqual(result.stats.total_executions, 113)
        self.assertEqual(result.stats.coverage_features, 24)

        # Crash artifact collected; the exception is the triage signal.
        self.assertEqual(len(result.crashes), 1)
        self.assertIsNotNone(result.java_exception)
        self.assertEqual(result.java_exception.exception_type,
                         "java.lang.IllegalStateException")
        self.assertEqual(result.java_exception.message, "boom: 7")
        self.assertEqual(
            result.java_exception.frames,
            ["com.example.ParserFuzz.parse(ParserFuzz.java:9)",
             "com.example.ParserFuzz.fuzzerTestOneInput(ParserFuzz.java:5)",
             "java.base/jdk.internal.reflect.DirectMethodHandleAccessor"
             ".invoke(DirectMethodHandleAccessor.java:103)"])
        self.assertEqual(len(result.java_exception.stack_key), 16)
        self.assertEqual(result.build_tool, "bare")
        self.assertEqual(result.classpath,
                         [str(runner.output_dir / "classes")])

        # Normalized crash records persisted beside the campaign.
        records_path = runner.output_dir / "jazzer-crashes.json"
        self.assertTrue(records_path.is_file())
        records = json.loads(records_path.read_text())
        self.assertEqual(records[0]["engine"], "jazzer")
        self.assertEqual(records[0]["target_class"],
                         "com.example.ParserFuzz")
        self.assertEqual(records[0]["exception_type"],
                         "java.lang.IllegalStateException")
        self.assertEqual(records[0]["stack_hash"],
                         result.java_exception.stack_key)

        # A dirty exit WITH a finding is a normal crash-terminated
        # campaign, not a failed one.
        self.assertFalse(result.campaign_failed)

    def test_maven_lane_builds_offline_with_hermetic_repo(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}

        def entries():
            runner = runner_box["runner"]
            good = runner.output_dir / "m2-repo" / "dep.jar"
            good.parent.mkdir(parents=True, exist_ok=True)
            good.write_bytes(b"jar")
            return [str(good), "/etc/passwd",
                    str(runner.project_dir / "missing.jar")]

        def fake(cmd, **kwargs):
            class Result:
                pass

            runner = runner_box["runner"]
            if cmd[0] != str(runner.harness):
                captured["build_cmd"] = cmd
                captured["build_kwargs"] = kwargs
                kwargs["stderr"].write(b"maven ok\n")
                (runner.project_dir / "target" / "classes"
                 ).mkdir(parents=True, exist_ok=True)
                runner._classpath_file.write_text(
                    os.pathsep.join(entries()))
                Result.returncode = 0
                return Result()
            captured["run_cmd"] = cmd
            captured["run_kwargs"] = kwargs
            kwargs["stderr"].write(
                b"#100\tDONE   cov: 1 ft: 1 corp: 1/1b exec/s: 50\n")
            Result.returncode = 0
            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, layout="maven")
            runner_box["runner"] = runner
            result = runner.run()

        build_cmd = captured["build_cmd"]
        self.assertEqual(build_cmd[0], "/usr/bin/mvn")
        self.assertIn("-o", build_cmd)                # pinned offline
        self.assertIn("test-compile", build_cmd)
        self.assertIn("dependency:build-classpath", build_cmd)
        self.assertIn(f"-Dmaven.repo.local={runner.output_dir / 'm2-repo'}",
                      build_cmd)
        # In-project write grant: the pre-created module target/ dir
        # only — resolve()-contained, never the module dir itself.
        bk = captured["build_kwargs"]
        self.assertEqual(
            bk["writable_paths"],
            [str((runner.project_dir / "target").resolve())])

        # Classpath vetting: the run-local jar and the module classes
        # survive; the outside-roots and missing entries are dropped.
        self.assertEqual(result.build_tool, "maven")
        self.assertIn(str(runner.output_dir / "m2-repo" / "dep.jar"),
                      result.classpath)
        self.assertIn(str(runner.project_dir / "target" / "classes"),
                      result.classpath)
        self.assertNotIn("/etc/passwd", result.classpath)
        self.assertTrue(all("missing.jar" not in e
                            for e in result.classpath))
        cp_arg = captured["run_cmd"][1]
        self.assertNotIn("/etc/passwd", cp_arg)

    def test_gradle_lane_builds_offline_with_hermetic_home(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}

        def fake(cmd, **kwargs):
            class Result:
                pass

            runner = runner_box["runner"]
            if cmd[0] != str(runner.harness):
                captured["build_cmd"] = cmd
                captured["build_kwargs"] = kwargs
                kwargs["stderr"].write(b"gradle ok\n")
                classes = (runner.project_dir / "build" / "classes"
                           / "java" / "test")
                classes.mkdir(parents=True, exist_ok=True)
                # A hostile init/build script can append arbitrary
                # entries — the gradle lane must vet them too.
                runner._classpath_file.write_text(
                    str(classes) + os.pathsep + "/etc/passwd"
                    + os.pathsep)
                Result.returncode = 0
                return Result()
            captured["run_cmd"] = cmd
            kwargs["stderr"].write(
                b"#100\tDONE   cov: 1 ft: 1 corp: 1/1b exec/s: 50\n")
            Result.returncode = 0
            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, layout="gradle")
            runner_box["runner"] = runner
            result = runner.run()

        build_cmd = captured["build_cmd"]
        self.assertEqual(build_cmd[0], "/usr/bin/gradle")
        self.assertIn("--offline", build_cmd)
        self.assertIn("--no-daemon", build_cmd)
        init_script = (runner.output_dir
                       / "raptor-classpath-init.gradle")
        self.assertIn(str(init_script), build_cmd)
        self.assertTrue(init_script.is_file())
        self.assertIn("raptorFuzzClasspath", build_cmd)
        benv = captured["build_kwargs"]["env"]
        self.assertEqual(benv["GRADLE_USER_HOME"],
                         str(runner.output_dir / "gradle-home"))
        # In-project write grants: module build/ + root .gradle/ only.
        writable = captured["build_kwargs"]["writable_paths"]
        self.assertIn(str((runner.project_dir / "build").resolve()),
                      writable)
        self.assertIn(str((runner.project_dir / ".gradle").resolve()),
                      writable)
        self.assertEqual(result.build_tool, "gradle")
        # The hostile /etc/passwd entry from the build's classpath
        # file is vetted out on THIS lane too, never reaching --cp.
        self.assertEqual(
            result.classpath,
            [str(runner.project_dir / "build" / "classes" / "java"
                 / "test")])
        self.assertNotIn("/etc/passwd", captured["run_cmd"][1])

    def test_symlinked_module_output_dir_is_refused(self):
        # A repo-planted `target` symlink pointing outside the project
        # must not steer the build write grant at an arbitrary host
        # tree (the module dir comes from a symlink-free walk; its
        # output child needs its own check).
        tmp = _tmpdir(self)
        outside = tmp / "victim"
        outside.mkdir()
        runner = self._runner(tmp, layout="maven")
        (runner.project_dir / "target").symlink_to(outside)
        grants = runner._module_build_dirs(("pom.xml",), "target")
        self.assertEqual(grants, [])

    def test_maven_stdout_failure_raises_with_bounded_hinted_excerpt(self):
        # Real mvn reports its failures ([ERROR] lines, the
        # offline-mode diagnosis) on STDOUT with a quiet stderr — the
        # failure message must excerpt and hint-key on that stream
        # too, not stderr alone.
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        # mvn shape: INFO noise first, [ERROR] diagnosis at the END —
        # so the bounded tail excerpt must carry it.
        hostile = ("[INFO] Scanning for projects...\n"
                   + "x" * 5000 + "\n\x1b]0;owned\x07more text\n"
                   "[ERROR] Failed to execute goal: Could not resolve "
                   "dependencies: the artifact is not available in "
                   "offline mode\n"
                   "[ERROR] -> [Help 1]\n")
        fake = self._fake_sandbox(runner_box, captured, build_rc=1,
                                  build_stdout=hostile,
                                  build_stderr="")

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, layout="maven")
            runner_box["runner"] = runner
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()

        message = str(ctx.exception)
        self.assertIn("build failed", message)
        self.assertIn("trusted context", message)      # offline remedy
        self.assertIn("[ERROR]", message)              # excerpt shown
        self.assertNotIn("\x1b", message)              # controls stripped
        self.assertNotIn("\x07", message)
        self.assertLess(len(message), 2500)            # excerpt bounded
        self.assertIn("build-stderr.log", message)     # BOTH logs named
        self.assertIn("build-stdout.log", message)

    def test_stderr_failure_raises_with_bounded_hinted_excerpt(self):
        # Gradle and javac report on stderr — the other keyed tail.
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        hostile = ("* What went wrong:\nCould not resolve all "
                   "dependencies: no cached version available for "
                   "offline mode\n\x1b]0;owned\x07more text\n"
                   + "x" * 5000)
        fake = self._fake_sandbox(runner_box, captured, build_rc=1,
                                  build_stderr=hostile)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()

        message = str(ctx.exception)
        self.assertIn("build failed", message)
        self.assertIn("trusted context", message)      # offline remedy
        self.assertNotIn("\x1b", message)              # controls stripped
        self.assertNotIn("\x07", message)
        self.assertLess(len(message), 2500)            # excerpt bounded
        self.assertIn("build-stderr.log", message)     # BOTH logs named
        self.assertIn("build-stdout.log", message)

    def test_erofs_failure_names_the_lane_masking_and_remedy(self):
        # mount-ns lane: writable entries under the read-only target
        # bind are masked, so module target//build/ writes fail EROFS —
        # the hint must name the trusted-context remedy.
        from packages.fuzzing.jazzer_runner import _build_failure_hints
        hints = " ".join(_build_failure_hints(
            "Failed to create /repo/target/classes: "
            "Read-only file system (os error 30)"))
        self.assertIn("trusted context", hints)
        self.assertIn("read-only target bind", hints)

    def test_missing_jazzer_api_hint(self):
        from packages.fuzzing.jazzer_runner import _build_failure_hints
        hints = " ".join(_build_failure_hints(
            "error: package com.code_intelligence.jazzer.api does "
            "not exist"))
        self.assertIn("jazzer_standalone.jar", hints)

    def test_build_success_without_classpath_raises(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(runner_box, captured,
                                  classpath_entries=None,
                                  make_classes=False)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp, layout="maven")
            runner_box["runner"] = runner
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()
        self.assertIn("no usable classpath", str(ctx.exception))

    def test_build_timeout_raises_cleanly(self):
        tmp = _tmpdir(self)

        def fake(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner.build_timeout = 1
            with self.assertRaises(RuntimeError) as ctx:
                runner.run()
        self.assertIn("exceeded 1s", str(ctx.exception))

    def test_startup_death_is_campaign_failed(self):
        tmp = _tmpdir(self)
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(
            runner_box, captured, run_rc=127,
            run_stderr="Error: could not find or load main class\n")

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake):
            runner = self._runner(tmp)
            runner_box["runner"] = runner
            result = runner.run()

        self.assertTrue(result.campaign_failed)
        self.assertEqual(len(result.crashes), 0)
        self.assertIsNone(result.java_exception)

    def test_planted_crash_sidecar_is_replaced_on_crashless_run(self):
        # The output dir is inside the campaign's sandbox write scope:
        # a hostile harness can plant jazzer-crashes.json mid-run. A
        # crash-less campaign must still overwrite it (and a planted
        # symlink must be unlinked, not written through).
        tmp = _tmpdir(self)
        runner_box: dict = {}

        def fake(cmd, **kwargs):
            class Result:
                pass

            runner = runner_box["runner"]
            if cmd[0] != str(runner.harness):
                kwargs["stderr"].write(b"javac ok\n")
                Result.returncode = 0
                return Result()
            outside = tmp / "outside.txt"
            outside.write_text("precious")
            (runner.output_dir / "jazzer-crashes.json").symlink_to(
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
        sidecar = runner.output_dir / "jazzer-crashes.json"
        self.assertFalse(sidecar.is_symlink())
        self.assertEqual(json.loads(sidecar.read_text()), [])
        self.assertEqual((tmp / "outside.txt").read_text(), "precious")


class TestHermeticDependencyCaches(_RunnerCase):
    """The host ~/.m2/repository and ~/.gradle caches are never in the
    build's write scope; the build gets run-local copies seeded by
    COPY from the host caches."""

    @staticmethod
    def _fake_host_m2(tmp: Path) -> Path:
        host = tmp / "host-m2" / "repository"
        dep = host / "com" / "acme" / "dep" / "1.0"
        dep.mkdir(parents=True)
        (dep / "dep-1.0.jar").write_bytes(b"jar-bytes")
        (dep / "dep-1.0.pom").write_text("<project/>\n")
        return host

    @staticmethod
    def _fake_host_gradle(tmp: Path) -> Path:
        host = tmp / "host-gradle"
        modules = host / "caches" / "modules-2" / "files-2.1"
        modules.mkdir(parents=True)
        (modules / "dep-1.0.jar").write_bytes(b"jar-bytes")
        # Ambient state that must NOT ride into the run-local home —
        # gradle.properties in particular carries signing keys and
        # repository credentials at the home root:
        (host / "gradle.properties").write_text(
            "signing.secret=placeholder\n")
        (host / "daemon").mkdir()
        (host / "daemon" / "registry.bin").write_bytes(b"state")
        (host / "init.d").mkdir()
        (host / "init.d" / "evil.gradle").write_text("// init code\n")
        return host

    def _build_call(self, tmp: Path, layout: str,
                    **toolchain_kwargs) -> tuple[dict, list]:
        captured: dict = {}
        runner_box: dict = {}
        fake = self._fake_sandbox(
            runner_box, captured, run_rc=0,
            run_stderr="#1\tDONE   cov: 1 ft: 1 corp: 1/1b exec/s: 1\n",
            classpath_entries=["PLACEHOLDER"])

        def entries_fixed(cmd, **kwargs):
            result = fake(cmd, **kwargs)
            runner = runner_box["runner"]
            if "build_cmd" in captured and \
                    not captured.get("classpath_fixed"):
                good = runner.output_dir / "m2-repo" / "dep.jar"
                good.parent.mkdir(parents=True, exist_ok=True)
                good.write_bytes(b"jar")
                runner._classpath_file.write_text(str(good))
                captured["classpath_fixed"] = True
            return result

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=entries_fixed):
            runner = self._runner(tmp, layout=layout, **toolchain_kwargs)
            runner_box["runner"] = runner
            runner.run()
        return captured["build_kwargs"], captured["build_cmd"]

    def test_writable_set_never_contains_the_host_caches(self):
        # BOTH branches per lane: host cache present and absent. This
        # is the standing regression for the shared-cache poisoning
        # class — Maven plugins and build.gradle ARE code, and a write
        # grant on the shared host cache hands them durable poison
        # that the operator's own later, trusted builds consume.
        for layout in ("maven", "gradle"):
            for with_host in (True, False):
                tmp = _tmpdir(self)
                host_m2 = (self._fake_host_m2(tmp)
                           if with_host and layout == "maven" else None)
                host_gradle = (self._fake_host_gradle(tmp)
                               if with_host and layout == "gradle"
                               else None)
                kwargs, cmd = self._build_call(
                    tmp, layout, host_m2=host_m2,
                    host_gradle=host_gradle)
                for host in (host_m2, host_gradle):
                    if host is None:
                        continue
                    resolved_host = host.resolve()
                    for path in (Path(p).resolve()
                                 for p in kwargs["writable_paths"]):
                        self.assertNotEqual(path, resolved_host)
                        self.assertNotIn(resolved_host, path.parents)
                if layout == "maven":
                    self.assertTrue(any(
                        arg.startswith("-Dmaven.repo.local=")
                        and "m2-repo" in arg for arg in cmd), cmd)
                else:
                    self.assertIn("gradle-home",
                                  kwargs["env"]["GRADLE_USER_HOME"])

    def test_read_set_never_contains_the_host_cache_roots(self):
        # MUST-level credential boundary: the host ~/.gradle root
        # carries gradle.properties (signing keys, repository
        # credentials) and ~/.m2 sits beside settings.xml server
        # credentials. The seeding copy runs OUTSIDE the sandbox, so
        # the sandboxed (hostile) build needs NO read on the host
        # cache roots — neither the readable set nor the tool paths
        # may contain them.
        for layout in ("maven", "gradle"):
            tmp = _tmpdir(self)
            host_m2 = self._fake_host_m2(tmp)
            host_gradle = self._fake_host_gradle(tmp)
            kwargs, _cmd = self._build_call(
                tmp, layout, host_m2=host_m2, host_gradle=host_gradle)
            read_set = list(kwargs["readable_paths"]) + list(
                kwargs["tool_paths"] or [])
            for host in (host_m2, host_gradle):
                resolved_host = host.resolve()
                for path in (Path(p).resolve() for p in read_set):
                    exposes = (
                        path == resolved_host                # the root
                        or resolved_host in path.parents     # inside it
                        or path in resolved_host.parents     # an ancestor
                    )
                    self.assertFalse(
                        exposes,
                        f"{layout}: read grant {path} exposes the "
                        f"host cache root {resolved_host}")

    def test_m2_seed_is_a_real_copy(self):
        tmp = _tmpdir(self)
        host = self._fake_host_m2(tmp)
        runner = self._runner(tmp, layout="maven", host_m2=host)
        runner._seed_run_m2_repo()
        seeded = (runner.output_dir / "m2-repo" / "com" / "acme"
                  / "dep" / "1.0" / "dep-1.0.jar")
        original = host / "com" / "acme" / "dep" / "1.0" / "dep-1.0.jar"
        self.assertEqual(seeded.read_bytes(), b"jar-bytes")
        # Real copies, not hardlinks to the host cache: shared inodes
        # would let an in-place write through.
        self.assertNotEqual(seeded.stat().st_ino, original.stat().st_ino)

    def test_gradle_seed_copies_dependency_cache_only(self):
        tmp = _tmpdir(self)
        host = self._fake_host_gradle(tmp)
        runner = self._runner(tmp, layout="gradle", host_gradle=host)
        runner._seed_run_gradle_home()
        run_home = runner.output_dir / "gradle-home"
        seeded = (run_home / "caches" / "modules-2" / "files-2.1"
                  / "dep-1.0.jar")
        self.assertEqual(seeded.read_bytes(), b"jar-bytes")
        self.assertNotEqual(
            seeded.stat().st_ino,
            (host / "caches" / "modules-2" / "files-2.1"
             / "dep-1.0.jar").stat().st_ino)
        # Never seeded: credentials, daemon state, executable init
        # scripts.
        self.assertFalse((run_home / "gradle.properties").exists())
        self.assertFalse((run_home / "daemon").exists())
        self.assertFalse((run_home / "init.d").exists())

    def test_seed_is_idempotent_and_tolerates_missing_host_cache(self):
        tmp = _tmpdir(self)
        host = self._fake_host_m2(tmp)
        runner = self._runner(tmp, layout="maven", host_m2=host)
        runner._seed_run_m2_repo()
        marker = (runner.output_dir / "m2-repo" / "com" / "acme"
                  / "dep" / "1.0" / "dep-1.0.pom")
        marker.write_text("run-local edit\n")
        runner._seed_run_m2_repo()   # existing seed kept
        self.assertEqual(marker.read_text(), "run-local edit\n")

        tmp2 = _tmpdir(self)
        runner2 = self._runner(tmp2, layout="maven", host_m2=None)
        runner2._seed_run_m2_repo()  # no host cache: dir only
        self.assertTrue((runner2.output_dir / "m2-repo").is_dir())

        tmp3 = _tmpdir(self)
        runner3 = self._runner(tmp3, layout="gradle", host_gradle=None)
        runner3._seed_run_gradle_home()
        self.assertTrue((runner3.output_dir / "gradle-home").is_dir())


class TestClasspathVetting(_RunnerCase):
    """The classpath file is written by the sandboxed (hostile) build:
    its entries feed a jazzer argument and the campaign's readable
    world, so they are vetted to existing paths inside the project or
    the run dir, bounded in count and length."""

    def test_outside_missing_and_oversize_entries_are_dropped(self):
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        inside = runner.output_dir / "keep.jar"
        inside.parent.mkdir(parents=True, exist_ok=True)
        inside.write_bytes(b"jar")
        in_project = runner.project_dir / "src" / "ParserFuzz.java"
        entries = [
            str(inside),
            str(in_project),                    # inside the project
            str(inside),                        # duplicate — deduped
            "/etc/passwd",                      # exists, outside roots
            str(tmp / "nope.jar"),              # missing
            "x" * 5000,                         # oversize
            "",                                  # empty
        ]
        kept = runner._vet_classpath_entries(entries)
        self.assertEqual(kept, [str(inside), str(in_project.resolve())])

    def test_pathsep_in_a_real_contained_path_is_dropped(self):
        # Join-boundary injection: entries are joined with os.pathsep
        # into ONE --cp argument, so a repo shipping a real directory
        # chain like <project>/a:/etc passes exists+containment as one
        # path and then splits into TWO classpath entries — including
        # /etc — when the JVM parses the joined string.
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        smuggle_dir = runner.project_dir / f"a{os.pathsep}"
        (smuggle_dir / "etc").mkdir(parents=True)
        entry = smuggle_dir / "etc"
        self.assertTrue(entry.is_dir())     # real, contained — and
        self.assertEqual(                   # still dropped
            runner._vet_classpath_entries([str(entry)]), [])

    def test_symlink_escaping_the_roots_is_dropped(self):
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        outside = tmp / "victim.jar"
        outside.write_bytes(b"jar")
        link = runner.project_dir / "escape.jar"
        link.symlink_to(outside)
        self.assertEqual(runner._vet_classpath_entries([str(link)]), [])

    def test_entry_count_is_bounded(self):
        from packages.fuzzing import jazzer_runner as jr
        # Fixture scale guard, matching the enumeration-bound idiom.
        self.assertLessEqual(jr._MAX_CLASSPATH_ENTRIES, 2048)
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        jars = runner.output_dir / "jars"
        jars.mkdir(parents=True, exist_ok=True)
        entries = []
        for i in range(jr._MAX_CLASSPATH_ENTRIES + 5):
            jar = jars / f"j{i:04d}.jar"
            jar.write_bytes(b"j")
            entries.append(str(jar))
        kept = runner._vet_classpath_entries(entries)
        self.assertEqual(len(kept), jr._MAX_CLASSPATH_ENTRIES)


class TestBuildBounds(_RunnerCase):
    """The build phase's own enumerations over scanned-repo content
    are bounded: the bare-lane source list refuses past its cap, and
    the in-project write-grant list stops at the module cap."""

    def test_bare_source_list_refuses_past_the_cap(self):
        from packages.fuzzing import jazzer_runner as jr
        # Fixture scale guard, matching the enumeration-bound idiom.
        self.assertLessEqual(jr._MAX_BARE_SOURCES, 10000)
        tmp = _tmpdir(self)
        runner = self._runner(tmp)
        src = runner.project_dir / "src"
        for i in range(12):
            (src / f"D{i:03d}.java").write_text("class D {}\n")
        with patch.object(jr, "_MAX_BARE_SOURCES", 10):
            with self.assertRaises(RuntimeError) as ctx:
                runner._bare_java_sources()
        self.assertIn("Maven/Gradle", str(ctx.exception))

    def test_module_write_grants_stop_at_the_cap(self):
        from packages.fuzzing import jazzer_runner as jr
        tmp = _tmpdir(self)
        runner = self._runner(tmp, layout="maven")
        for i in range(6):
            module = runner.project_dir / f"mod{i}"
            module.mkdir()
            (module / "pom.xml").write_text("<project/>\n")
        with patch.object(jr, "_MAX_BUILD_MODULES", 3):
            grants = runner._module_build_dirs(("pom.xml",), "target")
        self.assertEqual(len(grants), 3)


class TestConstructionRefusals(unittest.TestCase):

    def _project(self, tmp: Path, layout: str = "bare") -> Path:
        return _make_project(tmp, layout)

    def test_missing_jazzer_refuses_with_install_hint(self):
        tmp = _tmpdir(self)
        project = self._project(tmp)
        with patch("packages.fuzzing.jazzer_runner.jazzer_executable",
                   return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                JazzerRunner(project, "com.example.ParserFuzz",
                             output_dir=tmp / "out")
        self.assertEqual(str(ctx.exception), JAZZER_INSTALL_HINT)

    def test_missing_java_refuses_with_install_hint(self):
        tmp = _tmpdir(self)
        project = self._project(tmp)
        jazzer = _fake_jazzer(tmp)
        with patch("packages.fuzzing.jazzer_runner.jazzer_executable",
                   return_value=str(jazzer)), \
             patch("packages.fuzzing.jazzer_runner._resolve_java_home",
                   return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                JazzerRunner(project, "com.example.ParserFuzz",
                             output_dir=tmp / "out")
        self.assertEqual(str(ctx.exception), JAVA_INSTALL_HINT)

    def test_missing_build_tool_refuses_with_layout_hint(self):
        tmp = _tmpdir(self)
        project = self._project(tmp, layout="maven")
        jazzer = _fake_jazzer(tmp)
        with patch("packages.fuzzing.jazzer_runner.jazzer_executable",
                   return_value=str(jazzer)), \
             patch("packages.fuzzing.jazzer_runner._resolve_java_home",
                   return_value=_fake_java_home(tmp)), \
             patch("packages.fuzzing.jazzer_runner"
                   ".build_tool_executable", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                JazzerRunner(project, "com.example.ParserFuzz",
                             output_dir=tmp / "out")
        self.assertIn("mvn", str(ctx.exception))
        self.assertIn("mvnw wrapper is never executed",
                      str(ctx.exception))

    def test_hostile_class_name_is_refused_before_any_use(self):
        tmp = _tmpdir(self)
        project = self._project(tmp)
        with self.assertRaises(ValueError) as ctx:
            JazzerRunner(project, "com.example;rm -rf /",
                         output_dir=tmp / "out")
        self.assertIn("dotted Java identifier", str(ctx.exception))

    def test_unknown_target_lists_available(self):
        tmp = _tmpdir(self)
        project = self._project(tmp)
        with self.assertRaises(ValueError) as ctx:
            JazzerRunner(project, "com.example.Nope",
                         output_dir=tmp / "out")
        self.assertIn("com.example.ParserFuzz", str(ctx.exception))

    def test_no_targets_refuses_with_harness_shape(self):
        tmp = _tmpdir(self)
        project = tmp / "empty"
        (project / "src").mkdir(parents=True)
        (project / "src" / "Plain.java").write_text("class Plain {}\n")
        with self.assertRaises(FileNotFoundError) as ctx:
            JazzerRunner(project, "Plain", output_dir=tmp / "out")
        self.assertIn("fuzzerTestOneInput", str(ctx.exception))

    def test_bare_kotlin_harness_is_refused(self):
        tmp = _tmpdir(self)
        project = tmp / "ktproj"
        project.mkdir()
        (project / "KFuzz.kt").write_text(
            "object KFuzz {\n"
            "  @JvmStatic fun fuzzerTestOneInput(d: ByteArray) {}\n"
            "}\n")
        jazzer = _fake_jazzer(tmp)
        with patch("packages.fuzzing.jazzer_runner.jazzer_executable",
                   return_value=str(jazzer)), \
             patch("packages.fuzzing.jazzer_runner._resolve_java_home",
                   return_value=_fake_java_home(tmp)), \
             patch("packages.fuzzing.jazzer_runner"
                   ".build_tool_executable",
                   return_value="/usr/bin/javac"):
            with self.assertRaises(RuntimeError) as ctx:
                JazzerRunner(project, "KFuzz", output_dir=tmp / "out")
        self.assertIn("Kotlin", str(ctx.exception))


class TestJavaExceptionParsing(unittest.TestCase):

    def test_no_report_returns_none(self):
        self.assertIsNone(parse_java_exception("#1 DONE cov: 1\n"))

    def test_exception_with_message_and_frames(self):
        info = parse_java_exception(_JAZZER_CRASH_STDERR)
        self.assertEqual(info.exception_type,
                         "java.lang.IllegalStateException")
        self.assertEqual(info.message, "boom: 7")
        self.assertEqual(len(info.frames), 3)
        self.assertEqual(len(info.stack_key), 16)

    def test_exception_without_message(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.ArrayIndexOutOfBoundsException\n"
            "\tat com.x.Y.z(Y.java:1)\n")
        self.assertEqual(info.exception_type,
                         "java.lang.ArrayIndexOutOfBoundsException")
        self.assertEqual(info.message, "")
        self.assertEqual(info.frames, ["com.x.Y.z(Y.java:1)"])

    def test_security_issue_reports_parse_as_exceptions(self):
        info = parse_java_exception(
            "== Java Exception: com.code_intelligence.jazzer.api."
            "FuzzerSecurityIssueHigh: OS Command Injection\n"
            "\tat java.base/java.lang.ProcessBuilder.start"
            "(ProcessBuilder.java:1170)\n")
        self.assertEqual(
            info.exception_type,
            "com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh")
        self.assertEqual(info.message, "OS Command Injection")

    def test_native_method_and_unknown_source_frames(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: x\n"
            "\tat com.x.Y.n(Native Method)\n"
            "\tat com.x.Y.u(Unknown Source)\n")
        self.assertEqual(info.frames, ["com.x.Y.n(Native Method)",
                                       "com.x.Y.u(Unknown Source)"])

    def test_last_report_wins(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: first\n"
            "\tat com.x.A.a(A.java:1)\n"
            "later output\n"
            "== Java Exception: java.lang.IllegalStateException: last\n"
            "\tat com.x.B.b(B.java:2)\n")
        self.assertEqual(info.exception_type,
                         "java.lang.IllegalStateException")
        self.assertEqual(info.frames, ["com.x.B.b(B.java:2)"])

    def test_caused_by_chain_stays_out_of_the_key(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: wrap\n"
            "\tat com.x.A.a(A.java:1)\n"
            "Caused by: java.io.IOException: inner\n"
            "\tat com.x.C.c(C.java:3)\n")
        self.assertEqual(info.frames, ["com.x.A.a(A.java:1)"])

    def test_zero_frame_wrapper_keeps_the_cause_out_of_the_key(self):
        # A stack-suppressed wrapper prints ZERO top frames before the
        # Caused by: block — the cause's frames must not attribute to
        # the wrapper and contaminate the dedup key.
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: wrap\n"
            "Caused by: java.io.IOException: inner\n"
            "\tat com.x.C.c(C.java:3)\n")
        self.assertEqual(info.exception_type,
                         "java.lang.RuntimeException")
        self.assertEqual(info.frames, [])
        bare = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: wrap\n")
        self.assertEqual(info.stack_key, bare.stack_key)

    def test_suppressed_block_stays_out_of_the_key(self):
        # Zero-frame top exception again — with frames present, the
        # frames-started gate already stops at the Suppressed: line;
        # only the zero-frame case exercises the explicit terminator.
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: x\n"
            "\tSuppressed: java.io.IOException: closing\n"
            "\tat com.x.S.s(S.java:9)\n")
        self.assertEqual(info.frames, [])
        with_frames = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: x\n"
            "\tat com.x.A.a(A.java:1)\n"
            "\tSuppressed: java.io.IOException: closing\n"
            "\tat com.x.S.s(S.java:9)\n")
        self.assertEqual(with_frames.frames, ["com.x.A.a(A.java:1)"])

    def test_terminal_controls_stripped_from_message(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: "
            "\x1b]0;owned\x07boom\n")
        self.assertNotIn("\x1b", info.message)
        self.assertNotIn("\x07", info.message)
        self.assertIn("boom", info.message)

    def test_garbage_after_marker_is_not_misattributed(self):
        self.assertIsNone(parse_java_exception(
            "== Java Exception: not a class name!! $( rm -rf )\n"))

    def test_frame_count_is_bounded(self):
        flood = ("== Java Exception: java.lang.RuntimeException: x\n"
                 + "".join(f"\tat com.x.F.f{i}(F.java:{i})\n"
                           for i in range(500)))
        info = parse_java_exception(flood)
        self.assertEqual(len(info.frames), 40)

    def test_hostile_long_lines_are_bounded(self):
        info = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: "
            + "m" * 100_000 + "\n")
        self.assertIsNotNone(info)
        self.assertLessEqual(len(info.message), 300)

    def test_stack_key_depends_on_type_and_frames(self):
        a = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: x\n"
            "\tat com.x.A.a(A.java:1)\n")
        b = parse_java_exception(
            "== Java Exception: java.lang.IllegalStateException: x\n"
            "\tat com.x.A.a(A.java:1)\n")
        c = parse_java_exception(
            "== Java Exception: java.lang.RuntimeException: x\n"
            "\tat com.x.B.b(B.java:2)\n")
        self.assertNotEqual(a.stack_key, b.stack_key)
        self.assertNotEqual(a.stack_key, c.stack_key)


class TestProjectCorpusDir(unittest.TestCase):

    def _project_with_corpus(self, tmp: Path,
                             files: int = 1) -> tuple[Path, Path]:
        project = _make_project(tmp, layout="maven")
        corpus = (project / "src" / "test" / "resources" / "com"
                  / "example" / "ParserFuzzInputs")
        corpus.mkdir(parents=True)
        for i in range(files):
            (corpus / f"seed{i}").write_bytes(b"hi")
        return project, corpus

    def test_junit_inputs_convention_found(self):
        tmp = _tmpdir(self)
        project, corpus = self._project_with_corpus(tmp)
        self.assertEqual(
            project_corpus_dir(project, "com.example.ParserFuzz"),
            corpus)

    def test_module_nested_convention_found(self):
        tmp = _tmpdir(self)
        project = tmp / "root"
        module = project / "core"
        harness = module / "src" / "test" / "java" / "F.java"
        harness.parent.mkdir(parents=True)
        harness.write_text(
            "class F { static void fuzzerTestOneInput(byte[] d) {} }\n")
        (project / "pom.xml").write_text("<project/>\n")
        (module / "pom.xml").write_text("<project/>\n")
        corpus = module / "src" / "test" / "resources" / "FInputs"
        corpus.mkdir(parents=True)
        (corpus / "seed").write_bytes(b"hi")
        self.assertEqual(
            project_corpus_dir(project, "F", target_source=harness),
            corpus)

    def test_empty_or_symlink_only_corpus_is_none(self):
        tmp = _tmpdir(self)
        project, corpus = self._project_with_corpus(tmp, files=0)
        self.assertIsNone(
            project_corpus_dir(project, "com.example.ParserFuzz"))
        outside = tmp / "outside-seed"
        outside.write_bytes(b"hi")
        (corpus / "seed").symlink_to(outside)
        self.assertIsNone(
            project_corpus_dir(project, "com.example.ParserFuzz"))

    def test_hostile_class_name_is_none(self):
        tmp = _tmpdir(self)
        project, _ = self._project_with_corpus(tmp)
        self.assertIsNone(project_corpus_dir(project, "../etc"))

    def test_symlinked_resources_escaping_project_is_none(self):
        tmp = _tmpdir(self)
        outside = tmp / "victim" / "com" / "example" / "ParserFuzzInputs"
        outside.mkdir(parents=True)
        (outside / "seed").write_bytes(b"hi")
        project = _make_project(tmp, layout="maven")
        resources = project / "src" / "test" / "resources"
        resources.parent.mkdir(parents=True, exist_ok=True)
        resources.symlink_to(tmp / "victim")
        self.assertIsNone(
            project_corpus_dir(project, "com.example.ParserFuzz"))


if __name__ == "__main__":
    unittest.main()
