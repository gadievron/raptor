"""Tests for core/build/toolchain.py — toolchain-home detection.

Detection relies on filesystem layout (`/usr/lib/jvm/default-java`,
`readlink -f $(which java)`), not `os.environ`. Tests mock both so
they run deterministically regardless of what the host actually has
installed.
"""

from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import patch

from core.build import toolchain


class TestResolveFromWhich(unittest.TestCase):
    """`_resolve_from_which` locates binary, resolves symlink, strips suffix."""

    def test_returns_none_when_not_on_path(self):
        with patch("shutil.which", return_value=None):
            self.assertIsNone(toolchain._resolve_from_which("java", "bin/java"))

    def test_strips_suffix_when_real_path_matches(self):
        # `which java` -> /usr/bin/java, realpath -> /opt/jdk-17/bin/java.
        # Suffix "bin/java" strips to "/opt/jdk-17".
        with patch("shutil.which", return_value="/usr/bin/java"), \
             patch("os.path.realpath", return_value="/opt/jdk-17/bin/java"):
            self.assertEqual(
                toolchain._resolve_from_which("java", "bin/java"),
                "/opt/jdk-17",
            )

    def test_rejects_when_real_path_does_not_end_with_suffix(self):
        # A wrapper script at `/usr/local/bin/java` that isn't actually
        # under a JDK layout — real path `/opt/wrapper-script.sh`.
        # We refuse to synthesise a bogus home.
        with patch("shutil.which", return_value="/usr/local/bin/java"), \
             patch("os.path.realpath", return_value="/opt/wrapper-script.sh"):
            self.assertIsNone(
                toolchain._resolve_from_which("java", "bin/java"),
            )

    def test_os_error_returns_none(self):
        with patch("shutil.which", return_value="/usr/bin/java"), \
             patch("os.path.realpath", side_effect=OSError("stat failed")):
            self.assertIsNone(
                toolchain._resolve_from_which("java", "bin/java"),
            )


class TestDetectJavaHome(unittest.TestCase):
    def test_debian_default_java_symlink_wins(self):
        # Debian/Ubuntu convention: /usr/lib/jvm/default-java is a
        # symlink managed by update-alternatives. We detect it first.
        with patch("os.path.isdir", lambda p: p == "/usr/lib/jvm/default-java"):
            self.assertEqual(
                toolchain.detect_JAVA_HOME(),
                "/usr/lib/jvm/default-java",
            )

    def test_fallback_to_which_java(self):
        # default-java doesn't exist; fall back to readlink of `which java`.
        with patch("os.path.isdir", lambda p: p.startswith("/opt/jdk-17")), \
             patch("shutil.which", return_value="/usr/bin/java"), \
             patch("os.path.realpath", return_value="/opt/jdk-17/bin/java"):
            self.assertEqual(
                toolchain.detect_JAVA_HOME(),
                "/opt/jdk-17",
            )

    def test_returns_none_when_nothing_found(self):
        with patch("os.path.isdir", return_value=False), \
             patch("shutil.which", return_value=None), \
             patch("os.path.isfile", return_value=False):
            self.assertIsNone(toolchain.detect_JAVA_HOME())


class TestDetectGoroot(unittest.TestCase):
    def test_from_which_go(self):
        with patch("os.path.isdir", lambda p: p == "/usr/local/go"), \
             patch("shutil.which", return_value="/usr/local/go/bin/go"), \
             patch("os.path.realpath", return_value="/usr/local/go/bin/go"):
            self.assertEqual(toolchain.detect_GOROOT(), "/usr/local/go")

    def test_returns_none_when_go_not_on_path(self):
        with patch("shutil.which", return_value=None):
            self.assertIsNone(toolchain.detect_GOROOT())


class TestDetectDotnetRoot(unittest.TestCase):
    def test_dirname_of_dotnet_binary(self):
        with patch("shutil.which", return_value="/usr/share/dotnet/dotnet"), \
             patch("os.path.realpath", return_value="/usr/share/dotnet/dotnet"), \
             patch("os.path.isdir", lambda p: p == "/usr/share/dotnet"):
            self.assertEqual(
                toolchain.detect_DOTNET_ROOT(),
                "/usr/share/dotnet",
            )

    def test_returns_none_when_not_on_path(self):
        with patch("shutil.which", return_value=None):
            self.assertIsNone(toolchain.detect_DOTNET_ROOT())


class TestDetectRustupHome(unittest.TestCase):
    def test_asks_rustup_show_home(self):
        stub = subprocess.CompletedProcess(
            args=["rustup", "show", "home"],
            returncode=0,
            stdout="/home/user/.rustup\n",
            stderr="",
        )
        with patch("shutil.which", return_value="/usr/local/bin/rustup"), \
             patch("subprocess.run", return_value=stub), \
             patch("os.path.isdir", lambda p: p == "/home/user/.rustup"):
            self.assertEqual(
                toolchain.detect_RUSTUP_HOME(),
                "/home/user/.rustup",
            )

    def test_fallback_to_home_rustup_when_rustup_not_on_path(self):
        # `pwd.getpwuid(os.geteuid()).pw_dir` is queried first
        # (kernel-ratified user identity, can't be hijacked by
        # `HOME=/etc` env injection — see cluster 231 fix).
        # Env-var fallback only fires when pwd lookup fails.
        from collections import namedtuple
        FakePw = namedtuple("FakePw", ["pw_dir"])
        with patch("shutil.which", return_value=None), \
             patch("pwd.getpwuid", return_value=FakePw(pw_dir="/home/alice")), \
             patch("os.path.isdir", lambda p: p == "/home/alice/.rustup"):
            self.assertEqual(
                toolchain.detect_RUSTUP_HOME(),
                "/home/alice/.rustup",
            )

    def test_returns_none_when_no_rustup_and_no_home_dir(self):
        with patch("shutil.which", return_value=None), \
             patch("os.path.isdir", return_value=False):
            # Even with HOME set, if ~/.rustup isn't a real dir, None.
            self.assertIsNone(toolchain.detect_RUSTUP_HOME())


class TestDetectorsRegistry(unittest.TestCase):
    """The DETECTORS dict is the authoritative list of supported names.

    Tests to guarantee schema contract with BUILD_SYSTEMS:
    any `env_detect` entry in BUILD_SYSTEMS MUST have a matching
    detector here, or apply_toolchain_env will raise ValueError at
    build time.
    """

    def test_all_detectors_return_optional_str(self):
        # Each registered detector must be a zero-arg callable
        # returning Optional[str]. Exercise with everything mocked to
        # None — verifies the function signatures at minimum.
        with patch("shutil.which", return_value=None), \
             patch("os.path.isdir", return_value=False), \
             patch("os.path.isfile", return_value=False):
            for name, fn in toolchain.DETECTORS.items():
                result = fn()
                self.assertTrue(
                    result is None or isinstance(result, str),
                    f"detector for {name} returned {type(result)}",
                )


class TestApplyToolchainEnv(unittest.TestCase):
    """`apply_toolchain_env` consults the DETECTORS dict; patch entries
    in that dict to substitute specific detectors for testing."""

    def test_merges_detected_values_into_env(self):
        env = {"PATH": "/usr/bin"}
        with patch.dict(toolchain.DETECTORS,
                        {"JAVA_HOME": lambda: "/opt/jdk-17"}):
            result = toolchain.apply_toolchain_env(env, ["JAVA_HOME"])
        self.assertEqual(result["JAVA_HOME"], "/opt/jdk-17")
        self.assertEqual(result["PATH"], "/usr/bin")  # untouched

    def test_skips_when_detector_returns_none(self):
        # No JDK found: the env doesn't gain a JAVA_HOME key.
        # The build tool's own error takes over downstream.
        env = {"PATH": "/usr/bin"}
        with patch.dict(toolchain.DETECTORS, {"JAVA_HOME": lambda: None}):
            result = toolchain.apply_toolchain_env(env, ["JAVA_HOME"])
        self.assertNotIn("JAVA_HOME", result)

    def test_logs_warning_when_detector_returns_none(self):
        with patch.dict(toolchain.DETECTORS, {"JAVA_HOME": lambda: None}), \
             self.assertLogs("core.build.toolchain", level="WARNING") as cm:
            toolchain.apply_toolchain_env({}, ["JAVA_HOME"])
        self.assertTrue(any("JAVA_HOME" in line and "not found" in line
                            for line in cm.output))

    def test_unknown_env_detect_name_raises_value_error(self):
        # Protects against typos in BUILD_SYSTEMS.env_detect — a typo'd
        # name would otherwise become a silent no-op.
        with self.assertRaises(ValueError) as cm:
            toolchain.apply_toolchain_env({}, ["JAVA_HOM"])  # typo
        self.assertIn("JAVA_HOM", str(cm.exception))

    def test_detector_exception_treated_as_not_found(self):
        # A broken detector (OSError from exotic FS, unexpected crash)
        # must not take the whole build down. apply_toolchain_env
        # catches, logs WARNING, treats as "not found" — build tool
        # then surfaces its own error.
        def _broken_detector():
            raise RuntimeError("detector crashed")
        with patch.dict(toolchain.DETECTORS,
                        {"JAVA_HOME": _broken_detector}), \
             self.assertLogs("core.build.toolchain", level="WARNING") as cm:
            env = {"PATH": "/usr/bin"}
            result = toolchain.apply_toolchain_env(env, ["JAVA_HOME"])
        self.assertNotIn("JAVA_HOME", result)
        self.assertTrue(any("JAVA_HOME" in line and "RuntimeError" in line
                            for line in cm.output))

    def test_mutates_input_env_and_returns_it(self):
        env = {}
        with patch.dict(toolchain.DETECTORS,
                        {"JAVA_HOME": lambda: "/opt/jdk"}):
            result = toolchain.apply_toolchain_env(env, ["JAVA_HOME"])
        # Should be the SAME dict (in-place mutation + return)
        self.assertIs(result, env)


class TestBuildSystemsSchemaContract(unittest.TestCase):
    """Every `env_detect` string in BUILD_SYSTEMS must resolve to a
    detector in DETECTORS. Catches typos at test-time, not run time.
    """

    def test_every_env_detect_name_has_a_detector(self):
        from packages.codeql.build_detector import BuildDetector
        missing = set()
        for lang, tools in BuildDetector.BUILD_SYSTEMS.items():
            for tool_name, config in tools.items():
                for name in config.get("env_detect", []):
                    if name not in toolchain.DETECTORS:
                        missing.add(f"{lang}/{tool_name}: {name}")
        self.assertFalse(
            missing,
            f"BUILD_SYSTEMS references undefined detectors: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
