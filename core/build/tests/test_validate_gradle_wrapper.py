"""validate_build_command must not require system gradle for ./gradlew.

Regression: the probe map hardcoded ["gradle", "--version"], so
wrapper-only projects (the common Gradle layout, no system gradle
installed) failed validation with "gradle not found in PATH" although
the detected ./gradlew command would work. The wrapper itself is
untrusted repo code, so validation checks it without executing it and
probes the JVM instead.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core.build.build_detector import BuildDetector, BuildSystem


def _gradle_system(tmp_path: Path, command: str) -> BuildSystem:
    return BuildSystem(
        type="gradle", command=command, working_dir=tmp_path,
        env_vars={}, confidence=0.9, detected_files=["build.gradle"],
    )


def _ok_probe():
    return mock.patch(
        "core.build.build_detector._run_trusted",
        return_value=SimpleNamespace(returncode=0),
    )


def test_wrapper_command_probes_java_not_system_gradle(tmp_path):
    gradlew = tmp_path / "gradlew"
    gradlew.write_text("#!/bin/sh\nexit 0\n")
    gradlew.chmod(0o755)
    bs = _gradle_system(tmp_path, "./gradlew build -x test --no-daemon")

    with _ok_probe() as run:
        assert BuildDetector(tmp_path).validate_build_command(bs) is True

    assert run.call_args.args[0] == ["java", "-version"]


def test_missing_wrapper_fails_validation_without_probe(tmp_path):
    bs = _gradle_system(tmp_path, "./gradlew build -x test --no-daemon")

    with _ok_probe() as run:
        assert BuildDetector(tmp_path).validate_build_command(bs) is False

    run.assert_not_called()


def test_non_executable_wrapper_fails_validation(tmp_path):
    gradlew = tmp_path / "gradlew"
    gradlew.write_text("#!/bin/sh\nexit 0\n")
    gradlew.chmod(0o644)
    bs = _gradle_system(tmp_path, "./gradlew build -x test --no-daemon")

    with _ok_probe():
        assert BuildDetector(tmp_path).validate_build_command(bs) is False


def test_system_gradle_command_still_probes_gradle(tmp_path):
    bs = _gradle_system(tmp_path, "gradle build -x test")

    with _ok_probe() as run:
        assert BuildDetector(tmp_path).validate_build_command(bs) is True

    assert run.call_args.args[0] == ["gradle", "--version"]
