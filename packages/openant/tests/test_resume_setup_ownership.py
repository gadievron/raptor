"""Temporary directories remain owned when resume test setup fails."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("class_name", [
    "TestValidatePriorRun",
    "TestInFlightPriorRunRefuses",
    "TestScanFailedReportResumesLikeSuccess",
])
@pytest.mark.parametrize("scenario", ["mkdir-error", "mkdir-interrupt", "healthy"])
def test_resume_setup_owns_temporary_directory(tmp_path, class_name, scenario):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_resume_setup_ownership.py")
    source = Path(__file__).with_name("test_resume.py")
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", str(helper), str(source), class_name,
                 scenario, "candidate", str(result_path)],
                timeout=20, env=env, cwd=root, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr,
            )

    def bounded(path):
        with path.open("rb") as stream:
            value = stream.read(65537)
        assert len(value) <= 65536
        return value.decode("utf-8")

    message, error = bounded(output), bounded(errors)
    assert result.returncode == 0, error
    assert message == error == ""
    payload = json.loads(bounded(result_path))
    assert payload["class"] == class_name
    assert payload["scenario"] == scenario
    assert payload["expect"] == "candidate"
    assert payload["primary_identity"] is (None if scenario == "healthy" else True)
    assert payload["directory_exists_after_unittest_cleanup"] is False
    assert payload["independent_rescue_not_yet_run"] is True
    assert payload["forbidden_attempts"] == []
