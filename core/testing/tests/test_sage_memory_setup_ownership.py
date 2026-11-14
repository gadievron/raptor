"""Sage memory test scratch remains owned when setup imports fail."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("scenario", ["error", "interrupt", "cleanup-only"])
def test_sage_setup_owns_directory_after_import_refusal(tmp_path, scenario):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_sage_memory_setup_ownership.py")
    source = root / "core/sage/tests/test_sage_memory.py"
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", str(helper), str(source),
                 scenario, str(result_path)],
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
    assert payload["scenario"] == scenario
    assert payload["primary_identity"] is (None if scenario == "cleanup-only" else True)
    assert payload["directory_remaining_before_rescue"] is False
    assert payload["import_seam_hits"] == (
        [] if scenario == "cleanup-only" else ["core.sage.config"]
    )
    assert payload["forbidden_attempts"] == []
