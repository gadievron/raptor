"""Real private directories stay owned during pathname setup."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["path_error", "healthy"])
def test_tempfile_directory_path_setup_retires_allocation(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_tempfile_directory_path_ownership.py")
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    result_path = tmp_path / "result.json"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}) as env:
            result = run_in_process_group(
                [sys.executable, "-I", "-B", str(helper), str(root), mode, str(result_path)],
                timeout=20, env=env, cwd=root, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr,
            )
    def bounded(path):
        with path.open("rb") as stream:
            value = stream.read(65537)
        assert len(value) <= 65536
        return value
    assert result.returncode == 0, bounded(errors).decode()
    assert bounded(output) == bounded(errors) == b""
    payload = json.loads(bounded(result_path))
    assert payload["mode"] == mode
    assert payload["outward_assertion"] is (mode == "path_error")
    assert payload["path_error_context_identity"] is (True if mode == "path_error" else None)
    assert payload["owned_directory_absent_before_rescue"]
    assert payload["source_removal_calls"] == 1
    assert payload["source_body_unchanged_except_cleanup_registration"]
    assert payload["forbidden_attempts"] == [] and payload["independent_verified_rescue_complete"]
