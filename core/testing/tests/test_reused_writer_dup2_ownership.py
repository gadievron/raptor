"""Reused writer callbacks retain descriptors across duplication faults."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["dup_error", "duplicate", "same"])
def test_reused_writer_callback_owns_duplication_setup(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_reused_writer_dup2_ownership.py")
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
    assert payload["expected_exception"]
    assert payload["distinct_source_closed_before_rescue"] is (mode != "same")
    assert payload["source_close_calls"] == payload["duplicate_calls"] == int(mode != "same")
    assert payload["target_live_before_rescue"] is (mode != "dup_error")
    assert payload["borrowed_handoff_count"] == int(mode != "dup_error")
    assert payload["target_write_verified"] is (mode != "dup_error")
    assert payload["exact_callback_body"] and payload["pipe_process_body_excluded"]
    assert payload["forbidden_attempts"] == [] and payload["independent_verified_rescue_complete"]
