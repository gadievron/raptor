"""File-backed capture fixtures own handlers before setup callbacks."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["setup_error", "healthy"])
def test_log_capture_owns_handler_before_setup(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_log_capture_setup_ownership.py")
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
    assert payload["primary_identity"] is (True if mode == "setup_error" else None)
    assert payload["owned_file_stream_closed_before_rescue"] and payload["source_close_calls"] == 1
    assert payload["stream_live_during_setup"] and payload["borrowed_closed_by_source_finally"]
    assert payload["private_publication_names"] == (["RaptorLogger"] if mode == "healthy" else [])
    assert payload["consumer_module_body_excluded"] and payload["opaque_receiver_not_inspected"]
    assert payload["forbidden_attempts"] == [] and payload["independent_verified_rescue_complete"]
