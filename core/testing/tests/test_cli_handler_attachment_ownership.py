"""CLI logging fixtures own file handlers before attachment."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["attach_error", "healthy", "body_error"])
def test_cli_handler_owns_attachment_boundary(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_cli_handler_attachment_ownership.py")
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
    assert payload["expected_exception_or_native_success"]
    assert payload["stream_fd_closed_before_rescue"] and payload["source_close_calls"] == 1
    assert payload["unattached_after_scope"] and payload["borrowed_root_list_restored"]
    assert payload["borrowed_handler_kept_open"] and payload["private_manager"]
    assert payload["full_selected_function"]
    assert payload["native_content_assertions_passed"] is (mode != "attach_error")
    assert payload["forbidden_attempts"] == [] and payload["independent_verified_rescue_complete"]
