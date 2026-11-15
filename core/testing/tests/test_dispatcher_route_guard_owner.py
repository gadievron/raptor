"""Dispatcher-route scrubbing owns environment state through body teardown."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["present", "empty", "absent", "override", "error", "interrupt"])
def test_dispatcher_route_guard_outlives_body_undo(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_dispatcher_route_guard_owner.py")
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
    assert payload["selected_body_route_preserved"] and payload["expected_body_outcome_preserved"]
    assert payload["body_wrapper_drained_before_owner_exit"]
    assert payload["initial_presence_and_value_restored_before_rescue"]
    assert payload["late_body_undo_keeps_caller_environment"] and payload["native_fixture_strip_reached"]
    assert payload["provider_or_socket_never_used"]
    assert payload["forbidden_attempts"] == [] and payload["independent_environment_rescue_complete"]
