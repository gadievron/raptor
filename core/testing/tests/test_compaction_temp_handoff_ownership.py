"""Compaction fixture owns temporary descriptors until callback handoff."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("mode", ["wait_refusal", "healthy"])
def test_compaction_temp_callback_owns_descriptor_until_return(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_compaction_temp_handoff_ownership.py")
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", "-B", str(helper), str(root), mode, str(result_path)],
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
    assert payload["mode"] == mode and payload["expected_outcome"]
    failed = mode == "wait_refusal"
    assert payload["actual_caller_assertion"] is failed
    assert payload["exact_tuple_live_handoff_before_caller_cleanup"] is (not failed)
    assert payload["descriptor_closed_before_rescue"] and payload["path_absent_before_rescue"]
    assert payload["fixture_close_calls"] == payload["fixture_unlink_calls"] == int(failed)
    assert payload["handoff_caller_retirement_calls"] == int(not failed)
    assert payload["signal_calls"] == payload["tracked_temp_paths"] == 1
    assert payload["wait_seconds_arguments"] == [5]
    assert payload["callback_order"] == (["close", "unlink"] if failed else [])
    assert payload["independent_verified_rescue_complete"]
    assert payload["forbidden_attempts"] == []
