"""Stale audit fixture owns descriptors and paths throughout setup."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("mode", ["write_error", "healthy"])
def test_stale_audit_loop_owns_files_before_write(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_stale_audit_loop_ownership.py")
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
    assert payload["mode"] == mode and payload["expected_outcome_identity"]
    count = 1 if mode == "write_error" else 3
    assert payload["allocations"] == payload["closed_incarnations"] == payload["write_attempts"] == count
    assert payload["all_descriptors_closed_before_rescue"] and payload["all_paths_absent_before_rescue"]
    assert payload["caller_unlink_attempts"] == count
    assert payload["caller_missing_unlinks"] == (0 if mode == "write_error" else 3)
    assert payload["written_bytes"] == ([] if mode == "write_error" else [2, 2, 2])
    assert payload["actual_sweep_calls"] == int(mode == "healthy")
    assert payload["actual_sweep_lstats"] == payload["actual_sweep_unlinks"] == (0 if mode == "write_error" else 3)
    assert payload["exact_import_bindings"] == 1
    assert payload["independent_verified_rescue_complete"]
    assert payload["forbidden_attempts"] == []
