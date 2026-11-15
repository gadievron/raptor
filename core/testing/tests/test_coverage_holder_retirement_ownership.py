"""Coverage holder-close failures still attempt caller worker retirement."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("case", ["store", "journal"])
@pytest.mark.parametrize("mode", ["error", "interrupt"])
def test_coverage_holder_close_error_still_joins_worker(tmp_path, case, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_coverage_holder_retirement.py")
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", "-B", str(helper), str(root), case, mode, str(result_path)],
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
    assert payload["mode"] == mode
    assert payload["close_secondary_identity"] and payload["start_primary_context_identity"]
    assert payload["case"] == case
    assert payload["holder_close_calls"] == payload["caller_join_calls"] == 1
    assert payload["worker_alive_before_rescue"] is False
    assert payload["holder_fd_closed_before_rescue"] is True
    assert payload["initial_file_context_closes"] == int(case == "journal")
    assert payload["actual_entry_calls"] == payload["declared_append_calls"] == (2 if case == "journal" else 0)
    assert payload["independent_worker_rescue_complete"] is True
    assert payload["owned_data_module_restored"] is True
    assert payload["forbidden_attempts"] == []
