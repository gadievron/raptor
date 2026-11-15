"""Compaction fixture owns its guard before setup and through cleanup."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("mode", ["binding_error", "healthy"])
def test_compact_writer_fixture_owns_guard_before_setup(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_compact_writer_guard_setup_ownership.py")
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
    healthy = mode == "healthy"
    assert payload["yield_reached"] is payload["guard_live_at_yield"] is payload["dynamic_owned_then_retired"] is healthy
    assert payload["all_raw_descriptors_closed_before_rescue"] and payload["raw_guard_close_calls"] == 1
    assert payload["raw_dynamic_close_calls"] == int(healthy)
    assert payload["binding_calls"] == (["tempfile", "os"] if healthy else ["tempfile"])
    assert payload["private_bindings_restored"] and payload["generator_complete"]
    assert payload["guard_file_fixture_owned"] and payload["opaque_journal_prelude_excluded"]
    assert payload["close_order"] == (["dynamic", "guard"] if healthy else ["guard"])
    assert payload["independent_verified_rescue_complete"] and payload["forbidden_attempts"] == []
