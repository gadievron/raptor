"""Debugger mode interruptions retire unadopted script descriptors and paths."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("site", ["debugger", "crash"])
def test_mode_interrupt_retires_unadopted_script(tmp_path, site):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_debugger_mode_script_ownership.py")
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", str(helper), str(root), site, str(result_path)],
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
    assert payload["site"] == site
    assert payload["primary_identity"] is True
    assert payload["raw_descriptor_live_before_rescue"] is False
    assert payload["path_present_before_rescue"] is False
    assert payload["mode_effects"] == [0o600]
    assert payload["source_close_attempts"] == payload["source_unlink_attempts"] == 1
    assert payload["raw_descriptor_consumed_before_close"] is True
    assert payload["adoption_calls"] == 0
    assert payload["forbidden_attempts"] == []
