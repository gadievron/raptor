"""R2 fixture setup owns its temporary stream through private publication."""
import json
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize("stage", ["before", "after", "success"])
def test_setup_stream_is_closed_before_rescue(tmp_path, stage):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_r2_session_fixture_ownership.py")
    result_path = tmp_path / "result.json"
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONFAULTHANDLER": "1"}) as env:
            runtime = tmp_path / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            result = run_in_process_group(
                [sys.executable, "-I", str(helper), str(root), stage, str(result_path)],
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
    assert payload["stage"] == stage
    assert payload["oracle_mode"] == "candidate-closed-before-rescue"
    assert payload["native_stream_open_before_rescue"] is False
    assert payload["primary_identity"] is (None if stage == "success" else True)
    assert payload["publication_names"] == {"before": [], "after": ["_spawn_r2"], "success": ["_spawn_r2", "scratch_dir"]}[stage]
    assert payload["consumer_body_attempts"] == []
