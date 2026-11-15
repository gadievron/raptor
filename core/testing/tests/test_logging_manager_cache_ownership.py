"""Private logging fixtures preserve caller caches and filtering."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["root", "sdk", "named", "root_disabled"])
def test_logging_fixture_owns_manager_cache(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_logging_manager_cache_ownership.py")
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
    assert payload["borrowed_cache_preserved_before_rescue"] and payload["borrowed_cache_object_same"]
    assert payload["private_caches_invalidated"] and payload["disable_filtering_preserved"]
    assert payload["private_shapes_preserved"] and payload["owned_streams_closed_by_source"]
    assert payload["owned_helper_restored"]
    assert payload["forbidden_attempts"] == [] and payload["independent_identity_preserving_rescue_complete"]
