"""Registry pins reject aliases of protected roots and allow owned scratch."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["dotdot", "relative", "symlink", "root_symlink", "safe_child", "safe_missing"])
def test_state_pin_guard_canonicalises_aliases(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    helper = Path(__file__).with_name("_state_pin_alias_ownership.py")
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    result_path = tmp_path / "result.json"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env(env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}) as env:
            home = tmp_path / "home"
            home.mkdir(mode=0o700)
            env["HOME"] = str(home)
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
    assert payload["outcome"] == ("admitted" if mode in {"safe_child", "safe_missing"} else "refused")
    assert payload["guard_matches_expected_outcome"] and payload["canonical_admission_or_refusal_verified"]
    assert payload["stopped_before_producer_imports"] and payload["owned_paths_retired"]
    assert payload["forbidden_attempts"] == []
