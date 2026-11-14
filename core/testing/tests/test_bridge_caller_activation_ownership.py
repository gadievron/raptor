"""Caller cleanup restores backend bindings when pair acquisition refuses."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("outcome", ["error", "interrupt"])
def test_bridge_caller_restores_backend_after_pair_refusal(tmp_path, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_bridge_caller_activation.py")
    output, errors = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        with standalone_cli_env() as env:
            result = run_in_process_group(
                [sys.executable, "-I", str(script), str(root), str(tmp_path),
                 "pair-refusal", outcome, "candidate"],
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
    assert not error
    payload = json.loads(message)
    assert payload["result"] == "BRIDGE_REFUSAL_OWNER_OK"
    assert payload["stage"] == "pair-refusal"
    assert payload["owned_unix_pairs"] == 0
    assert not payload["forbidden_attempts"]
    guard = json.loads(bounded(tmp_path / "guard.json"))
    assert guard["profile"] == "refusal-only"
    assert guard["attempt_total"] == 0 and not guard["attempts"]
    assert guard["pair_factory_calls"] == 1
    assert guard["owned_unix_pairs"] == guard["socket_creations"] == 0
    assert guard["sent"] == guard["received"] == 0
    assert guard["pair_closed"] == []
