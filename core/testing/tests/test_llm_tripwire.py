"""Real subprocess proofs of the opt-in CI LLM tripwire."""

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from core.testing.llm_tripwire import Listener

ROOT = Path(__file__).resolve().parents[3]


def test_listener_records_bounded_body_and_joins(tmp_path):
    journal = tmp_path / "requests.jsonl"
    listener = Listener(journal, "unit")
    listener.active = "test-owned-node"
    try:
        with pytest.raises(HTTPError) as error:
            urlopen(Request(listener.url + "/chat/completions",
                            data=b"x" * 70000), timeout=3)
        assert error.value.code == 400
        row = json.loads(journal.read_text())
        assert row["active_test"] == "test-owned-node"
        assert len(row["body_excerpt"]) == 4096
        assert row["path"] == "/v1/chat/completions"
    finally:
        listener.close()
    assert not listener.thread.is_alive()


@pytest.mark.parametrize("workers", [0, 2])
@pytest.mark.parametrize("leak", [False, True])
@pytest.mark.wall_budget(30)  # Starts real nested pytest/xdist processes.
def test_swallowed_child_request_fails_session(tmp_path, workers, leak):
    """A child catches HTTPError and its test passes; CI must still fail."""
    if workers:
        pytest.importorskip("xdist")
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_child.py").write_text('''
import json, os, subprocess, sys
def test_child_request():
    if os.environ['MAKE_LEAK'] == '0':
        return
    code = """
import json, os
from urllib.request import Request, urlopen
from urllib.error import HTTPError
config = json.load(open(os.environ['RAPTOR_CONFIG']))
endpoint = config['models'][0]['api_base']
try:
    urlopen(Request(endpoint + '/chat/completions',
                    data=b'{"messages":[{"content":"tripwire proof"}]}'), timeout=3)
except HTTPError as error:
    assert error.code == 400
"""
    subprocess.run([sys.executable, '-I', '-c', code], check=True, timeout=10)
''')
    evidence = tmp_path / "evidence"
    bootstrap = (
        "import sys;sys.path.insert(0,sys.argv.pop(1));"
        "import pytest;raise SystemExit(pytest.main(sys.argv[1:]))"
    )
    env = dict(os.environ, MAKE_LEAK=str(int(leak)), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    for key in ("PYTEST_ADDOPTS", "PYTEST_XDIST_WORKER", "PYTEST_XDIST_WORKER_COUNT",
                "PYTEST_XDIST_TESTRUNUID", "RAPTOR_TEST_LIVE_LLM"):
        env.pop(key, None)
    result = subprocess.run(
        [sys.executable, "-c", bootstrap, str(ROOT), "-q", "-p",
         "core.testing.llm_tripwire", "--llm-tripwire-dir", str(evidence),
         *(["-p", "xdist.plugin", "-n", str(workers)] if workers else []),
         str(tmp_path / "test_child.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == int(leak), result.stdout + result.stderr
    rows = [json.loads(line) for p in evidence.glob("*/*.jsonl")
            for line in p.read_text().splitlines()]
    assert len(rows) == int(leak)
    if leak:
        assert rows[0]["active_test"].endswith("test_child.py::test_child_request")
        if workers:
            assert rows[0]["worker"].startswith("gw")
        else:
            assert rows[0]["worker"] == "controller"
        assert "tripwire proof" in rows[0]["body_excerpt"]
        assert "LLM tripwire FAILED" in result.stdout
