"""An affected-file batch may legitimately contain no default-tier cases."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("status", [0, 1, 2, 3, 4, 5])
def test_fast_batch_only_accepts_success_or_empty_selection(tmp_path, status):
    workflow = (ROOT / ".github/workflows/tests.yml").read_text()
    step = re.search(
        r"^      - name: Run unit tests \(batch .*?\n(.*?)(?=^      - name:|\Z)",
        workflow, re.M | re.S,
    )
    assert step is not None
    script = textwrap.dedent(step[1].split("        run: |\n", 1)[1])
    tools = tmp_path / "tools"
    tools.mkdir()
    record = tmp_path / "argv.json"
    python = tools / "python"
    python.write_text(f"#!{sys.executable}\n" +
                      "import json,os,pathlib,sys\n" +
                      "pathlib.Path(os.environ['ARGV_RECORD']).write_text(json.dumps(sys.argv[1:]))\n" +
                      "raise SystemExit(int(os.environ['PYTEST_STATUS']))\n")
    python.chmod(0o755)
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin/activate").write_text("# owned activation fixture\n")
    env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
               VENV_PATH=str(venv), RUNNER_TEMP=str(tmp_path),
               TEST_FILES="core/x/tests/test_only_slow.py", ARGV_RECORD=str(record),
               PYTEST_STATUS=str(status))
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if status == 5 else status), result.stderr
    args = json.loads(record.read_text())
    assert args[:4] == ["-m", "pytest", "-p", "core.testing.llm_tripwire"]
    assert args[-1] == env["TEST_FILES"]
    assert ("No default-tier cases" in result.stdout) is (status == 5)
