"""Optional nightly timing downloads only serve multi-batch selections."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("selection", [
    "empty", "single", "multiple", "large", "missing", "malformed", "object",
])
def test_real_duration_step_fetches_only_for_multiple_batches(tmp_path, selection):
    workflow = (ROOT / ".github/workflows/tests.yml").read_text()
    assert "python_matrix: ${{ steps.balance.outputs.python_matrix || steps.scope.outputs.python_matrix }}" in workflow
    step = workflow.split("      - id: durations\n", 1)[1].split("\n      - ", 1)[0]
    assert "if: steps.scope.outputs.python == 'true'" in step
    assert "continue-on-error: true" in step
    assert "SELECTED_MATRIX_FILE: ${{ steps.scope.outputs.python_matrix_file }}" in step
    run = re.search(r"(?m)^        run: \|\n((?:          [^\n]*\n|[ \t]*\n)+)", step)
    assert run, step
    command = textwrap.dedent(run.group(1))
    matrix = tmp_path / "selected.json"
    selected = [{"batch": 1, "files": "core/testing/tests/test_llm_tripwire.py"}]
    if selection in {"multiple", "large"}:
        selected.append({"batch": 2, "files": "core/testing/tests/test_llm_hosts_tripwire.py"})
    if selection == "large":
        selected[0]["files"] = " ".join(f"core/tests/test_owned_{i}.py" for i in range(10000))
    if selection != "missing":
        matrix.write_text("{" if selection == "malformed" else json.dumps(
            [] if selection == "empty" else {} if selection == "object" else selected))
    original = matrix.read_bytes() if matrix.exists() else None
    tools = tmp_path / "bin"
    tools.mkdir()
    gh = tools / "gh"
    gh.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''
        import json, os, sys
        from pathlib import Path
        with Path(os.environ["API_CALLS"]).open("a") as output:
            output.write(json.dumps(sys.argv[1:]) + "\\n")
        if sys.argv[1] == "api":
            print("123")
        else:
            assert sys.argv[1:4] == ["run", "download", "123"]
            directory = Path(sys.argv[sys.argv.index("--dir") + 1])
            (directory / "results.xml").write_text(
                '<testsuite><testcase classname="core.testing.tests.test_llm_tripwire" '
                'name="test_owned" time="2.5" /></testsuite>')
    '''))
    gh.chmod(0o700)
    calls = tmp_path / "calls.jsonl"
    output = tmp_path / "outputs"
    env = dict(os.environ, PATH=str(tools) + os.pathsep + os.defpath,
               API_CALLS=str(calls), GITHUB_OUTPUT=str(output),
               SELECTED_MATRIX_FILE=str(matrix), RUNNER_TEMP=str(tmp_path),
               REPO="owned/repo", GH_TOKEN="owned-test-token")
    result = subprocess.run(["bash", "-c", command], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (matrix.read_bytes() if matrix.exists() else None) == original
    if selection in {"multiple", "large"}:
        requests = [json.loads(line) for line in calls.read_text().splitlines()]
        assert len(requests) == 2
        assert requests[0][0] == "api"
        assert requests[1][:3] == ["run", "download", "123"]
        durations = tmp_path / "test_durations.json"
        assert output.read_text() == f"path={durations}\n"
        assert json.loads(durations.read_text())["core/testing/tests/test_llm_tripwire.py"] == 2.5
    else:
        assert not calls.exists()
        assert not output.exists()
