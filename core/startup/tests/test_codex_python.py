"""Standalone procedure files receive context before their first import."""
import json
import os
import subprocess
import sys

import pytest

from core.startup import codex_environment as environment
from core.startup.tests.test_codex_broker import host  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='live Linux owner fixture')


@pytest.mark.parametrize('status', [0, 17])
def test_standalone_python_receives_context_and_preserves_argv_and_exit(host, tmp_path, status):  # noqa: F811
    sid, _process, _credential = host
    script = tmp_path / "helper with spaces ' $(false).py"
    script.write_text(
        'import sys, os, json\n'
        'sys.path.insert(0, os.environ["RAPTOR_DIR"])\n'
        'from core.project import sessions\n'
        'print(json.dumps([sys.argv[1:], sessions.session_binding()[1]]))\n'
        f'raise SystemExit({status})\n')
    words = ['a path with spaces', '$(touch never-execute)', '#literal', '-']
    env = {'HOME': os.environ['HOME'], 'PATH': os.environ['PATH'],
           '_RAPTOR_TRUSTED': '1', 'CODEX_THREAD_ID': sid,
           'RAPTOR_CODEX_ENVIRONMENT': '1'}
    result = subprocess.run(
        [sys.executable, '-I', str(environment.ROOT / 'libexec/raptor-session-init'),
         '--codex-python', str(script), *words],
        env=env, cwd=environment.ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == status, result.stderr
    assert json.loads(result.stdout) == [words, 'none']


def test_uninitialized_runner_never_executes_script(tmp_path):
    marker = tmp_path / 'must-not-exist'
    script = tmp_path / 'helper.py'
    script.write_text('from pathlib import Path\nPath(__file__).with_name("must-not-exist").touch()\n')
    result = subprocess.run(
        [sys.executable, '-I', str(environment.ROOT / 'libexec/raptor-session-init'),
         '--codex-python', str(script)],
        env={'PATH': os.environ['PATH'], '_RAPTOR_TRUSTED': '1'},
        capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert not marker.exists()
