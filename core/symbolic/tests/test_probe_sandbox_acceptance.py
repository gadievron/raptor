"""Real nested dependency import under the symbolic worker's write restriction."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux Landlock worker check')]


def test_angr_probe_inherits_private_worker_scratch(tmp_path):
    from core.symbolic._availability import angr_available
    from core.symbolic.tests.test_isolate import _landlock_engageable
    if not _landlock_engageable():
        pytest.skip('symbolic Landlock restriction unavailable')
    if not angr_available():
        pytest.skip('Angr required for the real nested import')
    private, outside, home = (tmp_path/name for name in ('private', 'outside', 'home'))
    for directory in (private, outside, home):
        directory.mkdir()
    root = Path(__file__).resolve().parents[3]
    code = r'''
import json, pathlib, sys, tempfile
sys.path.insert(0, sys.argv[1])
from core.symbolic._isolate import _apply_symex_sandbox
_apply_symex_sandbox(sys.argv[2])
try: (pathlib.Path(sys.argv[3])/'forbidden').write_text('bad')
except PermissionError: pass
else: raise AssertionError('worker write restriction did not engage')
from core.symbolic._availability import angr_available
assert angr_available(), 'nested dependency probe failed under the worker write restriction'
print(json.dumps({'scratch': tempfile.gettempdir(), 'available': True}))
'''
    env = dict(PATH=os.environ.get('PATH', os.defpath), HOME=str(home), TMPDIR=str(outside))
    result = subprocess.run([sys.executable, '-I', '-c', code, str(root), str(private), str(outside)],
                            cwd=outside, env=env, capture_output=True, text=True, timeout=150)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1])['scratch'] == str(private.resolve())
    assert not (outside/'forbidden').exists()
