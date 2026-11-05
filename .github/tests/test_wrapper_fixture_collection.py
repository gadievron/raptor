"""Check wrapper fixture ownership against actual isolated pytest collection."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.slow
@pytest.mark.parametrize('explicit', [False, True], ids=['runtime-import', 'explicit-conftest-import'])
def test_importing_dependencies_does_not_inherit_their_autouse_fixtures(tmp_path, explicit):
    library = tmp_path / 'library'
    checks = tmp_path / 'checks'
    library.mkdir()
    checks.mkdir()
    (library / '__init__.py').write_text('')
    (library / 'helper.py').write_text('VALUE = 7\n')
    (library / 'conftest.py').write_text(
        'import pytest\nfrom pathlib import Path\nTOKEN = 7\n'
        'Path(__file__).with_name("fixture-imported").write_text("loaded")\n'
        '@pytest.fixture(autouse=True)\n'
        'def dependency_fixture():\n'
        '    raise AssertionError("imported dependency fixtures must not run")\n'
    )
    (checks / 'conftest.py').write_text(
        'import pytest\n'
        '@pytest.fixture\n'
        'def collected_fixture():\n'
        '    return "collected"\n'
    )
    source = 'from library import helper\n'
    if explicit:
        source += 'from library.conftest import TOKEN\n'
    source += ('def test_consumer(collected_fixture):\n'
               '    assert collected_fixture == "collected"\n'
               '    assert helper.VALUE == 7\n')
    if explicit:
        source += '    assert TOKEN == 7\n'
    (checks / 'test_consumer.py').write_text(source)
    config = tmp_path / 'pytest.ini'
    config.write_text('[pytest]\n')
    env = dict(os.environ)
    for key in ('PYTEST_ADDOPTS', 'PYTHONPATH', 'RAPTOR_TEST_LIVE_LLM'):
        env.pop(key, None)
    for name in ('home', 'registry', 'out', 'scratch'):
        (tmp_path / name).mkdir()
    env.update(HOME=str(tmp_path / 'home'), RAPTOR_REGISTRY_HOME=str(tmp_path / 'registry'),
               RAPTOR_OUT_DIR=str(tmp_path / 'out'), TMPDIR=str(tmp_path / 'scratch'),
               PYTHONPATH=os.pathsep.join([str(tmp_path), str(ROOT)]),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', '-c', str(config), '--confcutdir', str(tmp_path),
         '-o', 'addopts=--import-mode=importlib', '-p', 'core.testing.llm_tripwire',
         '-q', 'checks/test_consumer.py'],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert (library / 'fixture-imported').exists() == explicit
