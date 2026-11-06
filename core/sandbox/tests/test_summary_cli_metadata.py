"""Retroactive summary CLI bounds human metadata without changing stored records."""
import errno
import json
import os

import pytest

from core.sandbox import evidence, summary
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='requires POSIX control-character filenames')
CONTROL = 'owned-\x1b[31m\r\x85\u202e'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


def source(run, kind='write'):
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_text(json.dumps({'type': kind, 'path': '/tmp/owned'}) + '\n')


def safe(text):
    for value in ('\x1b', '\r', '\x85', '\u202e'):
        assert value not in text
    assert 'owned-' in text


@pytest.mark.parametrize('branch,code', [('missing', 1), ('empty', 0), ('written', 0)],
                         ids=['missing', 'empty', 'written'])
def test_single_run_directory_metadata_is_escaped(tmp_path, capsys, branch, code):
    run = tmp_path / CONTROL
    if branch != 'missing':
        run.mkdir(mode=0o700)
    if branch == 'written':
        source(run)
    assert summary._cli_main([str(run)]) == code
    output = capsys.readouterr()
    safe(output.out + output.err)
    if branch == 'written':
        result = json.loads((run / summary.SUMMARY_FILE).read_text())
        assert result['total_denials'] == 1
        assert result['run_dir'] == str(run)
        assert result['by_type'] == {'write': 1}


@pytest.mark.parametrize('position', ['project', 'child'])
def test_sweep_directory_metadata_is_escaped(tmp_path, capsys, position):
    project = tmp_path / (CONTROL if position == 'project' else 'project')
    run = project / (CONTROL if position == 'child' else 'run')
    source(run)
    assert summary._cli_main(['--sweep', str(project)]) == 0
    safe(capsys.readouterr().out)
    result = json.loads((run / summary.SUMMARY_FILE).read_text())
    assert result['total_denials'] == 1
    assert result['run_dir'] == str(run)


def test_sweep_listing_error_escapes_exception_metadata(tmp_path, monkeypatch, capsys):
    class OwnedListingPath(type(tmp_path)):
        def iterdir(self):
            raise OSError(errno.EIO, CONTROL)
    monkeypatch.setattr(summary, 'Path', OwnedListingPath)
    assert summary._cli_main(['--sweep', str(tmp_path)]) == 1
    safe(capsys.readouterr().err)


def test_type_breakdown_is_bounded_but_stored_data_is_complete(tmp_path, capsys):
    run = tmp_path / 'run'
    label = 'future-' + 'x' * 5000
    source(run, label)
    assert summary._cli_main([str(run)]) == 0
    output = capsys.readouterr().out
    assert len(output) < 1500
    assert '...[+' in output
    result = json.loads((run / summary.SUMMARY_FILE).read_text())
    assert result['by_type'] == {label: 1}
    assert result['denials'][0]['type'] == label


def test_plain_output_preserves_existing_breakdown(tmp_path, capsys):
    run = tmp_path / 'run'
    source(run)
    assert summary._cli_main([str(run)]) == 0
    output = capsys.readouterr().out
    assert f'Wrote {run / summary.SUMMARY_FILE}' in output
    assert "by_type={'write': 1}" in output
