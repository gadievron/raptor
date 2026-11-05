"""Sweep discovery must preserve candidates for the hardened finalizer."""
import json

import pytest

from core.sandbox import evidence, summary
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.parametrize('location', ['canonical', 'legacy'])
@pytest.mark.parametrize('shape', ['dangling', 'loop'])
def test_sweep_finalizes_unreadable_links(tmp_path, capsys, location, shape):
    project = tmp_path / 'project'
    run = project / 'run'
    run.mkdir(parents=True)
    (project / 'empty').mkdir()
    path = (evidence.evidence_write_path(run, summary.DENIALS_FILE)
            if location == 'canonical'
            else evidence.legacy_read_path(run, summary.DENIALS_FILE))
    path.parent.mkdir(parents=True, exist_ok=True)
    destination = run / 'missing'
    path.symlink_to(destination if shape == 'dangling' else path)

    assert summary._cli_main(['--sweep', str(project)]) == 0

    result = json.loads((run / summary.SUMMARY_FILE).read_text())
    assert result['planted_object'] == 'symlink'
    assert result['total_denials'] == 0
    assert not destination.exists()
    assert not path.is_symlink()
    output = capsys.readouterr().out
    assert 'Swept 1 stranded run(s)' in output
    assert '1 summary file(s) written' in output
    assert not (project / 'empty' / summary.SUMMARY_FILE).exists()
