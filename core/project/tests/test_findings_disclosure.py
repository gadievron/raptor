"""Filtered findings retain explicit input and discarded-row accounting."""
import json
from types import SimpleNamespace

import pytest

from core.project import findings_utils as utils

ROW = {'id': 'good', 'file': 'a.c', 'line': 1}


@pytest.mark.parametrize('source', ['findings.json', 'openant_findings.json', 'sca/findings.json'])
@pytest.mark.parametrize('envelope', ['list', 'findings', 'results'])
@pytest.mark.parametrize('rows,discarded', [
    pytest.param([], 0, id='empty'),
    pytest.param([ROW], 0, id='valid'),
    pytest.param([None, 'row', 1, False, []], 5, id='all-malformed'),
    pytest.param([None, ROW, 'row'], 2, id='mixed'),
])
def test_selected_collection_discloses_all_rows(tmp_path, source, envelope, rows, discarded):
    path = tmp_path / source
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows if envelope == 'list' else {envelope: rows}))
    disclosure = utils.FindingsLoadDisclosure()
    loader = utils.load_sca_findings_from_dir if source.startswith('sca/') else utils.load_findings_from_dir
    loaded = loader(tmp_path, disclosure=disclosure)
    assert loaded == [row for row in rows if isinstance(row, dict)]
    assert disclosure.total_rows == len(rows)
    assert disclosure.discarded_rows == discarded
    assert len(loaded) + disclosure.discarded_rows == disclosure.total_rows


@pytest.mark.parametrize('primary', [[], {'findings': []}, {'findings': [], 'results': [None]}])
def test_shadowed_collections_do_not_contribute_counts(tmp_path, primary):
    (tmp_path / 'findings.json').write_text(json.dumps(primary))
    (tmp_path / 'openant_findings.json').write_text(json.dumps([ROW, None]))
    disclosure = utils.FindingsLoadDisclosure()
    assert utils.load_findings_from_dir(tmp_path, disclosure=disclosure) == []
    assert disclosure == utils.FindingsLoadDisclosure()


@pytest.mark.parametrize('payload', ['{broken', 'null', '"not-a-collection"', '{"findings": 7}'])
def test_unknown_row_counts_are_not_invented(tmp_path, payload):
    (tmp_path / 'findings.json').write_text(payload)
    disclosure = utils.FindingsLoadDisclosure()
    assert utils.load_findings_from_dir(tmp_path, disclosure=disclosure) == []
    assert disclosure.total_rows == disclosure.discarded_rows == 0


def test_missing_file_does_not_disclose_a_phantom_row(tmp_path):
    disclosure = utils.FindingsLoadDisclosure()
    assert utils.load_findings_from_dir(tmp_path, disclosure=disclosure) == []
    assert disclosure == utils.FindingsLoadDisclosure()


def test_disclosure_can_accumulate_across_explicit_loads(tmp_path):
    (tmp_path / 'findings.json').write_text(json.dumps([ROW, None]))
    disclosure = utils.FindingsLoadDisclosure()
    for _ in range(2):
        assert utils.load_findings_from_dir(tmp_path, disclosure=disclosure) == [ROW]
    assert disclosure.total_rows == 4
    assert disclosure.discarded_rows == 2
    assert utils.FindingsLoadDisclosure().total_rows == 0


def test_strict_loader_still_refuses_filtered_data(tmp_path):
    (tmp_path / 'findings.json').write_text(json.dumps([ROW, None]))
    disclosure = utils.FindingsLoadDisclosure()
    with pytest.raises(ValueError, match='Invalid findings rows'):
        utils.load_findings_from_dir(tmp_path, strict=True, disclosure=disclosure)
    assert disclosure.total_rows == 2
    assert disclosure.discarded_rows == 1


def test_explicit_snapshot_discloses_its_selected_rows(tmp_path):
    context = SimpleNamespace(findings=[{'native': ROW}], kind='scan')
    disclosure = utils.FindingsLoadDisclosure()
    assert utils.load_findings_from_dir(tmp_path, report_context=context, disclosure=disclosure) == [ROW]
    assert disclosure.total_rows == 1
    assert disclosure.discarded_rows == 0
