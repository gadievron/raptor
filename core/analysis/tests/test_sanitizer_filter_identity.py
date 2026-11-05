"""Line-bound enforcement must not remove distinct neighboring findings."""

import json
from copy import deepcopy

import pytest

from core.analysis.sanitizer_cut_postpass import filter_enforced_from_sarif


def _result(file='src/A.java', line=8, rule='r'):
    return {'ruleId': rule, 'locations': [{'physicalLocation': {
        'artifactLocation': {'uri': file}, 'region': {'startLine': line},
    }}]}


def _write(tmp_path, runs):
    path = tmp_path / 'combined.sarif'
    path.write_text(json.dumps({'runs': [{'results': results} for results in runs]}))
    return path


def _selector(file='src/A.java', line=8, rule='r'):
    return {'rule_id': rule, 'file': file, 'line': line}


@pytest.mark.parametrize('separate_runs', [False, True])
def test_ambiguous_same_line_selector_keeps_every_report(tmp_path, separate_runs):
    first = _result()
    second = deepcopy(first)
    first['locations'][0]['physicalLocation']['region']['startColumn'] = 3
    second['locations'][0]['physicalLocation']['region']['startColumn'] = 30
    first['fingerprints'] = {'matchBasedId/v1': 'safe'}
    second['fingerprints'] = {'matchBasedId/v1': 'unsafe'}
    path = _write(tmp_path, [[first], [second]] if separate_runs else [[first, second]])
    original = path.read_bytes()
    assert filter_enforced_from_sarif(path, [_selector()]) == 0
    assert path.read_bytes() == original


def test_unique_selector_still_removes_with_ambiguous_neighbor(tmp_path):
    path = _write(tmp_path, [[_result(), _result(), _result(line=9)]])
    assert filter_enforced_from_sarif(path, [_selector(), _selector(line=9)]) == 1
    assert len(json.loads(path.read_text())['runs'][0]['results']) == 2


@pytest.mark.parametrize('bad', [None, [], {}, {'line': []},
    {'rule_id': [], 'file': 'src/A.java', 'line': 8},
    {'rule_id': 'r', 'file': 'src/A.java', 'line': True},
    {'rule_id': 'r', 'file': 'src/A.java', 'line': 8.5}])
def test_malformed_selector_cannot_crash_or_hide_valid_sibling(tmp_path, bad):
    path = _write(tmp_path, [[_result()]])
    assert filter_enforced_from_sarif(path, [bad, _selector()]) == 1


@pytest.mark.parametrize('path_name', [
    '../src/A.java', '../../src/A.java', '%2e%2e/src/A.java',
    'https://host.invalid/src/A.java', 'file://host.invalid/src/A.java',
])
def test_traversal_path_cannot_match_in_tree_suffix(tmp_path, path_name):
    path = _write(tmp_path, [[_result(file=path_name)]])
    original = path.read_bytes()
    assert filter_enforced_from_sarif(path, [_selector()]) == 0
    assert path.read_bytes() == original


def test_dotfile_directory_is_not_a_plain_directory(tmp_path):
    path = _write(tmp_path, [[_result(file='.config/A.java')]])
    assert filter_enforced_from_sarif(path, [_selector(file='config/A.java')]) == 0


def test_duplicate_selectors_count_one_removed_result(tmp_path):
    path = _write(tmp_path, [[None, _result()]])
    assert filter_enforced_from_sarif(path, [_selector(), _selector()]) == 1
    assert json.loads(path.read_text())['runs'][0]['results'] == [None]


def test_many_unrelated_selectors_do_not_prevent_unique_match(tmp_path):
    results = [_result(line=line) for line in range(1, 1001)]
    selectors = [_selector(line=line) for line in range(1, 1001)]
    path = _write(tmp_path, [results])
    assert filter_enforced_from_sarif(path, selectors) == 1000


def test_local_file_uri_keeps_existing_suffix_matching(tmp_path):
    path = _write(tmp_path, [[_result(file='file:///repo/src/A.java')]])
    assert filter_enforced_from_sarif(path, [_selector()]) == 1
