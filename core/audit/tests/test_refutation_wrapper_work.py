"""Wrapper refutations require the selected occurrence's source and calls."""

from copy import deepcopy

import pytest

from core.audit import refutation
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome


@pytest.fixture(autouse=True)
def owned_gate_caches(monkeypatch):
    monkeypatch.setattr(refutation, '_caller_map_cache', [])
    monkeypatch.setattr(refutation, '_signal_reachable_cache', [])
    monkeypatch.setattr(refutation, '_threading_seen_cache', {})


def outcome(line=20):
    return ReviewOutcome(file='record.cpp', function='read', line=line, status='finding', body='',
                         hypothesis='the function risky has a bug')


def checklist(second_source='int read(int n) { return other(); }'):
    return {'files': [{'path': 'record.cpp', 'items': [
        {'name': 'read', 'kind': 'function', 'line_start': 1, 'line_end': 5,
         'source': 'int read() { return risky(); }'},
        {'name': 'read', 'kind': 'function', 'line_start': 20, 'line_end': 40,
         'source': second_source},
    ], 'call_graph': {'calls': [
        {'caller': 'read', 'chain': ['risky'], 'line': 2},
        {'caller': 'read', 'chain': ['other'], 'line': 22},
    ]}}]}


def test_duplicate_name_uses_selected_source_and_scopes_calls():
    inventory = checklist()
    original = deepcopy(inventory)
    assert refutation._get_function_source_and_callees(outcome(), inventory) == (
        inventory['files'][0]['items'][1]['source'], ['other'],
    )
    assert refutation._get_function_source_and_callees(outcome(1), inventory) == (
        inventory['files'][0]['items'][0]['source'], ['risky'],
    )
    assert inventory == original


def test_another_occurrences_callee_cannot_refute_the_finding(tmp_path):
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')
    assert refutation.refute_hypothesis(outcome(), domain_model=None, checklist=checklist(), config=config) is None


def test_another_occurrences_thin_body_cannot_refute_the_finding(tmp_path):
    inventory = checklist('int read(int n) {\n' + '  calculate();\n' * 13 + '}')
    inventory['files'][0]['call_graph']['calls'][1]['chain'] = ['risky']
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')
    assert refutation.refute_hypothesis(outcome(), domain_model=None, checklist=inventory, config=config) is None


@pytest.mark.parametrize('line', [0, 9, 20.0, True])
def test_ambiguous_or_missing_source_occurrence_supplies_no_refutation_data(line):
    assert refutation._get_function_source_and_callees(outcome(line), checklist()) == ('', [])


@pytest.mark.parametrize('damage', ['missing-end', 'overlap', 'duplicate-start', 'missing-call-line'])
def test_incomplete_or_overlapping_occurrence_evidence_is_withheld(damage):
    inventory = checklist()
    file = inventory['files'][0]
    if damage == 'missing-end':
        del file['items'][0]['line_end']
    elif damage == 'overlap':
        file['items'][0]['line_end'] = 25
    elif damage == 'duplicate-start':
        file['items'][0]['line_start'] = 20
    else:
        del file['call_graph']['calls'][1]['line']
    source, callees = refutation._get_function_source_and_callees(outcome(), inventory)
    assert callees == []
    if damage == 'duplicate-start':
        assert source == ''


def test_unique_function_keeps_legacy_call_rows_without_line_numbers():
    inventory = checklist()
    file = inventory['files'][0]
    file['items'] = file['items'][:1]
    for call in file['call_graph']['calls']:
        del call['line']
    assert refutation._get_function_source_and_callees(outcome(), inventory) == (
        file['items'][0]['source'], ['risky', 'other'],
    )


def test_large_wrapper_candidate_stops_after_twelve_retained_lines(monkeypatch):
    actual = refutation.iter_splitlines
    consumed = []

    def bounded(text):
        for index, line in enumerate(actual(text)):
            if index >= 12:
                raise AssertionError('gate consumed a tail after exceeding its SLOC limit')
            consumed.append(line)
            yield line

    monkeypatch.setattr(refutation, 'iter_splitlines', bounded)
    source = 'int read() {\n' + '  work();\n' * 11 + 'x' * 1000000
    assert refutation._refute_by_callee_inheritance(outcome(), source, ['risky']) is None
    assert len(consumed) == 12


def test_unicode_display_separators_keep_the_existing_sloc_model():
    source = 'int read() {' + '\u2028work();' * 11 + '\u2028}'
    assert refutation._refute_by_callee_inheritance(outcome(), source, ['risky']) is None


def test_source_adapter_retains_its_strip_and_split_operations():
    calls = []

    class Adapter(str):
        def strip(self):
            calls.append('strip')
            return 'int read() { return risky(); }'

    verdict = refutation._refute_by_callee_inheritance(outcome(), Adapter('ignored'), ['risky'])
    assert verdict.gate == 'callee_inheritance'
    assert calls == ['strip']
