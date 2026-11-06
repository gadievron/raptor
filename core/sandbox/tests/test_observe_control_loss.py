"""Accepted control metadata preserves loss without inventing sampled drops."""
from contextlib import ExitStack
import json

import pytest

from core.sandbox import audit_budget, evidence, observe_profile as observe, seatbelt_audit as audit
from core.testing.state_isolation import pin_user_state_dirs


NONCE = 'owned-observation'
BUDGET_DROPS = ['category_budget_exceeded', 'pid_budget_exceeded', 'sampling_budget_exceeded']


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


def operation(path='/tmp/owned', nonce=NONCE, **fields):
    record = {'type': 'write', 'syscall': 'file-read-data', 'target_pid': 1234,
              'path': path, 'observe': True, **fields}
    if nonce is not None:
        record['nonce'] = nonce
    return record


def tail(**fields):
    return {'type': 'audit_summary', 'nonce': NONCE,
            'reader_failed': False, 'reader_drained': True,
            'dropped_by_category': {}, **fields}


def profile(run):
    return observe.parse_observe_log(run, expected_nonce=NONCE, current_run=True,
                                     sandbox_info={'nonce_delivery': 'in_process'})


def load(run, control):
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(mode=0o700, parents=True)
    records = [operation('/first'), control, operation('/last'), tail()]
    path.write_text(''.join(json.dumps(record) + '\n' for record in records))
    result = profile(run)
    assert result.paths_read == ['/first', '/last']
    assert result.nonce_trusted is True
    assert result.dropped_by_category == {}
    return result


@pytest.fixture
def owner_factory(tmp_path, request):
    cleanup = ExitStack()
    request.addfinalizer(cleanup.close)
    owners = []

    def make(*, global_cap=10, category_cap=10, pid_cap=20, sampling=0, nonce=NONCE):
        budget = audit_budget.AuditBudget(
            global_cap=global_cap, category_caps={'owned': category_cap}, pid_cap=pid_cap,
            refill_rates={'owned': 0}, sampling_rates={'owned': sampling},
            categorise=lambda action: 'owned', clock=lambda: 0.0)
        run = tmp_path / f'run-{len(owners)}'
        owner = audit.LogStreamer(run, budget=budget, observe_mode=True, observe_nonce=nonce)
        cleanup.callback(owner.stop)
        owners.append(owner)
        return owner, run
    return make


def records(run):
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize('kind', ['category', 'pid', 'sampling', 'sampling-limit', 'global', 'ambiguity'])
def test_real_producer_binds_control_markers_to_the_run(owner_factory, monkeypatch, kind):
    options = {
        'category': {'category_cap': 1},
        'pid': {'pid_cap': 1},
        'sampling': {'category_cap': 0, 'sampling': 2},
        'sampling-limit': {'global_cap': 1, 'category_cap': 0, 'sampling': 1},
        'global': {'global_cap': 1},
        'ambiguity': {},
    }[kind]
    owner, run = owner_factory(**options)
    if kind == 'ambiguity':
        monkeypatch.setattr(audit, '_AMBIGUOUS_ADMIT_MAX', 1)
    for _ in range(2):
        record = operation(**({'parse_ambiguous': True} if kind == 'ambiguity' else {}))
        before = dict(record)
        owner._filter_and_append(record)
        assert record == before
    owner.stop()
    output = records(run)
    markers = [row for row in output if row.get('type') != 'audit_summary' and 'syscall' not in row]
    assert markers
    assert all(row.get('nonce') == NONCE for row in markers)
    assert output[-1]['nonce'] == NONCE
    assert owner._evidence is None


@pytest.mark.parametrize('nonce', [None, 'foreign'], ids=['missing', 'foreign'])
def test_regular_record_nonce_is_not_upgraded(owner_factory, nonce):
    owner, run = owner_factory()
    owner._filter_and_append(operation(nonce=nonce))
    owner.stop()
    row = next(row for row in records(run) if 'syscall' in row)
    assert row.get('nonce') == nonce
    assert ('nonce' in row) is (nonce is not None)


def test_nonce_less_control_output_keeps_legacy_shape(owner_factory):
    owner, run = owner_factory(category_cap=1, nonce=None)
    for _ in range(2):
        owner._filter_and_append(operation(nonce=None))
    owner.stop()
    assert all('nonce' not in row for row in records(run))


def test_interrupted_capture_keeps_known_budget_loss(owner_factory):
    owner, run = owner_factory(category_cap=1)
    for _ in range(2):
        owner._filter_and_append(operation())
    result = profile(run)
    assert result.capture_incomplete is True  # no completion tail yet
    assert result.budget_truncated is True


def test_global_sampling_notice_without_drops_stays_complete(owner_factory):
    owner, run = owner_factory(global_cap=1, sampling=1)
    for _ in range(2):
        owner._filter_and_append(operation())
    owner.stop()
    assert any(row.get('type') == 'global_budget_exceeded' for row in records(run))
    result = profile(run)
    assert result.budget_truncated is False
    assert result.capture_incomplete is False


@pytest.mark.parametrize('kind', BUDGET_DROPS)
def test_guaranteed_drop_markers_survive_later_clean_tails(tmp_path, kind):
    result = load(tmp_path, {'type': kind, 'nonce': NONCE})
    assert result.budget_truncated is True
    assert result.capture_incomplete is False


@pytest.mark.parametrize('kind', ['global_budget_exceeded', 'category_budget_exceeded_sampling'])
def test_sampling_notices_do_not_manufacture_budget_drops(tmp_path, kind):
    result = load(tmp_path, {'type': kind, 'nonce': NONCE})
    assert result.budget_truncated is False
    assert result.capture_incomplete is False


@pytest.mark.parametrize('value', [1, True, False, -1, 0.0, 1.0, '1', None, [], {}],
                         ids=['positive', 'true', 'false', 'negative', 'float-zero',
                              'float-one', 'string', 'null', 'array', 'object'])
def test_ambiguity_drop_accounting_reasserts_incompleteness(tmp_path, value):
    result = load(tmp_path, tail(parse_ambiguous_records_dropped=value))
    assert result.capture_incomplete is True
    assert result.budget_truncated is False


@pytest.mark.parametrize('fields', [{}, {'parse_ambiguous_records_dropped': 0},
                                    {'parse_ambiguous_records': 200, 'foreign_records_dropped': 200}],
                         ids=['legacy', 'zero', 'foreign-ambiguity-total'])
def test_diagnostic_ambiguity_totals_are_not_capture_loss(tmp_path, fields):
    result = load(tmp_path, tail(**fields))
    assert result.capture_incomplete is False
    assert result.budget_truncated is False


def test_ambiguity_cap_marker_preserves_known_capture_loss(tmp_path):
    result = load(tmp_path, {'type': 'parse_ambiguous_cap_exceeded', 'nonce': NONCE})
    assert result.capture_incomplete is True
    assert result.budget_truncated is False


@pytest.mark.parametrize('kind', BUDGET_DROPS + ['parse_ambiguous_cap_exceeded', 'audit_summary'])
def test_foreign_nonce_cannot_claim_loss(tmp_path, kind):
    result = load(tmp_path, {'type': kind, 'nonce': 'foreign',
                             'parse_ambiguous_records_dropped': 1})
    assert result.budget_truncated is False
    assert result.capture_incomplete is False
