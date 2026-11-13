"""Binary context records narrow reuse without granting evidence authority."""
from dataclasses import replace

import pytest

from core.audit.binary_context_inputs import (
    binary_context_anchor, binary_context_bound, binary_context_record_digest,
    capture_binary_context_inputs,
)
from core.audit.context import format_context_for_prompt, _defend_identifier
from core.audit.continuation_context import context_spec, context_version
from core.audit.disagreement_review_context import render_disagreement_context
from core.audit.gaps import _fold_journal_into_covered, _verify_entries_fold
from core.audit.tests.test_binary_review_origin import binary_inputs as binary_inputs
from core.coverage import journal_mac
from core.coverage.journal import (
    CLEAN_BASIS_VERDICT, ReviewJournalEntry, append_entry, load_entries, merge_into_index, make_function_key,
)


def _current_plain_hash(origin):
    from core.audit.binary_review_scope import binary_view_anchor
    anchor = binary_view_anchor(origin.binary_identity)
    assert anchor is not None and anchor.startswith('bin:inputs3:')
    return anchor


@pytest.fixture
def subject(binary_inputs):
    target, runtime, context = binary_inputs
    ctx = context()
    origin = runtime._origin(ctx)
    ctx['disagreement_override'] = {'resolution': 'advisory independent review requested'}
    text = render_disagreement_context(ctx['disagreement_override'], defend_identifier=_defend_identifier)
    spec = context_spec(ctx, kind='disagreement', version=context_version(text))
    ctx['continuation_context_inputs'] = [spec]
    captured = []
    prompt = format_context_for_prompt(ctx, budget_limit=100000, external_delivery_sink=captured.append)
    assert text in prompt
    deliveries, = captured
    record = capture_binary_context_inputs(ctx, origin, deliveries)
    assert record is not None
    anchor = binary_context_anchor(origin, record)
    assert anchor is not None
    identity = origin.binary_identity
    plain = f'bin:{identity.module_sha256}:{identity.address:x}:{identity.size:x}'
    row = ReviewJournalEntry(ts='2026-11-13T01:00:00Z', run_id='owned', file=origin.file,
        function=origin.function, line_start=0, verdict='clean', source_hash=anchor,
        producer='audit', model='scripted', clean_basis=CLEAN_BASIS_VERDICT,
        review_claims={'version': 1, 'role': 'review-history-only', 'review': None,
                      'intakes': [], 'complete': False, 'omissions': [], 'binary_inputs': record})
    return target, origin, ctx, deliveries, row, plain


def _signed(path, row):
    append_entry(path, row)
    loaded, = load_entries(path, fresh=True)
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED
    return loaded


def test_actual_fitted_binary_advisory_record_has_separate_anchor_and_no_source_identity(subject):
    target, origin, ctx, deliveries, row, plain = subject
    record = row.review_claims['binary_inputs']
    assert record['origin']['source_identity'] is None
    assert record['origin']['binary_identity']['view_sha256'] == origin.binary_identity.view_sha256
    assert row.source_hash.startswith('bin:ctx1:') and row.source_hash != plain
    assert binary_context_record_digest(record) in row.source_hash
    assert capture_binary_context_inputs(ctx, origin, [{**deliveries[0], 'delivered': False}]) is None
    assert capture_binary_context_inputs(ctx, origin, [{**deliveries[0], 'version': '0'*64}]) is None
    assert capture_binary_context_inputs(ctx, origin, []) is None
    assert binary_context_anchor(replace(origin, pass_id='foreign'), record) is None


@pytest.mark.parametrize('context_in_project', [False, True])
@pytest.mark.parametrize('reuse', [False, True])
@pytest.mark.parametrize('damage', ['none', 'missing-history', 'missing-tag', 'unknown'])
def test_contextual_binary_review_blocks_older_other_source_credit(subject, tmp_path, context_in_project, reuse, damage):
    target, origin, ctx, deliveries, current, plain = subject
    old = replace(current, source_hash=_current_plain_hash(origin), review_claims=None, ts='2026-11-13T00:00:00Z')
    if damage == 'missing-history':
        current = replace(current, review_claims=None)
    elif damage == 'missing-tag':
        current = replace(current, source_hash=_current_plain_hash(origin))
    elif damage == 'unknown':
        current = replace(current, source_hash='bin:ctx99:unknown', review_claims=None)
    own, project = tmp_path/'own', tmp_path/'project'
    first, indexed = (old, current) if context_in_project else (current, old)
    _signed(own, first)
    _signed(project/'indexed', indexed)
    merge_into_index(project, project/'indexed')
    covered, credits, sink = set(), {}, {} if reuse else None
    _fold_journal_into_covered(covered, own, project, target_path=target, current_spans={},
        binary_hashes={make_function_key(origin.file, origin.function): plain},
        binary_view_hashes={make_function_key(origin.file, origin.function): _current_plain_hash(origin)}, credits=credits,
        reuse_sink=sink, own_run_reuse=reuse)
    assert not covered and not credits and not sink


def test_untrusted_context_cannot_invalidate_signed_plain_binary_review(subject, tmp_path):
    target, origin, ctx, deliveries, current, plain = subject
    trusted = _signed(tmp_path/'plain', replace(current, source_hash=_current_plain_hash(origin), review_claims=None,
                      ts='2026-11-13T00:00:00Z'))
    covered = set()
    _verify_entries_fold(covered, [trusted, current], target_path=target, current_spans={},
        binary_hashes={make_function_key(origin.file, origin.function):plain},
        binary_view_hashes={make_function_key(origin.file, origin.function): _current_plain_hash(origin)}, reuse_sink=None,
        current_strategies_fn=lambda *_:set(), current_model=None, source_label='owned')
    assert covered == {make_function_key(origin.file, origin.function)}


def test_binary_context_is_not_projected_into_existence_only_coverage(subject, tmp_path):
    from core.coverage.record import build_from_journal
    from core.coverage.journal import entry_earns_function_coverage
    target, origin, ctx, deliveries, current, plain = subject
    out = tmp_path/'run'
    row = _signed(out, current)
    assert not entry_earns_function_coverage(row)
    record = build_from_journal(out)
    assert record is not None and not record['functions_analysed']
    assert not entry_earns_function_coverage(replace(row, source_hash=_current_plain_hash(origin)))
    assert not entry_earns_function_coverage(replace(row, review_claims=None))
    assert binary_context_bound('', {'binary_inputs': None})


def test_current_plain_binary_review_and_later_independent_review_keep_credit(subject, tmp_path):
    target, origin, ctx, deliveries, current, plain = subject
    key = make_function_key(origin.file, origin.function)
    signed = _signed(tmp_path/'plain', replace(current, source_hash=_current_plain_hash(origin), review_claims=None))
    covered = set()
    _verify_entries_fold(covered, [signed], target_path=target, current_spans={},
        binary_hashes={key:plain}, binary_view_hashes={key:_current_plain_hash(origin)}, reuse_sink=None,
        current_strategies_fn=lambda *_:set(), current_model=None, source_label='owned')
    assert covered == {key}
    own, project = tmp_path/'own', tmp_path/'project'
    _signed(own, current)
    _signed(project/'later', replace(signed, ts='2026-11-13T02:00:00Z'))
    merge_into_index(project, project/'later')
    covered = set()
    _fold_journal_into_covered(covered, own, project, target_path=target, current_spans={},
                              binary_hashes={key:plain}, binary_view_hashes={key:_current_plain_hash(origin)})
    assert covered == {key}


@pytest.mark.parametrize('kind', [None, [], {}, 1, True])
def test_malformed_delivery_kind_is_refused_without_exception(subject, kind):
    target, origin, ctx, deliveries, current, plain = subject
    assert capture_binary_context_inputs(ctx, origin, [{**deliveries[0], 'kind':kind}]) is None


def test_history_intake_merge_and_panel_keep_binary_dependency_marker(subject):
    from copy import deepcopy
    from core.audit.review_claims import read_history, record_intake, merge_history, panel_context_history
    from core.audit.binary_context_inputs import merge_binary_context_inputs
    target, origin, ctx, deliveries, current, plain = subject
    history = current.review_claims
    record = history['binary_inputs']
    assert binary_context_anchor(origin, read_history(history)['binary_inputs']) == current.source_hash
    assert record_intake(history, [])['binary_inputs'] == merge_binary_context_inputs(record)
    merged = merge_history(None, history)
    assert merged['binary_inputs'] == merge_binary_context_inputs(record)
    assert panel_context_history(None, [{'review_claims':history}])['binary_inputs'] == merge_binary_context_inputs(record)
    for preserved in (record_intake(history, []), merged, panel_context_history(None, [{'review_claims':history}])):
        assert binary_context_anchor(origin, preserved['binary_inputs']) == current.source_hash
    other = deepcopy(record)
    other['origin']['pass_id'] = 'another-historical-pass'
    union = merge_binary_context_inputs(record, other)
    assert len(union['inputs']) == 2 and union['complete'] is True
    assert merge_binary_context_inputs(union) == union
    unknown = merge_binary_context_inputs(record, {})
    assert unknown['complete'] is False and len(unknown['inputs']) == 1
    assert merge_history(history, {'binary_inputs':None})['binary_inputs']['complete'] is False
    cyclic = deepcopy(record)
    cyclic['contexts'].append(cyclic)
    assert binary_context_record_digest(cyclic) is None


def test_external_signed_binary_context_projection_is_refused_by_importer(subject, tmp_path):
    from core.coverage.importer import import_functions_analysed
    from core.coverage.store import CoverageStore
    target, origin, ctx, deliveries, current, plain = subject
    projected = {'file':origin.file, 'function':origin.function, 'status':'clean', 'hash':current.source_hash}
    projected[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(projected, 'journal')
    assert journal_mac.coverage_row_provenance(projected, 'journal') == journal_mac.ROW_VERIFIED
    store = CoverageStore(tmp_path/'coverage.json', target='owned')
    assert import_functions_analysed(store, {'tool':'journal', 'functions_analysed':[projected]},
        {(origin.file, origin.function):(1,1)}, {origin.file}) == 0
    assert not store.who_checked(origin.file, 1)
