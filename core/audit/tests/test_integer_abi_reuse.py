"""A source hash alone cannot reauthorize a target-dependent integer disproof."""

import pytest

from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
from core.audit.tests.test_verdict_reuse import _entry, _write_target


@pytest.mark.parametrize("receipts,body", [
    pytest.param(["smt:disproof:unsat"], "review", id="disproof-receipt"),
    pytest.param(["smt:check-overflow"], "review", id="overflow-receipt"),
    pytest.param([], "[smt-disproof: integer overflow impossible (Z3 UNSAT)]\nreview", id="legacy-body-marker"),
])
def test_integer_clean_requires_fresh_target_context(tmp_path, receipts, body):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=receipts, body=body, clean_basis="verdict")
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "integer disproof requires target ABI revalidation"
    assert _reuse_block_class(reason) == "integer_abi_unbound"


def test_other_clean_verdicts_keep_existing_reuse_policy(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=[], body="review", clean_basis="verdict")
    assert _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None) is None


STAMP = '[smt-disproof: integer overflow impossible (Z3 UNSAT)]\n'
LEAD = '[reused: verdict imported from run older; source hash unchanged]\n\n'
ABI_SOURCE = ('long Read(long Count, int Step) { '
              'if(Count >= 0 && Count <= 2147483647 && Step >= 0 && Step <= 1) '
              'return Count + Step; return 0; }\n')
HYPOTHESIS = 'integer overflow in `Count + Step`'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant'])
@pytest.mark.parametrize('leads', [0, 1, 2])
def test_disproof_body_requires_revalidation_behind_every_reuse_lead(tmp_path, verdict, leads):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, body=LEAD * leads + STAMP + 'LP64 proof', clean_basis='verdict')
    reason = _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None)
    assert reason == 'integer disproof requires target ABI revalidation'
    assert _reuse_block_class(reason) == 'integer_abi_unbound'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant'])
def test_structured_negative_disproof_receipt_needs_no_body_read(tmp_path, verdict):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, body='', evidence_tools=['semgrep:lead + smt:disproof:unsat'],
                   clean_basis='verdict', body_offload={
                       'sidecar': '', 'offset': 0, 'bytes': 0, 'sha256': '0' * 64, 'fields': ['body'],
                   })

    def forbidden(_entry):
        pytest.fail('the receipt already establishes that target-context revalidation is required')
    reason = _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None,
                                  current_model=None, hydrate_fn=forbidden)
    assert reason == 'integer disproof requires target ABI revalidation'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant', 'finding'])
def test_plain_reviews_and_prose_quotes_keep_reuse_policy(tmp_path, verdict):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, body='Reviewed: the old ' + STAMP + 'is not applicable.', clean_basis='verdict')
    assert _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None) is None


def test_positive_finding_is_not_treated_as_a_negative_integer_proof(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict='finding', body=STAMP + 'new positive evidence', evidence_tools=['smt:disproof:unsat'])
    assert _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None) is None


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant'])
@pytest.mark.parametrize('storage', ['inline', 'wrapped', 'offloaded'])
def test_real_journal_cannot_reuse_lp64_disproof_under_another_abi(tmp_path, verdict, storage):
    pytest.importorskip('tree_sitter_c')
    pytest.importorskip('z3')
    from core.audit.condition_smt import disprove_integer_overflow
    from core.audit.gaps import compute_gaps
    from core.audit.overflow_demotion import source_overflow_demotion_reason
    from core.audit.strategy import strategies_from_item
    from core.audit.tests.test_verdict_reuse import _gap_keys, _project_with
    from core.coverage.journal import ReviewJournalEntry, _INDEX_SLIM_MIN_BYTES, load_index, now_iso
    from core.staleness import hash_span

    proof = source_overflow_demotion_reason(HYPOTHESIS, ABI_SOURCE, file_path='record.c',
                                            function_name='Read', integer_abi='lp64')
    assert proof == STAMP.rstrip()
    current = disprove_integer_overflow(HYPOTHESIS, ABI_SOURCE, file_path='record.c',
                                       function_name='Read', integer_abi='ilp32')
    assert current.disproved is False
    assert current.witness['Count'] + current.witness['Step'] > (1 << 31) - 1

    target = tmp_path / 'abi-target'
    target.mkdir()
    (target / 'record.c').write_text(ABI_SOURCE)
    item = {'name': 'Read', 'kind': 'function', 'line_start': 1, 'line_end': 1}
    body = (LEAD if storage == 'wrapped' else '') + proof + '\nLP64 proof'
    if storage == 'offloaded':
        body += ' source proof context' * (_INDEX_SLIM_MIN_BYTES // 10 + 1)
    entry = ReviewJournalEntry(ts=now_iso(), run_id='run1', file='record.c', function='Read',
                               verdict=verdict, body=body, clean_basis='verdict', model='model-a',
                               source_hash=hash_span(target / 'record.c', 1, 1), line_start=1, line_end=1,
                               strategies=sorted(strategies_from_item(item, 'record.c')))
    project = _project_with(tmp_path, entry)
    stored = load_index(project)['record.c:Read']
    if storage == 'offloaded' and verdict in {'clean', 'dormant'}:
        assert stored.body == '' and stored.body_offload
    checklist = {'target_path': str(target), 'files': [
        {'path': 'record.c', 'language': 'c', 'items': [item]},
    ]}
    sink, stats = {}, {}
    gaps = compute_gaps(checklist, [], project_dir=project, reuse_sink=sink,
                        reuse_stats=stats, current_model='model-a')
    assert 'record.c:Read' in _gap_keys(gaps)
    assert 'record.c:Read' not in sink
    assert stats['record.c:Read'] == 'integer_abi_unbound'
