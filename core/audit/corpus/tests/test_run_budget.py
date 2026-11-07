"""Whole-run limits count infrastructure spend and never fabricate clean rows."""

import json
from types import SimpleNamespace

import pytest

from core.audit.corpus import run_corpus as runner
from core.audit.corpus.tests.test_run_corpus import _mk_label, _stub_main_run, _result_row


def test_spend_uses_telemetry_and_fences_next_group(tmp_path, monkeypatch):
    seen = []
    for name in ('r1', 'r2'):
        (tmp_path / name).mkdir()
    def target(path, labels, **kwargs):
        seen.append(labels[0].source.repo)
        out = tmp_path / 'out'
        out.mkdir()
        (out / 'llm-telemetry.jsonl').write_text(json.dumps({
            'event': 'call', 'call_class': 'study', 'cost_usd': 2.5}) + '\n')
        return {'a.c:f': {'status': 'clean', 'cost_usd': 0.001}}, {}, out
    monkeypatch.setattr(runner, '_run_audit_on_target', target)
    budget = runner.CorpusBudget(max_cost=2)
    rows, _ = runner._run_audit([_mk_label(repo='r1'), _mk_label(fid='a.c:g', repo='r2')],
                                {k: tmp_path / k for k in ('r1', 'r2')},
                                joern_server=object(), run_budget=budget)
    assert seen == ['r1']
    assert budget.spent == 2.5
    assert rows[-1]['actual'] == 'error'
    assert rows[-1]['error_reason'] == 'not_reviewed:cost_budget_exhausted'


def test_deadline_stops_before_preparation(tmp_path, monkeypatch):
    budget = runner.CorpusBudget(max_seconds=1)
    budget.deadline = 0
    monkeypatch.setattr(runner, '_run_audit_on_target', lambda *a, **k: pytest.fail('prep started'))
    rows, _ = runner._run_audit([_mk_label()], {'test': tmp_path}, joern_server=object(), run_budget=budget)
    assert rows[0]['actual'] == 'error'
    assert rows[0]['error_reason'] == 'not_reviewed:wall_budget_exhausted'


def test_no_telemetry_fails_closed_for_cost_limited_run(tmp_path):
    budget = runner.CorpusBudget(max_cost=2)
    budget.observe(tmp_path)
    assert budget.stop_reason() == 'spend_ledger_unavailable'


def test_group_cap_and_remaining_total_both_apply():
    budget = runner.CorpusBudget(max_cost=3, group_cap=1.2)
    assert budget.group_cost_limit(10) == 1.2
    budget.spent = 2.5
    assert budget.group_cost_limit(10) == 0.5


def test_checklist_time_counts_and_prevents_llm_setup(tmp_path, monkeypatch):
    import core.audit.pipeline as pipeline
    budget = runner.CorpusBudget(max_seconds=60)
    def checklist(*args):
        budget.deadline = 0
    monkeypatch.setattr(runner, '_build_checklist', checklist)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', lambda *a: pytest.fail('LLM setup ran'))
    assert runner._run_audit_on_target(tmp_path, [_mk_label()], out_dir=tmp_path/'out', run_budget=budget)[:2] == ({}, {})


def test_limits_and_static_mode_reach_pipeline(tmp_path, monkeypatch):
    import core.audit.pipeline as pipeline
    captured = []
    monkeypatch.setattr(runner, '_build_checklist', lambda *a: True)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', lambda opts: captured.append(opts))
    budget = runner.CorpusBudget(max_cost=3, max_seconds=60, group_cap=1.2)
    runner._run_audit_on_target(tmp_path, [_mk_label()], out_dir=tmp_path/'out',
                                run_budget=budget, static_only=True)
    opts = captured[0]
    assert opts.max_cost_usd == 1.2
    assert 0 < opts.max_seconds <= 60
    assert opts.study_concept_seeding is False
    assert opts.automatic_witnesses is False
    assert opts.dynamic_validation is False and opts.repo_trusted is False


@pytest.mark.parametrize('flag', ['--max-cost', '--max-time', '--max-group-cost', '--max-group-time'])
@pytest.mark.parametrize('value', ['0', '-1', 'nan', 'inf'])
def test_invalid_limits_rejected_before_work(flag, value):
    with pytest.raises(SystemExit) as error:
        runner.main([flag, value])
    assert error.value.code == 2


def test_cli_metadata_and_limits_are_reproducible(tmp_path, monkeypatch):
    captured = []
    def audit(labels, sources, **kwargs):
        captured.append(kwargs)
        return [{**_result_row(), 'model': ''}], []
    rc, output, _ = _stub_main_run(tmp_path, monkeypatch, audit_stub=audit,
        argv=['--max-cost', '3', '--max-time', '900', '--max-group-cost', '1.2', '--static-only', '--max-workers', '1'])
    assert rc == 0
    budget = captured[0]['run_budget']
    assert budget.max_cost == 3 and budget.group_cap == 1.2
    assert captured[0]['static_only'] and captured[0]['max_workers'] == 1
    meta = json.loads(output.read_text())['meta']
    assert meta['max_cost_usd'] == 3 and meta['max_seconds'] == 900
    assert meta['static_only'] and meta['max_group_cost_usd'] == 1.2


def test_static_mode_bypasses_all_automatic_dark_witness_work():
    from core.audit import orchestrator as orch
    config = SimpleNamespace(automatic_witnesses=False)
    assert orch._submit_dark_probes_early(None, config, llm_client=object()) == ([], [], None)
    assert orch._run_dark_verification(None, config, llm_client=object()) is None


def test_disabled_prep_seeding_cannot_start_a_private_llm_client(tmp_path, monkeypatch):
    from core.concepts.tests.test_study_prep_scoping import _load_prep, _PREP_PATH
    from core.concepts.tests._study_cli import run_study_main
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'unit.c').write_text('struct token { int value; };\nint parse_token(int x) { return x; }\n')
    def load():
        module = _load_prep()
        def paid(*args, **kwargs):
            pytest.fail('isolated concept seeding would bypass the run budget')
        monkeypatch.setattr(module, '_llm_seed_concepts', paid)
        monkeypatch.setattr(module, '_llm_seed_concepts_from_names', paid)
        return module
    result = run_study_main(load, _PREP_PATH, [str(source), str(tmp_path/'out'),
        '--root', str(source), '--concept', 'token lifecycle', '--no-concept-seeding', '--threads', '1'])
    assert result.returncode == 0, result.stderr
    assert 'semantic concept seeding disabled' in result.stdout


def test_prep_cache_cannot_cross_concept_seeding_policy():
    from core.concepts.tests.test_study_prep_scoping import _load_prep
    module = _load_prep()
    parsed = SimpleNamespace(identifier=None, concept=None, correlate=None, narrow=False,
                             redb=None, bridge_seed_file=None, reading_list=None,
                             no_concept_seeding=False)
    normal = module._scope_fingerprint(parsed)
    parsed.no_concept_seeding = True
    assert module._scope_fingerprint(parsed) != normal


@pytest.fixture
def group_clock(monkeypatch):
    import time as real_time

    class Clock:
        now = 100.0

        def monotonic(self):
            return self.now

        def __getattr__(self, name):
            return getattr(real_time, name)

    clock = Clock()
    # Replace only the corpus module's binding, not shared time.monotonic.
    monkeypatch.setattr(runner, 'time', clock)
    return clock


@pytest.mark.parametrize('total,group,elapsed,remaining', [
    (None, 10, 2, 8),
    (5, 10, 2, 3),
    (50, 10, 2, 8),
    (None, None, 2, None),
])
def test_group_window_is_bounded_by_remaining_whole_run(
    group_clock, total, group, elapsed, remaining,
):
    budget = runner.CorpusBudget(max_seconds=total, max_group_seconds=group)
    budget.begin_group()
    group_clock.now += elapsed
    assert budget.group_remaining_seconds() == remaining


def test_group_expiry_does_not_reset_or_exhaust_whole_budget(group_clock):
    budget = runner.CorpusBudget(max_seconds=15, max_group_seconds=10)
    budget.begin_group()
    group_clock.now += 11
    assert budget.group_dispatch_stop_reason() == 'group_wall_budget_exhausted'
    assert budget.stop_reason() == ''
    budget.begin_group()
    assert budget.group_stop_reason == ''
    assert budget.group_remaining_seconds() == 4
    group_clock.now += 4
    assert budget.group_dispatch_stop_reason() == 'wall_budget_exhausted'


def test_checklist_consumes_group_window_before_pipeline_setup(
    tmp_path, monkeypatch, group_clock,
):
    import core.audit.pipeline as pipeline

    def checklist(*_args):
        group_clock.now += 11

    monkeypatch.setattr(runner, '_build_checklist', checklist)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', lambda *_a: pytest.fail('pipeline started'))
    budget = runner.CorpusBudget(max_seconds=100, max_group_seconds=10)
    assert runner._run_audit_on_target(
        tmp_path, [_mk_label()], out_dir=tmp_path/'out', run_budget=budget,
    )[:2] == ({}, {})
    assert budget.group_stop_reason == 'group_wall_budget_exhausted'
    assert budget.stop_reason() == ''


def test_pipeline_receives_time_left_after_checklist(tmp_path, monkeypatch, group_clock):
    import core.audit.pipeline as pipeline

    captured = []

    def checklist(*_args):
        group_clock.now += 3

    monkeypatch.setattr(runner, '_build_checklist', checklist)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', lambda opts: captured.append(opts))
    budget = runner.CorpusBudget(max_seconds=100, max_group_seconds=10)
    runner._run_audit_on_target(
        tmp_path, [_mk_label()], out_dir=tmp_path/'out', run_budget=budget,
    )
    assert captured[0].max_seconds == 7


@pytest.mark.parametrize('total,group,first_limit,second_runs,termination', [
    (30, 10, 10, True, 'max_seconds'),
    (5, 10, 5, False, 'max_seconds'),
    (None, 10, 10, True, 'max_seconds'),
    (30, 10, 10, True, 'complete'),
    (30, 10, 10, True, 'llm_budget_exceeded'),
])
def test_group_stop_keeps_missing_labels_errors_and_preserves_later_groups(
    tmp_path, monkeypatch, group_clock, total, group, first_limit, second_runs, termination,
):
    import core.audit.pipeline as pipeline

    sources = {name: tmp_path/name for name in ('r1', 'r2')}
    for source in sources.values():
        source.mkdir()
    limits = []

    def audit(opts):
        limits.append(opts.max_seconds)
        if opts.out_dir.name == 'r1':
            group_clock.now += opts.max_seconds
            return SimpleNamespace(terminated_by=termination)
        return SimpleNamespace(terminated_by='complete')

    monkeypatch.setattr(runner, '_build_checklist', lambda *_args: True)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', audit)
    monkeypatch.setattr(runner, '_load_inventoried_functions', lambda _out: {('a.c', 'f')})
    monkeypatch.setattr(runner, '_parse_audit_log_outcomes', lambda path: (
        ({'a.c:f': {'status': 'clean', 'cost_usd': 0, 'duration_s': 0}}
         if path.parent.name == 'r2' else {}), {},
    ))
    budget = runner.CorpusBudget(max_seconds=total, max_group_seconds=group)
    rows, _ = runner._run_audit(
        [_mk_label(repo='r1'), _mk_label(repo='r2')], sources,
        out_dir=tmp_path/'out', joern_server=object(), triage=True, run_budget=budget,
    )
    assert limits == ([first_limit, group] if second_runs else [first_limit])
    assert rows[0]['actual'] == 'error'
    reason = ('wall_budget_exhausted' if not second_runs else
              'llm_budget_exceeded' if termination == 'llm_budget_exceeded' else
              'group_wall_budget_exhausted')
    assert rows[0]['error_reason'] == f'not_reviewed:{reason}'
    assert rows[1]['actual'] == ('clean' if second_runs else 'error')


def test_group_time_cli_is_recorded_in_metadata_history_and_wall_stamp(tmp_path, monkeypatch):
    captured = []

    def audit(_labels, _sources, **kwargs):
        wall = json.loads((tmp_path/'run'/'wall-segments.json').read_text())
        captured.append((kwargs['run_budget'], wall['stamp']))
        return [{**_result_row(), 'model': ''}], []

    rc, output, history = _stub_main_run(
        tmp_path, monkeypatch, audit_stub=audit,
        argv=['--out', str(tmp_path/'run'), '--max-group-time', '17'],
    )
    assert rc == 0
    assert captured[0][0].max_group_seconds == 17
    meta = json.loads(output.read_text())['meta']
    assert meta['max_group_seconds'] == 17
    assert captured[0][1]['max_group_time'] == 17
    records = [json.loads(line) for line in history.read_text().splitlines()]
    header = next(row for row in records if row['record'] == 'run')
    assert header['config']['max_group_seconds'] == 17


def test_group_time_is_rejected_in_probe_mode():
    with pytest.raises(SystemExit) as error:
        runner.main(['--probe', '--max-group-time', '10'])
    assert error.value.code == 2


def test_group_time_change_invalidates_group_checkpoint(tmp_path, monkeypatch, group_clock):
    source = tmp_path/'source'
    source.mkdir()
    calls = []

    def audit(_source, _labels, **_kwargs):
        calls.append(True)
        return {'a.c:f': {'status': 'clean', 'cost_usd': 0, 'duration_s': 0}}, {}, None

    monkeypatch.setattr(runner, '_run_audit_on_target', audit)
    checkpoint = tmp_path/'checkpoint.json'
    for seconds in (10, 10, 20):
        runner._run_audit(
            [_mk_label()], {'test': source}, joern_server=object(), checkpoint=checkpoint,
            run_budget=runner.CorpusBudget(max_group_seconds=seconds),
        )
    assert len(calls) == 2
    assert json.loads(checkpoint.read_text())['stamp']['max_group_time'] == 20


def test_mechanical_timeout_with_cost_cap_can_continue_and_resume(
    tmp_path, monkeypatch, group_clock,
):
    import core.audit.pipeline as pipeline

    sources = {name: tmp_path/name for name in ('r1', 'r2')}
    for path in sources.values():
        path.mkdir()
    calls = []

    def checklist(target, _out):
        if target.name == 'r1':
            group_clock.now += 11
        return True

    def audit(opts):
        calls.append(opts.out_dir.name)
        assert opts.max_cost_usd == 3
        (opts.out_dir/'llm-telemetry.jsonl').write_text(json.dumps({
            'event': 'call', 'call_class': 'review', 'cost_usd': 0.5,
        }) + '\n')
        return SimpleNamespace(terminated_by='complete')

    monkeypatch.setattr(runner, '_build_checklist', checklist)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', audit)
    monkeypatch.setattr(runner, '_load_inventoried_functions', lambda _out: {('a.c', 'f')})
    monkeypatch.setattr(runner, '_parse_audit_log_outcomes', lambda path: (
        {'a.c:f': {'status': 'clean', 'cost_usd': 0.5, 'duration_s': 0}}, {},
    ))
    checkpoint = tmp_path/'checkpoint.json'
    for _invocation in range(2):
        budget = runner.CorpusBudget(max_cost=3, max_seconds=100, max_group_seconds=10)
        rows, _ = runner._run_audit(
            [_mk_label(repo='r1'), _mk_label(repo='r2')], sources,
            out_dir=tmp_path/'out', joern_server=object(), checkpoint=checkpoint,
            run_budget=budget,
        )
        assert rows[0]['error_reason'] == 'not_reviewed:group_wall_budget_exhausted'
        assert rows[1]['actual'] == 'clean'
        assert budget.accounted and budget.spent == 0.5
        # Only the completed group has a ledger that can support resume.
        assert set(json.loads(checkpoint.read_text())['groups']) == {'r2'}
    assert calls == ['r2']


def test_pipeline_failure_without_ledger_still_blocks_later_groups(
    tmp_path, monkeypatch, group_clock,
):
    import core.audit.pipeline as pipeline

    sources = {name: tmp_path/name for name in ('r1', 'r2')}
    for path in sources.values():
        path.mkdir()
    calls = []

    def audit(opts):
        calls.append(opts.out_dir.name)
        raise RuntimeError('request may have happened before failure')

    monkeypatch.setattr(runner, '_build_checklist', lambda *_args: True)
    monkeypatch.setattr(pipeline, 'run_audit_pipeline', audit)
    monkeypatch.setattr(runner, '_load_inventoried_functions', lambda _out: {('a.c', 'f')})
    budget = runner.CorpusBudget(max_cost=3, max_seconds=100, max_group_seconds=10)
    rows, _ = runner._run_audit(
        [_mk_label(repo='r1'), _mk_label(repo='r2')], sources,
        out_dir=tmp_path/'out', joern_server=object(), triage=True, run_budget=budget,
    )
    assert calls == ['r1']
    assert not budget.accounted
    assert all(row['actual'] == 'error' for row in rows)
    assert all(row['error_reason'] == 'not_reviewed:spend_ledger_unavailable' for row in rows)
