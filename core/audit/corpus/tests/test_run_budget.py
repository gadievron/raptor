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


@pytest.mark.parametrize('flag', ['--max-cost', '--max-time', '--max-group-cost'])
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
