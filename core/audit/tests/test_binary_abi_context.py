import pytest
from core.audit.integer_abi_context import compare_integer_abi
from packages.binary_analysis.tests.test_macho_facts import build_fat, build_thin
from core.audit import integer_abi
from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config
from core.audit.tests.test_integer_abi_binary import _elf


def test_explicit_binary_override_records_contradictory_platform_facts(tmp_path):
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    detected = integer_abi.binary_integer_abi(target)
    assert detected is not None and detected.long_bits == 64
    opts = AuditPipelineOpts(target_path=target, out_dir=tmp_path / 'run', integer_abi='llp64')
    config = _build_orchestrator_config(opts, None, ['captured'], ReviewMode.SECURITY)
    selected = integer_abi.resolve_integer_abi(config.integer_abi)
    assert selected is not None and selected.long_bits == 32
    context = getattr(config, 'integer_abi_context', None)
    assert context is not None, 'explicit override lost its contradiction with known binary platform facts'
    assert context['status'] == 'contradictory'
    assert context['selected']['long_bits'] == 32
    assert context['binary_platform']['long_bits'] == 64
    assert context['contradicted_fields'] == ['long_bits']


def test_platform_change_during_comparison_remains_unknown(tmp_path, monkeypatch):
    from core.audit import integer_abi_context as consumer
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    original = consumer.binary_integer_abi
    def changed(path):
        answer = original(path)
        target.write_bytes(_elf(32, 3))
        return answer
    monkeypatch.setattr(consumer, 'binary_integer_abi', changed)
    record = consumer.compare_integer_abi('llp64', target_path=target)
    assert record['status'] == 'platform_unavailable'
    assert record['selected']['long_bits'] == 32
    assert record['binary_platform'] is None and record['module_sha256'] is None
    assert record['contradicted_fields'] == []
    assert record['reason'] == 'binary_changed_during_platform_comparison'


def test_source_directory_has_no_binary_platform_comparison(tmp_path):
    assert compare_integer_abi('lp64', target_path=tmp_path) is None


def test_unknown_selection_disables_assumptions_without_host_default(tmp_path, monkeypatch):
    from core.audit import integer_abi
    monkeypatch.setattr(integer_abi, 'host_integer_abi',
                        lambda: pytest.fail('unknown must not borrow analysis host ABI'))
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    result = compare_integer_abi('unknown', target_path=target)
    assert result['status'] == 'disabled'
    assert result['selected'] is None
    assert result['contradicted_fields'] == []
    assert result['role'] == 'conditional_assumption_not_verification_evidence'


@pytest.mark.parametrize('selected,status,long_bits,contradictions', [
    ('lp64', 'consistent', 64, []),
    ('llp64', 'contradictory', 32, ['long_bits']),
])
def test_explicit_integer_layout_compares_only_semantic_platform_fields(
    tmp_path, selected, status, long_bits, contradictions,
):
    target = tmp_path / 'program'
    image = _elf(64, 62)
    target.write_bytes(image)
    result = compare_integer_abi(selected, target_path=target)
    assert result['schema_version'] == 1
    assert result['role'] == 'conditional_assumption_not_verification_evidence'
    assert result['status'] == status
    assert result['selected']['long_bits'] == long_bits
    assert result['selected']['source'] == 'explicit'
    assert result['binary_platform']['long_bits'] == 64
    assert result['binary_platform']['source'] == 'binary-platform'
    assert result['contradicted_fields'] == contradictions
    from hashlib import sha256
    assert result['module_sha256'] == sha256(image).hexdigest()


def test_universal_image_keeps_platform_unknown_without_selecting_a_slice(tmp_path, monkeypatch):
    from core.audit import integer_abi
    monkeypatch.setattr(integer_abi, 'host_integer_abi',
                        lambda: pytest.fail('universal image must not borrow host ABI'))
    target = tmp_path / 'universal'
    target.write_bytes(build_fat([build_thin([]), build_thin([], bits=32, cputype=7)]))
    result = compare_integer_abi('lp64', target_path=target)
    assert result['status'] == 'platform_unavailable'
    assert result['selected']['long_bits'] == 64
    assert result['binary_platform'] is None
    assert result['contradicted_fields'] == []


def test_pipeline_records_each_binary_assumption_before_dispatch(tmp_path, monkeypatch):
    from core.audit import pipeline, llm_review, orchestrator
    from core.audit.record import load_verified_audit_log
    from core.llm import log_quiet
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    out = tmp_path / 'run'
    # The production pipeline's model/config setup is incidental here. No
    # renderer, client, provider, or orchestrator dispatch may execute.
    client = object()
    reviewer = object()
    result = object()
    monkeypatch.setattr(log_quiet, 'quiet_noisy_loggers', lambda: None)
    monkeypatch.setattr(pipeline, '_make_llm_client', lambda opts: (client, ['captured'], 'captured'))
    monkeypatch.setattr(llm_review, 'make_review_fn', lambda *a, **k: reviewer)
    observed = []
    def dispatch(config, review_fn, **kwargs):
        assert review_fn is reviewer
        rows = [row for row in load_verified_audit_log(out)
                if row.get('action') == 'integer_abi_context']
        assert rows, 'comparison must be durable before review dispatch'
        assert rows[-1]['context'] == config.integer_abi_context
        observed.append(rows[-1]['context']['status'])
        return result
    monkeypatch.setattr(orchestrator, 'run_orchestrator', dispatch)
    for selected in ('llp64', 'lp64'):
        opts = pipeline.AuditPipelineOpts(target_path=target, out_dir=out,
                                         integer_abi=selected, auto_siblings=False)
        assert pipeline.run_audit_pipeline(opts) is result
    assert observed == ['contradictory', 'consistent']
    rows = [row for row in load_verified_audit_log(out)
            if row.get('action') == 'integer_abi_context']
    assert len(rows) == 2
    assert rows[0]['context']['contradicted_fields'] == ['long_bits']
    assert rows[1]['context']['contradicted_fields'] == []
    assert all(row['context']['role'] == 'conditional_assumption_not_verification_evidence'
               for row in rows)


def test_changed_binary_does_not_receive_a_platform_contradiction_record(tmp_path, monkeypatch):
    from core.audit import integer_abi_context as consumer
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    original = consumer.binary_integer_abi
    parsed = []
    def parse_then_replace(path):
        platform = original(path)
        assert platform is not None and platform.long_bits == 64
        parsed.append(platform)
        path.write_bytes(_elf(32, 3))
        return platform
    monkeypatch.setattr(consumer, 'binary_integer_abi', parse_then_replace)
    result = compare_integer_abi('llp64', target_path=target)
    assert len(parsed) == 1
    assert result['status'] == 'platform_unavailable'
    assert result['reason'] == 'binary_changed_during_platform_comparison'
    assert result['selected']['long_bits'] == 32
    assert result['binary_platform'] is None and result['module_sha256'] is None
    assert result['contradicted_fields'] == []
