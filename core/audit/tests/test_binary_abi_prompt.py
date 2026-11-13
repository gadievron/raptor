import pytest
from hashlib import sha256
from core.audit import binary_context
from core.audit.tests.test_binary_review_availability import _reviewer
from core.audit.tests.test_integer_abi_binary import _elf
from core.audit.orchestrator import _build_context
from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config
from core.inventory.binary_builder import build_binary_checklist
from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def binary_abi_case(tmp_path, monkeypatch):
    target = tmp_path / 'program'
    image = _elf(64, 62)
    target.write_bytes(image)
    database = REDatabase(source_tool='fixture', binary_path=str(target),
        metadata={'binary_sha256': sha256(image).hexdigest()},
        functions=[REFunction(name='f', address=4096, size=32, source_tool='fixture',
                              decompilation='long f(long n) { return n + 1; }')])
    monkeypatch.setattr(binary_context, 'find_redb_snapshot', lambda *args: (tmp_path / 'captured.json', database))
    monkeypatch.setattr(binary_context, '_lazy_decompile',
                        lambda *args, **kwargs: pytest.fail('ABI context test dispatched a backend'))
    import core.inventory.binary_builder as builder
    # Incidental build/provenance inspection is explicitly unavailable here.
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    checklist = build_binary_checklist(database, binary_path=target)
    entry = checklist['files'][0]
    gap = {**entry['items'][0], 'file': entry['path'], 'line_start': 0, 'line_end': None}
    def build(selection):
        opts = AuditPipelineOpts(target_path=target, out_dir=tmp_path / 'run', integer_abi=selection)
        config = _build_orchestrator_config(opts, None, ['captured'], ReviewMode.SECURITY)
        config.enable_session_context = False
        return _build_context(config, gap, checklist, None), config
    return build, target


@pytest.mark.parametrize("bucket", [None, "glance"])
def test_explicit_counterfactual_layout_is_disclosed_to_actual_binary_reviewer(binary_abi_case, bucket):
    build, target = binary_abi_case
    ctx, config = build('llp64')
    if bucket is not None:
        ctx['triage_bucket'] = bucket
    review, calls = _reviewer()
    assert review(ctx, config).status == 'clean'
    assert len(calls) == 1
    prompt = calls[0][0]
    assert 'Selected integer-layout assumptions' in prompt, 'binary review omitted operator-selected conditional ABI'
    assert 'contradictory' in prompt and 'long_bits' in prompt
    assert 'not verification evidence' in prompt


def test_same_binary_view_under_different_integer_assumptions_has_distinct_input_identity(binary_abi_case):
    from core.audit.binary_review_scope import capture_binary_publication_scope
    build, target = binary_abi_case
    contexts = [build(selection)[0] for selection in (None, 'llp64', 'unknown')]
    scopes = [capture_binary_publication_scope(ctx, ctx['_binary_module_snapshot']) for ctx in contexts]
    assert all(scope is not None and scope.current(target) for scope in scopes)
    identities = [scope.view_identity for scope in scopes]
    assert len({identity.view_sha256 for identity in identities}) == 1
    assert len({identity.analysis_sha256 for identity in identities}) == 1
    assert len({identity.threat_model_sha256 for identity in identities}) == 1
    assert len({identity.integer_abi_sha256 for identity in identities}) == 3
    assert len({scope.anchor() for scope in scopes}) == 3
    assert all(scope.anchor().startswith('bin:inputs3:') for scope in scopes)


@pytest.mark.parametrize('change', ['material', 'lost_owner', 'wrong_target'])
def test_original_abi_scope_cannot_adopt_replaced_material(binary_abi_case, change):
    from core.audit.binary_review_scope import capture_binary_publication_scope
    from core.audit.knowledge_calls import KnowledgeCallRefused
    build, target = binary_abi_case
    ctx, config = build('llp64')
    scope = capture_binary_publication_scope(ctx, ctx['_binary_module_snapshot'])
    assert scope is not None and scope.current(target)
    if change == 'material':
        ctx['integer_abi_context']['selected']['long_bits'] = 64
    elif change == 'lost_owner':
        ctx['_binary_integer_abi_owner'] = {'material': ctx['integer_abi_context']}
    else:
        from core.audit.binary_integer_inputs import capture_binary_integer_context
        other = target.with_name('different-target')
        other.write_bytes(target.read_bytes())
        owner = capture_binary_integer_context('llp64', target_path=other)
        assert owner is not None and owner.current(owner.material)
        ctx['_binary_integer_abi_owner'] = owner
        ctx['integer_abi_context'] = owner.material
    assert not scope.current(target)
    review, calls = _reviewer()
    with pytest.raises(KnowledgeCallRefused, match='binary_integer_abi_context_changed'):
        review(ctx, config)
    assert calls == []


def test_immutable_abi_material_cannot_be_replaced_or_coerced(tmp_path):
    from core.audit.binary_integer_inputs import capture_binary_integer_context
    target = tmp_path / 'program'
    target.write_bytes(_elf(64, 62))
    owner = capture_binary_integer_context('llp64', target_path=target)
    assert owner is not None and owner.current(owner.material)
    changed = owner.material
    changed['selected']['long_bits'] = 64
    assert owner.material['selected']['long_bits'] == 32
    assert not owner.current(changed)
    class Unowned:
        def __str__(self):
            pytest.fail('unowned objects must not be coerced into ABI material')
    changed['selected'] = Unowned()
    assert not owner.current(changed)
    unknown = capture_binary_integer_context('unknown', target_path=target)
    assert unknown is not None and unknown.material['status'] == 'disabled'
    assert unknown.digest != owner.digest
    assert 'not verification evidence' in owner.render()
