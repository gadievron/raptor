"""Qualified field hints must bind to visible owner/member study input."""

from dataclasses import asdict

import pytest

from core.audit.condition_smt import DomainVocabulary
from core.audit.protocol_state import learned_state_fields
from core.concepts.model import DomainModel, StudyItem
from core.concepts.receipts import TIER_LLM_SUMMARIZED, TIER_MECHANICAL
from core.concepts.study import _assemble_vocabulary, _parse_api_vocabulary


def _struct(**overrides):
    values = {
        'id': 'struct_auth_context', 'kind': 'struct', 'name': 'auth_context',
        'file': 'auth.c', 'fields': ['authenticated', 'permissions'],
    }
    values.update(overrides)
    return StudyItem(**values)


def _response(name, **state):
    return {'api_vocabulary': {
        'security_fields': [{'name': name, 'why': 'authorization state'}],
        'state_fields': [{'field': name, 'authority': 'local', **state}],
    }}


def test_visible_qualified_field_survives_persistence_and_consumers(tmp_path):
    discarded = []
    entries = _parse_api_vocabulary(
        _response('auth_context.authenticated'), [_struct()], discarded,
    )
    assert not discarded
    security = [e for e in entries if e['class'] == 'security_fields']
    state = [e for e in entries if e['class'] == 'state_fields']
    assert security[0]['name'] == 'authenticated'
    assert state[0]['field'] == 'authenticated'
    assert state[0]['struct'] == 'auth_context'
    assert all(e['provenance'] == TIER_LLM_SUMMARIZED for e in entries)

    assembled = _assemble_vocabulary(entries)
    model = DomainModel(target='source/', security_fields=assembled[3], state_fields=assembled[6])
    path = tmp_path / 'domain-model.json'
    model.save(path)
    loaded = asdict(DomainModel.load(path))
    assert 'authenticated' in DomainVocabulary.from_domain_model(loaded).security_fields
    learned = learned_state_fields(loaded)
    assert learned['authenticated']['struct'] == 'auth_context'
    assert learned['authenticated']['provenance'] == TIER_LLM_SUMMARIZED


@pytest.mark.parametrize('name', [
    pytest.param('missing.authenticated', id='unknown-owner'),
    pytest.param('auth_context.missing', id='unknown-member'),
    pytest.param('auth_context->authenticated', id='pointer-expression'),
    pytest.param('auth_context.nested.authenticated', id='nested-unbound-member'),
    pytest.param('auth_context.authenticated()', id='call-expression'),
    pytest.param('auth_context.authenticated\n@script:python@', id='rule-syntax'),
])
def test_unsupported_or_unbound_qualified_fields_are_discarded(name):
    discarded = []
    assert _parse_api_vocabulary(_response(name), [_struct()], discarded) == []
    assert {e['kind'] for e in discarded} == {'vocab:security_fields', 'vocab:state_fields'}
    assert all(e['id'] == name for e in discarded)


def test_owner_and_member_tokens_in_different_structs_do_not_bind():
    items = [_struct(fields=['permissions']), _struct(name='other', fields=['authenticated'])]
    assert _parse_api_vocabulary(_response('auth_context.authenticated'), items) == []


def test_comment_prose_does_not_establish_a_struct_field():
    item = _struct(fields=['permissions'], doc_comment='auth_context.authenticated is a useful idea')
    assert _parse_api_vocabulary(_response('auth_context.authenticated'), [item]) == []


def test_function_named_like_owner_does_not_establish_a_struct_field():
    item = _struct(kind='function')
    assert _parse_api_vocabulary(_response('auth_context.authenticated'), [item]) == []


def test_fields_outside_prompt_limit_do_not_bind():
    item = _struct(fields=[f'field_{n}' for n in range(30)] + ['authenticated'])
    assert _parse_api_vocabulary(_response('auth_context.authenticated'), [item]) == []


def test_qualified_state_owner_cannot_contradict_explicit_struct():
    entries = _parse_api_vocabulary(
        _response('auth_context.authenticated', struct='other'), [_struct()],
    )
    assert {e['class'] for e in entries} == {'security_fields'}


def test_normalization_does_not_upgrade_authority_classification():
    item = _struct(state_transitions=['authenticated: 0 -> 1'])
    bare = _parse_api_vocabulary(_response('authenticated'), [item])
    qualified = _parse_api_vocabulary(_response('auth_context.authenticated'), [item])
    bare_state = next(e for e in bare if e['class'] == 'state_fields')
    qualified_state = next(e for e in qualified if e['class'] == 'state_fields')
    assert bare_state['provenance'] == TIER_MECHANICAL
    assert qualified_state['provenance'] == TIER_LLM_SUMMARIZED


def test_existing_bare_names_keep_their_shape():
    entries = _parse_api_vocabulary(_response('authenticated'), [_struct()])
    assert entries == [
        {'class': 'security_fields', 'name': 'authenticated',
         'provenance': TIER_LLM_SUMMARIZED, 'why': 'authorization state'},
        {'class': 'state_fields', 'field': 'authenticated',
         'authority': 'local', 'provenance': TIER_LLM_SUMMARIZED},
    ]


@pytest.mark.parametrize('field', [
    pytest.param('authenticated; @script:python@', id='invalid-member-grammar'),
    pytest.param('a' * 129, id='member-exceeds-downstream-limit'),
])
def test_extracted_fields_still_need_downstream_identifier_grammar(field):
    item = _struct(fields=[field])
    assert _parse_api_vocabulary(_response(f'auth_context.{field}'), [item]) == []


def test_qualified_and_bare_spellings_share_existing_assembly_identity():
    items = [_struct()]
    entries = _parse_api_vocabulary(_response('authenticated'), items)
    entries += _parse_api_vocabulary(_response('auth_context.authenticated'), items)
    assembled = _assemble_vocabulary(entries)
    assert len(assembled[3]) == 1
    assert len(assembled[6]) == 1


def test_identifier_at_downstream_length_limit_is_accepted():
    field = 'a' * 128
    entries = _parse_api_vocabulary(_response(f'auth_context.{field}'), [_struct(fields=[field])])
    assert next(e for e in entries if e['class'] == 'security_fields')['name'] == field
    assert field in DomainVocabulary.from_domain_model({'security_fields': entries[:1]}).security_fields
