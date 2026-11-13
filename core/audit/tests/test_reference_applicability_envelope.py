"""Reference material labels narrow applicability without certifying a target."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.reference_inputs import reference_inputs_from_delivery
from core.language_reference import ReferenceContext,lookup


def _fitted():
    answer=lookup('owned-reference','integer overflow',ReferenceContext('c'))
    assert answer.entries
    ctx={'file':'unit.c','function':'f','line_start':1,'line_end':1,
         'source':'int f(int a, int b) { return a + b; }','language':'c',
         'language_reference_answers':(answer,)}
    captured=[]
    prompt=format_context_for_prompt(ctx,budget_limit=100000,knowledge_delivery_sink=captured.append)
    snapshot,=captured
    rows=snapshot['language_reference_delivery']
    assert rows[0]['delivered'] is True
    return answer,ctx,prompt,rows


def test_actual_fitted_reference_declares_material_domain_and_no_correspondence():
    answer,ctx,prompt,rows=_fitted()
    row,=rows
    assert row['representation']=='language-reference'
    assert row['applicability_domain']=='source-language'
    assert row['correspondence_ids']==[]
    assert asdict(answer)['correspondence_ids']==()
    assert 'source-language' in prompt
    assert 'conditional C11 rules' in prompt
    assert reference_inputs_from_delivery(rows,(answer,))['complete'] is True


@pytest.mark.parametrize('change',['domain','correspondence','representation','missing'])
def test_material_labels_must_match_the_owned_reference_answer(change):
    answer,ctx,prompt,rows=_fitted()
    bad=deepcopy(rows)
    if change=='domain':
        bad[0]['applicability_domain']='binary-machine'
    elif change=='correspondence':
        bad[0]['correspondence_ids']=['unvalidated-build-mapping']
    elif change=='representation':
        bad[0]['representation']='disassembly'
    else:
        bad[0].pop('applicability_domain')
    assert reference_inputs_from_delivery(bad,(answer,))['complete'] is False


def test_explicit_reference_beside_binary_view_stays_source_language_context():
    answer,ctx,prompt,rows=_fitted()
    ctx.update(file='binary:owned',line_start=0,line_end=0,is_binary=True,
               representation='decompilation',language='')
    captured=[]
    rendered=format_context_for_prompt(ctx,budget_limit=100000,knowledge_delivery_sink=captured.append)
    snapshot,=captured
    supplied=snapshot['language_reference_delivery']
    assert supplied[0]['applicability_domain']=='source-language'
    assert supplied[0]['correspondence_ids']==[]
    assert 'does not establish source/build/module correspondence' in rendered
    assert 'conditional C11 rules' in rendered
    assert 'binary-machine' not in rendered


def test_omitted_reference_still_discloses_material_domain_without_delivery():
    answer,ctx,prompt,rows=_fitted()
    captured=[]
    format_context_for_prompt(ctx,budget_limit=1,knowledge_delivery_sink=captured.append)
    snapshot,=captured
    omitted=snapshot['language_reference_delivery']
    assert omitted[0]['delivered'] is False
    assert omitted[0]['applicability_domain']=='source-language'
    assert omitted[0]['correspondence_ids']==[]
    assert reference_inputs_from_delivery(omitted,(answer,)) is None


def test_reference_material_labels_cannot_be_supplied_as_target_correspondence():
    from dataclasses import replace
    from core.audit.knowledge_context import context_answers
    from core.language_reference import ReferenceAnswer
    answer,ctx,prompt,rows=_fitted()
    with pytest.raises(TypeError):
        ReferenceAnswer('forged','answered',applicability_domain='binary-machine')
    with pytest.raises((TypeError,ValueError)):
        replace(answer,correspondence_ids=('unvalidated-mapping',))
    assert context_answers((asdict(answer),))==()
    row=answer.material_envelope()
    row['correspondence_ids'].append('borrowed mutation')
    assert answer.correspondence_ids==()


def test_shared_reference_body_retains_each_pack_and_material_envelope():
    from dataclasses import replace
    from core.audit.knowledge_context import reference_delivery,reference_sections
    answer,ctx,prompt,rows=_fitted()
    other=replace(answer,request_id='other',pack_version='other-reference-version')
    sections=reference_sections((answer,other))
    assert len(sections)==1
    received=reference_delivery((answer,other),sections)
    assert received[0]['delivered'] is True and received[1]['delivered'] is True
    assert [row['pack_version'] for row in received]==[answer.pack_version,other.pack_version]
    assert received[0]['applicability_domain']==received[1]['applicability_domain']=='source-language'
    assert reference_inputs_from_delivery(received,(answer,other))['complete'] is False
