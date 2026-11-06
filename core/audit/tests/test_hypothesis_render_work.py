"""Hypothesis rendering consumes only its useful prefix and rejects bad fields."""

import pytest

from core.audit import context


RENDERERS = [
    (context._format_prior_hypotheses, 'mechanism'),
    (context._format_injected_hypotheses, 'mechanism'),
    (context._format_seed_hypotheses, 'claim'),
]


@pytest.mark.parametrize(('render', 'field'), RENDERERS)
def test_render_stops_after_eight_usable_records(render, field):
    class Rows(list):
        visited = 0

        def __iter__(self):
            for row in super().__iter__():
                self.visited += 1
                yield row

    rows = Rows([None, {field: '  '}] + [
        {field: f'claim-marker-{i:04d}'} for i in range(1000)
    ])
    text = render(rows)
    assert 'claim-marker-0000' in text
    assert 'claim-marker-0007' in text
    assert 'claim-marker-0008' not in text
    assert rows.visited == 10


@pytest.mark.parametrize(('render', 'field'), RENDERERS)
@pytest.mark.parametrize('bad', [42, True, ['text'], {'nested': 'text'}])
def test_wrong_typed_hypothesis_text_is_skipped(render, field, bad):
    assert render([{field: bad}]) == ''
    text = render([{field: bad}, {field: 'usable-text-marker'}])
    assert 'usable-text-marker' in text


@pytest.mark.parametrize('bad', [42, {'artifact': 'wrong-shape'}, 'not-a-reference-list'])
def test_seed_evidence_requires_a_reference_sequence(bad):
    text = context._format_seed_hypotheses([{'claim': 'usable-text-marker', 'evidence': bad}])
    assert 'usable-text-marker' in text
    assert '  evidence:' not in text


def test_seed_tuple_references_keep_their_existing_cap():
    text = context._format_seed_hypotheses([{
        'claim': 'usable-text-marker',
        'evidence': tuple({'artifact': f'artifact-marker-{i}'} for i in range(6)),
    }])
    assert 'artifact-marker-3' in text
    assert 'artifact-marker-4' not in text


@pytest.mark.parametrize(('render', 'field'), RENDERERS)
@pytest.mark.parametrize('bad', [42, True, 3.5])
def test_noniterable_hypothesis_collection_is_ignored(render, field, bad):
    assert render(bad) == ''


@pytest.mark.parametrize(('render', 'field'), RENDERERS)
def test_valid_generators_stop_before_the_unused_tail(render, field):
    def rows():
        for i in range(8):
            yield {field: f'generated-marker-{i}'}
        raise AssertionError('renderer consumed unused hypothesis tail')

    text = render(rows())
    assert 'generated-marker-0' in text
    assert 'generated-marker-7' in text
