"""Framework context emits distinct guarantees and scopes lookup reuse per source."""

from dataclasses import asdict

import pytest

from core.audit import context, framework_model
from core.audit.framework_model import FrameworkGuarantee


ORM_SOURCE = 'from django.db import models\nqs = User.objects.filter(name=user_input)'


@pytest.fixture
def lookups(monkeypatch):
    calls = []
    original = framework_model.framework_negates_cwe

    def tracked(file_path, source, cwe):
        calls.append((file_path, cwe))
        return original(file_path, source, cwe)

    monkeypatch.setattr(framework_model, 'framework_negates_cwe', tracked)
    return calls


def test_same_returned_guarantee_is_emitted_once(lookups):
    rows = context._detect_framework_guarantees('views.py', ORM_SOURCE)
    assert len(rows) == 1
    row = rows[0]
    assert row['framework'] == 'django'
    assert row['negates_cwe'] == ['CWE-89']
    expected = framework_model._GUARANTEE_INDEX['django', 'CWE-89']
    assert row == asdict(expected)
    covered = {cwe for guarantee in framework_model.FRAMEWORK_GUARANTEES for cwe in guarantee.negates_cwe}
    assert {cwe for _, cwe in lookups} == covered
    assert len(lookups) == len(covered)


def test_negative_matches_are_reused_too(lookups):
    assert context._detect_framework_guarantees('plain.c', 'int f(void){return 0;}') == []
    assert len(lookups) == len({cwe for _, cwe in lookups}) == 6


def test_first_match_order_and_all_guarantee_details_are_preserved():
    source = (ORM_SOURCE + '\nfrom django.template import loader\nrender_to_string("a.html", ctx)\n'
              '@csrf_protect\n@Valid\n@PreAuthorize\nhelmet();')
    rows = context._detect_framework_guarantees('mixed.txt', source)
    cwes = ['CWE-89', 'CWE-352', 'CWE-79', 'CWE-20', 'CWE-862', 'CWE-693']
    expected = [asdict(framework_model.framework_negates_cwe('mixed.txt', source, cwe)) for cwe in cwes]
    assert rows == expected
    assert len({(row['framework'], row['pattern']) for row in rows}) == len(rows)


def test_escape_hatch_still_voids_template_guarantee():
    source = ORM_SOURCE + '\nfrom django.template import loader\nmark_safe(user_html)\nrender_to_string("a.html", ctx)'
    rows = context._detect_framework_guarantees('views.py', source)
    assert len(rows) == 1
    assert rows[0]['negates_cwe'] == ['CWE-89']


def test_lookup_reuse_does_not_cross_sources_or_files(lookups):
    assert context._detect_framework_guarantees('plain.c', 'int f(void){return 0;}') == []
    django = context._detect_framework_guarantees('views.py', ORM_SOURCE)
    flask = context._detect_framework_guarantees('query.py', 'from sqlalchemy import select\nq = session.query(User).filter(name=value)')
    assert django[0]['framework'] == 'django'
    assert flask[0]['framework'] == 'flask'
    assert sum(cwe == 'CWE-89' for _, cwe in lookups) == 3
    assert len(lookups) == 18


class Adapted(str):
    __hash__ = None


def test_non_native_cwe_keeps_direct_lookup(lookups, monkeypatch):
    catalogue = [FrameworkGuarantee('first', 'one', 'hint', [Adapted('CWE-89')]),
                 FrameworkGuarantee('second', 'two', 'hint', [Adapted('CWE-89')])]
    monkeypatch.setattr(framework_model, 'FRAMEWORK_GUARANTEES', catalogue)
    assert context._detect_framework_guarantees('plain.c', 'int f(void){return 0;}') == []
    assert len(lookups) == 2


def test_adapted_match_identity_is_not_hashed(monkeypatch):
    catalogue = [FrameworkGuarantee('first', 'one', 'hint', ['CWE-89']),
                 FrameworkGuarantee('second', 'two', 'hint', ['CWE-89'])]
    match = FrameworkGuarantee(Adapted('adapted'), 'pattern', 'hint', ['CWE-89'])
    monkeypatch.setattr(framework_model, 'FRAMEWORK_GUARANTEES', catalogue)
    monkeypatch.setattr(framework_model, 'framework_negates_cwe', lambda *args: match)
    assert context._detect_framework_guarantees('plain.c', '') == [asdict(match), asdict(match)]


def test_detection_failure_still_discards_partial_hints(monkeypatch, caplog):
    match = framework_model._GUARANTEE_INDEX['django', 'CWE-89']

    def failing(file_path, source, cwe):
        if cwe == 'CWE-89':
            return match
        raise ValueError('owned test failure')

    monkeypatch.setattr(framework_model, 'framework_negates_cwe', failing)
    with caplog.at_level('DEBUG', logger='core.audit.context'):
        assert context._detect_framework_guarantees('views.py', ORM_SOURCE) == []
    assert 'framework detection failed' in caplog.text


def test_catalogue_is_unchanged_and_returned_rows_are_independent():
    before = [asdict(g) for g in framework_model.FRAMEWORK_GUARANTEES]
    first = context._detect_framework_guarantees('views.py', ORM_SOURCE)
    first[0]['guarantees'] = 'caller-owned field'
    second = context._detect_framework_guarantees('views.py', ORM_SOURCE)
    assert second[0]['guarantees'] != first[0]['guarantees']
    assert [asdict(g) for g in framework_model.FRAMEWORK_GUARANTEES] == before


def test_rendered_prompt_contains_one_framework_hint(monkeypatch):
    monkeypatch.setattr(context, '_get_tool_catalog', lambda: '')
    rows = context._detect_framework_guarantees('views.py', ORM_SOURCE)
    ctx = {'file': 'views.py', 'function': 'view', 'line_start': 1, 'source': ORM_SOURCE,
           'metadata': {}, 'callers': [], 'callees': [], 'sinks': [],
           'framework_guarantees': rows}
    prompt = context.format_context_for_prompt(ctx, patterns_in_system=True)
    prefix = f"- **{rows[0]['framework']}** {rows[0]['pattern']}:"
    assert prompt.count(prefix) == 1
    assert '(CWE-89 mitigated)' in prompt
