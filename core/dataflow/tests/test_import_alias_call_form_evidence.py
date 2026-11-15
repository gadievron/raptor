"""Explicit import spelling must not erase scoped call-form observations."""
from dataclasses import asdict
from hashlib import sha256

import pytest

from core.dataflow.source_identity import known_python_identity_conflict
from core.dataflow.string_type_evidence import (
    default_positional_call_evidence,
    exact_str_default_call_evidence,
)


@pytest.mark.parametrize('header,callee', [
    ('import html', 'html.escape'),
    ('import html as markup', 'markup.escape'),
    ('from html import escape as encode', 'encode'),
    ('from html import escape', 'escape'),
], ids=['canonical', 'module-alias', 'member-alias', 'member-import'])
@pytest.mark.parametrize('kind', ['form', 'primitive'])
def test_owned_import_call_keeps_scoped_evidence(header, callee, kind):
    source = (header + '\ndef handle(raw):\n    if type(raw) is not str: return\n'
              f'    safe = {callee}(raw)\n    return safe\n')
    namespace = {'__name__': 'owned_import_call_form'}
    exec(compile(source, '<owned-import-call-form>', 'exec', dont_inherit=True), namespace)
    assert namespace['handle']('<owned>') == '&lt;owned&gt;'
    assert known_python_identity_conflict(source, 4, ('html.escape',)) is None
    if kind == 'form':
        evidence = default_positional_call_evidence(source, 4, 'html.escape')
    else:
        evidence = exact_str_default_call_evidence(source, 4, 'raw', 'html.escape')
    assert evidence is not None
    assert evidence.library_call == 'html.escape'
    assert evidence.source_digest == sha256(source.encode()).hexdigest()
    assert evidence.call_span[0] == 4
    assert evidence.assumptions
    if kind == 'form':
        assert evidence.scope == 'source-call-form-only'
        assert 'variable' not in asdict(evidence)
    else:
        assert evidence.origin == 'adjacent-exact-type-guard'
        assert evidence.scope == 'primitive-input-type-and-default-call-form'


@pytest.mark.parametrize('source,line', [
    ('import other as markup\ndef handle(raw):\n    return markup.escape(raw)\n', 3),
    ('from .html import escape as encode\ndef handle(raw):\n    return encode(raw)\n', 3),
    ('import html as markup\ndef handle(raw, markup):\n    return markup.escape(raw)\n', 3),
    ('import html\ndef handle(raw):\n    alias = html.escape\n    return alias(raw)\n', 4),
    ('import other\ndef handle(raw):\n    return other.escape(raw)\n', 3),
    ('import html as markup\nfrom html import escape as encode\ndef handle(raw):\n    first, last = markup.escape(raw), encode(raw)\n', 4),
    ('import html as markup\ndef handle(raw):\n    return markup.escape(raw, quote=False)\n', 3),
    ('import html as markup\ndef handle(raw):\n    return markup.escape(*raw)\n', 3),
    ('import html as markup\ndef handle(raw, options):\n    return markup.escape(raw, **options)\n', 3),
    ('import html as markup\ndef handle(raw):\n    return markup.escape(raw, False)\n', 3),
    ('import html as markup\nmarkup.escape = replacement\ndef handle(raw):\n    return markup.escape(raw)\n', 4),
], ids=['wrong-import', 'relative-import', 'parameter-shadow', 'assignment-alias', 'same-tail', 'ambiguous',
        'configured-option', 'star', 'keyword-expansion', 'extra-positional', 'member-mutation'])
def test_import_call_evidence_keeps_existing_refusals(source, line):
    assert default_positional_call_evidence(source, line, 'html.escape') is None
    assert exact_str_default_call_evidence(source, line, 'raw', 'html.escape') is None


def test_import_call_form_does_not_supply_missing_input_type():
    source = 'import html as markup\ndef handle(raw):\n    return markup.escape(raw)\n'
    form = default_positional_call_evidence(source, 3, 'html.escape')
    assert form is not None and form.scope == 'source-call-form-only'
    assert 'variable' not in asdict(form)
    assert exact_str_default_call_evidence(source, 3, 'raw', 'html.escape') is None


def test_shadowed_builtin_guard_stays_unverified_with_import_alias():
    source = ('import html as markup\ndef handle(raw, type):\n'
              '    if type(raw) is not str: return\n    return markup.escape(raw)\n')
    assert default_positional_call_evidence(source, 4, 'html.escape') is not None
    assert exact_str_default_call_evidence(source, 4, 'raw', 'html.escape') is None


@pytest.mark.parametrize('header,callee', [
    ('import html as markup', 'markup.escape'),
    ('from html import escape as encode', 'encode'),
    ('from html import escape', 'escape'),
])
def test_literal_import_call_evidence_retains_its_primitive_scope(header, callee):
    source = header + f'\ndef handle():\n    return {callee}("<owned>")\n'
    namespace = {'__name__': 'owned_literal_import_call'}
    exec(compile(source, '<owned-literal-import-call>', 'exec', dont_inherit=True), namespace)
    assert namespace['handle']() == '&lt;owned&gt;'
    evidence = exact_str_default_call_evidence(source, 3, 'unused', 'html.escape')
    assert evidence is not None and evidence.origin == 'literal'
    assert evidence.variable is None and evidence.guard_span is None
    assert evidence.assumptions
