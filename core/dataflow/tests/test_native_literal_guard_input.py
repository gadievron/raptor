"""Actual consumers retain locally established primitive literal inputs."""
import json

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason='requires native Z3')
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'
SOURCE = ('function previous() { const value = {}; }\nfunction handle(other) {\n'
          ' const value = "abc";\n' + GUARD + '\n consume(value);\n}\n')


@pytest.mark.parametrize('language,filename', [('javascript', 'app.js'), ('typescript', 'app.ts')], ids=['javascript', 'typescript'])
def test_local_primitive_input_is_independent_of_unrelated_object_scope(tmp_path, language, filename):
    pytest.importorskip('tree_sitter_javascript' if language == 'javascript' else 'tree_sitter_typescript')
    (tmp_path / filename).write_bytes(SOURCE.encode())
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
        sink_uri=filename, sink_line=5, sink_class='xss', language=language)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_same_primitive_fact_reaches_llm_and_prescreen_consumers(tmp_path):
    pytest.importorskip('tree_sitter_javascript')
    (tmp_path / 'app.js').write_bytes(SOURCE.encode())
    reply = json.dumps({'kind': 'charset', 'validator_source_line': GUARD.strip(),
                        'variable_name': 'value', 'charset': 'a-z', 'forbidden': '', 'library_call': ''})
    result = tier1_llm.try_tier1b(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
        sink_uri='app.js', sink_line=5, sink_class='xss', language='javascript',
        complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
    spec = sb.extract_validator_from_line(GUARD, 'javascript')
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file='app.js', step_line=4, sink_file='app.js', sink_line=5,
        source_text=SOURCE, language='javascript', sink_classes=frozenset({'xss'}),
    )
    assert refuted is True, reason


def test_entry_type_fact_does_not_erase_a_post_guard_rebind(tmp_path):
    pytest.importorskip('tree_sitter_javascript')
    source = SOURCE.replace('const value = "abc";', 'let value = "abc";').replace(' consume(value);', ' value = other;\n consume(value);')
    (tmp_path / 'app.js').write_bytes(source.encode())
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
        sink_uri='app.js', sink_line=6, sink_class='xss', language='javascript')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert 'no chain member reaches' in result.reasoning
