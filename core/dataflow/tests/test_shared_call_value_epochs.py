"""An opaque call cannot freeze an externally owned validated name."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def python_source(event, *, before="", after="", sink="value", parameter=False):
    prefix = ('import re\nvalue = "abc"\ndef mutate(*args):\n global value\n value = " "\n'
              ' return lambda item: item\n')
    header = 'def handle(value, raw):\n' if parameter else 'def handle():\n'
    text = prefix + header + before + GUARD + '\n' + event + '\n' + after + ' consume(' + sink + ')\n'
    lines = text.splitlines()
    return text, lines.index(GUARD) + 1, len(lines)


@pytest.mark.parametrize("event", [
    ' mutate()', ' later = lambda arg=mutate(): None',
    ' def later(arg=mutate()):\n  pass', ' @mutate\n def later():\n  pass',
    ' class Later:\n  mutate()', ' def later(arg: mutate()):\n  pass',
], ids=["sibling-call", "lambda-default", "function-default", "decorator", "class-body", "annotation-profile"])
def test_shared_python_slot_loses_proof_at_inline_effect(tmp_path, event):
    text, guard_line, sink_line = python_source(event)
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=sink_line, sink_class='xss')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert not sb._python_chain_reaches_sink(ast.parse(text), 'value', guard_line, sink_line, text.splitlines()[-1])


@pytest.mark.parametrize("capture_before", [False, True], ids=["late-lookup", "snapshot"])
def test_python_alias_observes_call_order(tmp_path, capture_before):
    before = ' alias = value\n' if capture_before else ''
    after = '' if capture_before else ' alias = value\n'
    text, _, sink_line = python_source(before + ' mutate()', after=after, sink='alias')
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=sink_line, sink_class='xss')
    assert result.status is (sb.Tier0Status.SOUND if capture_before else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


def test_python_parameter_is_not_the_sibling_global(tmp_path):
    text, _, sink_line = python_source(' mutate()', parameter=True)
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=sink_line, sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_header_rebinding_ends_local_parameter_epoch():
    text, guard_line, sink_line = python_source(' def later(arg=(value := raw)):\n  pass', parameter=True)
    assert not sb._python_chain_reaches_sink(ast.parse(text), 'value', guard_line, sink_line, text.splitlines()[-1])


def test_python_substitution_checks_intervening_call():
    text = ('import re\nvalue = "abc"\ndef mutate():\n global value\n value = " "\n'
            'def handle():\n global value\n value = re.sub(r"[ ]+", "", value)\n mutate()\n consume(value)\n')
    assert not sb.substitution_dominates_sink(text, 8, 10, 'value')
    assert sb.substitution_dominates_sink(text.replace(' global value\n value = re.sub', ' value = "abc"\n value = re.sub'), 8, 10, 'value')


@pytest.mark.parametrize("language", ['javascript', 'typescript'])
@pytest.mark.parametrize("parameter", [False, True], ids=['shared-slot', 'local-parameter'])
def test_native_call_distinguishes_shared_and_function_slot(tmp_path, language, parameter):
    pytest.importorskip('tree_sitter_javascript' if language == 'javascript' else 'tree_sitter_typescript')
    guard = ' if (!/^[a-z]+$/.test(value)) return;'
    header = 'function handle(value) {' if parameter else 'function handle() {'
    text = ('let value = "abc";\nfunction mutate() { value = " "; }\n' + header + '\n'
            + guard + '\n mutate();\n consume(value);\n}\n')
    name = 'app.js' if language == 'javascript' else 'app.ts'
    (tmp_path / name).write_text(text)
    result = sb.try_tier0(fix_diff='+' + guard + '\n', repo_root=tmp_path,
                          sink_uri=name, sink_line=6, sink_class='xss', language=language)
    assert result.status is (sb.Tier0Status.SOUND if parameter else sb.Tier0Status.NOT_APPLICABLE), result.reasoning
