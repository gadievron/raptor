"""Descriptor and getter dispatch cannot freeze a shared validated name."""
import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PYTHON_PREFIX = ('import re\nvalue = "abc"\nclass Carrier:\n'
                 ' @property\n def item(self):\n  global value\n  value = " "\n  return 0\n'
                 ' def __getitem__(self, key):\n  global value\n  value = " "\n  return 0\n'
                 ' @property\n def consume(self):\n  global value\n  value = " "\n'
                 '  return lambda argument: None\ncarrier = Carrier()\n')


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def python_query(tmp_path, middle, sink='consume(value)', *, parameter=False, before='', fresh=False):
    header = 'def handle(value):\n' if parameter else 'def handle():\n'
    guard = '' if fresh else GUARD + '\n'
    text = PYTHON_PREFIX + header + guard + before + middle + '\n'
    if fresh:
        text += GUARD + '\n'
    text += ' ' + sink + '\n'
    (tmp_path / 'app.py').write_text(text)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')


@pytest.mark.parametrize('access', ['attribute', 'index', 'sink-callee'])
@pytest.mark.parametrize('parameter', [False, True], ids=['shared-slot', 'local-slot'])
def test_python_lookup_preserves_only_owned_value_slot(tmp_path, access, parameter):
    middle = ' unused = carrier.item' if access == 'attribute' else ' unused = carrier[0]'
    sink = 'consume(value)'
    if access == 'sink-callee':
        middle, sink = ' pass', 'carrier.consume(value)'
    result = python_query(tmp_path, middle, sink, parameter=parameter)
    assert result.status is (sb.Tier0Status.SOUND if parameter else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


@pytest.mark.parametrize('early', [False, True], ids=['late-lookup', 'snapshot'])
def test_python_alias_capture_order_around_descriptor(tmp_path, early):
    before = ' alias = value\n' if early else ''
    middle = ' unused = carrier.item' + ('' if early else '\n alias = value')
    result = python_query(tmp_path, middle, 'consume(alias)', before=before)
    assert result.status is (sb.Tier0Status.SOUND if early else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


def test_python_default_lookup_is_an_inline_effect(tmp_path):
    result = python_query(tmp_path, ' def later(argument=carrier.item):\n  pass')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_python_validation_after_lookup_refreshes_slot(tmp_path):
    result = python_query(tmp_path, ' unused = carrier.item', fresh=True)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize('language', ['javascript', 'typescript'])
@pytest.mark.parametrize('access', ['attribute', 'index', 'sink-callee'])
@pytest.mark.parametrize('parameter', [False, True], ids=['shared-slot', 'local-slot'])
def test_native_lookup_preserves_only_owned_value_slot(tmp_path, language, access, parameter):
    pytest.importorskip('tree_sitter_javascript' if language == 'javascript' else 'tree_sitter_typescript')
    from core.analysis import validator_control_scope

    prefix = ('let value = "abc";\nconst carrier = {\n'
              ' get item() { value = " "; return 0; },\n'
              ' get consume() { value = " "; return function(argument) {}; }\n};\n')
    header = 'function handle(value) {' if parameter else 'function handle() {'
    guard = ' if (!/^[a-z]+$/.test(value)) return;'
    middle = ' const unused = carrier.item;' if access == 'attribute' else ' const unused = carrier["item"];'
    sink = ' consume(value);'
    if access == 'sink-callee':
        middle, sink = ' ;', ' carrier.consume(value);'
    text = prefix + header + '\n' + guard + '\n' + middle + '\n' + sink + '\n}\n'
    assert validator_control_scope._native_source_tree(text, language) is not None
    name = 'app.js' if language == 'javascript' else 'app.ts'
    (tmp_path / name).write_text(text)
    result = sb.try_tier0(fix_diff='+' + guard + '\n', repo_root=tmp_path,
                          sink_uri=name, sink_line=len(text.splitlines())-1, sink_class='xss', language=language)
    assert result.status is (sb.Tier0Status.SOUND if parameter else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


@pytest.mark.parametrize('early', [False, True], ids=['late-captured-read', 'local-snapshot'])
def test_known_nested_writer_makes_parameter_slot_shared(tmp_path, early):
    prefix = ('import re\ndef handle(value):\n class Carrier:\n  @property\n'
              '  def item(self):\n   nonlocal value\n   value = " "\n   return 0\n carrier = Carrier()\n')
    text = prefix + GUARD + '\n'
    if early:
        text += ' alias = value\n'
    text += ' unused = carrier.item\n'
    if not early:
        text += ' alias = value\n'
    text += ' consume(alias)\n'
    (tmp_path / 'captured.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='captured.py', sink_line=len(text.splitlines()), sink_class='xss')
    assert result.status is (sb.Tier0Status.SOUND if early else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


def test_substitution_epoch_refuses_known_captured_writer():
    text = ('import re\ndef handle(value):\n class Carrier:\n  @property\n'
            '  def item(self):\n   nonlocal value\n   value = " "\n   return 0\n carrier = Carrier()\n'
            ' value = re.sub(r"[ ]+", "", value)\n unused = carrier.item\n consume(value)\n')
    assert not sb.substitution_dominates_sink(text, 10, 12, 'value')
