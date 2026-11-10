"""Match callbacks may expire shared slots; fixtures are inspected as source only."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = '''import re
value = "abc"
class Subject:
 def __eq__(self, other):
  global value
  value = " "
  return True
class Flag:
 def __bool__(self):
  global value
  value = " "
  return True
subject = Subject()
flag = Flag()
def consume(argument):
 pass
'''


def query(tmp_path, pattern, *, mode='shared', subject='subject'):
    """Never import or execute the authored application or its callbacks."""
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    text += f' match {subject}:\n  case {pattern}:\n   pass\n'
    if mode == 'fresh':
        text += GUARD + '\n'
    text += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')


@pytest.mark.parametrize('pattern', ['0', '_ if flag', '0 | _'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
def test_match_dispatch_respects_value_epoch(tmp_path, pattern, mode):
    result = query(tmp_path, pattern, mode=mode)
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('pattern', ['_', 'captured', 'None', 'True', 'False',
                                      'None | True | False', '(None | True) as captured'])
def test_identity_only_match_preserves_shared_slot(tmp_path, pattern):
    result = query(tmp_path, pattern)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_match_capture_overwrite_expires_parameter(tmp_path):
    result = query(tmp_path, 'value', mode='parameter')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_match_subject_call_still_expires_shared_slot(tmp_path):
    result = query(tmp_path, '_', subject='make_subject()')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


@pytest.mark.parametrize('pattern', ['0', '_ if flag', '0 | _', '[item]',
                                      '{"key": item}', 'Subject()', '[*items]'])
def test_match_dispatch_is_inclusive_on_sink_row(pattern):
    tree = ast.parse(f'def handle():\n pass\n match subject:\n  case {pattern}: pass\n')
    match = tree.body[0].body[1]
    assert sb._python_possible_call(match)
    assert sb._python_evaluation_dispatch(match)
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
