"""Context entry cannot freeze externally owned validated name slots."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Manager:
 def __enter__(self):
  global value
  value = " "
  return self
 def __exit__(self, *args):
  global value
  value = " "
  return False
manager = Manager()
"""


@pytest.mark.parametrize('placement', ['inside', 'outside', 'same-line'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot'])
def test_context_entry_retains_only_owned_values(tmp_path, placement, mode):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    sink = 'consume(' + ('alias' if mode == 'snapshot' else 'value') + ')'
    if placement == 'same-line':
        text += ' with manager: ' + sink + '\n'
    elif placement == 'inside':
        text += ' with manager:\n  ' + sink + '\n'
    else:
        text += ' with manager:\n  pass\n ' + sink + '\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = (sb.Tier0Status.NOT_APPLICABLE
                if mode == 'shared' or placement == 'same-line' else sb.Tier0Status.SOUND)
    assert result.status is expected, result.reasoning
    if placement == 'same-line':
        # The public reader already declines compound sink statements.
        # Check entry timing without granting that additional sink shape.
        name = 'alias' if mode == 'snapshot' else 'value'
        line = len(text.splitlines())
        assert sb._variable_reassigned_between(ast.parse(text), name, line - 1, line) is (mode == 'shared')


@pytest.mark.parametrize('inside', [False, True], ids=['after-exit', 'inside-body'])
def test_fresh_validation_after_context_entry(tmp_path, inside):
    pytest.importorskip('z3')
    text = PREFIX + 'def handle():\n with manager:\n  pass\n'
    if inside:
        text += ' ' + GUARD + '\n  consume(value)\n'
    else:
        text += GUARD + '\n consume(value)\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
