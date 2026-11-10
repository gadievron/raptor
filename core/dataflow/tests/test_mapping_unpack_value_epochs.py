"""Mapping expansion cannot freeze a separately shared validated slot."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Mapping:
 def keys(self):
  global value
  value = " "
  return ()
 def __getitem__(self, key):
  return 0
mapping = Mapping()
"""


@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
@pytest.mark.parametrize('middle', [' unused = {**mapping}',
                                    ' def later(argument={**mapping}):\n  pass'])
def test_mapping_dispatch_retains_owned_or_refreshed_values(tmp_path, mode, middle):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    text += middle + '\n'
    if mode == 'fresh':
        text += GUARD + '\n'
    text += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('literal', ['{}', '{"fixed": 0}'])
def test_plain_dictionary_literals_do_not_expire_shared_values(tmp_path, literal):
    pytest.importorskip('z3')
    text = PREFIX + 'def handle():\n' + GUARD
    text += '\n unused = ' + literal + '\n consume(value)\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_mapping_effect_precedes_same_row_read():
    tree = ast.parse('def handle():\n pass\n unused = {**mapping}; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
