"""Assertions may truth-test arbitrary objects; application text is never run."""
import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'


@pytest.mark.parametrize('method,returned', [('__bool__', 'True'), ('__len__', '1')])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
def test_assert_truth_dispatch_respects_value_epoch(tmp_path, method, returned, mode):
    # This source profile enables assertions. Optimisation can omit the entire
    # statement; no application execution or optimisation profile is inferred.
    pytest.importorskip('z3')
    text = f'''import re
value = "abc"
class Flag:
 def {method}(self):
  global value
  value = " "
  return {returned}
flag = Flag()
def consume(argument): pass
'''
    text += 'def handle(value):\n' if mode == 'parameter' else 'def handle():\n'
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    text += ' assert flag\n'
    if mode == 'fresh':
        text += GUARD + '\n'
    text += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                         sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning
