"""A condition executes before its selected value is captured."""
import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Flag:
 def __bool__(self):
  global value
  value = " "
  return True
 def __add__(self, other):
  global value
  value = " "
  return True
flag = Flag()
"""


@pytest.mark.parametrize('middle', [' if flag:\n  pass',
                                    ' while flag:\n  break',
                                    ' alias = value if flag else value',
                                    ' alias = value if (flag + 0) else value'])
@pytest.mark.parametrize('local', [False, True], ids=['shared', 'local'])
def test_condition_dispatch_precedes_selected_read(tmp_path, middle, local):
    pytest.importorskip('z3')
    source = PREFIX + ('def handle(value):\n' if local else 'def handle():\n')
    name = 'alias' if 'alias =' in middle else 'value'
    source += GUARD + '\n' + middle + '\n consume(' + name + ')\n'
    (tmp_path / 'app.py').write_text(source)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')
    assert result.status is (sb.Tier0Status.SOUND if local else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


def test_early_local_alias_survives_later_truth_dispatch(tmp_path):
    pytest.importorskip('z3')
    source = PREFIX + 'def handle():\n' + GUARD
    source += '\n snapshot = value\n if flag:\n  pass\n consume(snapshot)\n'
    (tmp_path / 'app.py').write_text(source)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
