"""Synchronous iteration may rebind a separately shared validated slot."""
import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Source:
 def __iter__(self):
  global value
  value = " "
  return iter(())
source = Source()
"""


@pytest.mark.parametrize('local', [False, True], ids=['shared-slot', 'local-slot'])
@pytest.mark.parametrize('snapshot', [False, True], ids=['live-read', 'early-snapshot'])
def test_iterator_dispatch_preserves_only_owned_snapshot(tmp_path, local, snapshot):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if local else 'def handle():\n')
    text += GUARD + '\n'
    if snapshot:
        text += ' alias = value\n'
    text += ' for ignored in source:\n  pass\n'
    text += ' consume(' + ('alias' if snapshot else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.SOUND if local or snapshot else sb.Tier0Status.NOT_APPLICABLE
    assert result.status is expected, result.reasoning


def test_validator_after_iteration_refreshes_shared_slot(tmp_path):
    pytest.importorskip('z3')
    text = PREFIX + 'def handle():\n for ignored in source:\n  pass\n'
    text += GUARD + '\n consume(value)\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
