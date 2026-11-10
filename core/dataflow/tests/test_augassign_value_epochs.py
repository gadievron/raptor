"""Implicit augmented operators may expire shared slots; fixtures stay inert."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'


@pytest.mark.parametrize('method', ['__iadd__', '__add__'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
def test_unrelated_augmented_target_respects_value_epoch(tmp_path, method, mode):
    pytest.importorskip('z3')
    source = f'''import re
value = "abc"
class Counter:
 def {method}(self, other):
  global value
  value = " "
  return self
def consume(argument): pass
'''
    source += 'def handle(counter, value):\n' if mode == 'parameter' else 'def handle(counter):\n'
    if mode != 'fresh':
        source += GUARD + '\n'
    if mode == 'snapshot':
        source += ' alias = value\n'
    source += ' counter += 1\n'
    if mode == 'fresh':
        source += GUARD + '\n'
    source += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    # Only the analyzer reads this source; no application or callback runs.
    (tmp_path / 'app.py').write_text(source)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                         sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


def test_augmented_dispatch_is_inclusive_for_shared_slot():
    tree = ast.parse('def handle(counter):\n pass\n counter += item\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
    assert not sb._variable_reassigned_between(tree, 'counter', 2, 3)


def test_augmented_dispatch_on_backedge_expires_outer_shared_fact():
    tree = ast.parse('def handle(counter):\n pass\n while True:\n  consume(value)\n  counter += item\n')
    assert sb._rebound_in_loop_containing_sink(tree, 'value', 2, 4)
