"""Finally paths remain visible across abrupt exits and possible exceptions."""

from textwrap import indent

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs


def build(body):
    cfg = build_python_cfg('def handle(raw, flag):\n' + indent(body, '    '), 'handle')
    assert cfg is not None
    return cfg


def call(cfg, name):
    return next(n for n in cfg.nodes() if name in n.calls)


def reaches(cfg, start, goal, blocked=frozenset()):
    pending = [start]
    seen = set(blocked)
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        if node == goal:
            return True
        seen.add(node)
        pending.extend(cfg.successors(node))
    return False


def test_finally_sink_is_reachable_when_try_raises():
    cfg = build('try:\n    raise ValueError()\nfinally:\n    consume(raw)\n')
    assert reaches(cfg, cfg.entry, call(cfg, 'consume'))


@pytest.mark.parametrize('abrupt', ['return raw', 'break', 'continue'])
def test_each_abrupt_path_can_enter_finally(abrupt):
    body = 'try:\n    ' + abrupt + '\nfinally:\n    consume(raw)\n'
    if abrupt in ('break', 'continue'):
        body = 'while flag:\n' + indent(body, '    ')
    cfg = build(body)
    cleanup = call(cfg, 'consume')
    terminal = next(n for n in cfg.nodes()
                    if n.label.startswith('Return' if abrupt == 'return raw' else abrupt))
    assert reaches(cfg, cfg.entry, cleanup)
    assert reaches(cfg, terminal, cleanup)


@pytest.mark.parametrize('tail', [
    'except Exception:\n    return raw\n',
    'except Exception:\n    pass\nelse:\n    return raw\n',
])
def test_handler_and_else_return_paths_can_enter_finally(tail):
    cfg = build('try:\n    prepare()\n' + tail + 'finally:\n    consume(raw)\n')
    terminal = next(n for n in cfg.nodes() if n.label.startswith('Return'))
    assert reaches(cfg, terminal, call(cfg, 'consume'))


def test_possible_exception_before_assignment_preserves_the_prior_value():
    cfg = build('tmp = raw\ntry:\n    tmp = prepare(raw)\nfinally:\n    consume(tmp)\n')
    initial = next(n for n in cfg.nodes() if n.defs == frozenset({'tmp'}) and not n.calls)
    assert initial in reaching_defs(cfg).at(call(cfg, 'consume'), 'tmp')


def test_break_finally_value_reaches_after_loop_without_retesting_header():
    cfg = build("tmp = 'safe'\nwhile True:\n    try:\n        break\n    finally:\n        tmp = raw\nconsume(tmp)\n")
    cleanup = next(n for n in cfg.nodes() if 'tmp' in n.defs and 'raw' in n.uses)
    header = next(n for n in cfg.nodes() if n.label.startswith('While'))
    sink = call(cfg, 'consume')
    assert cleanup in reaching_defs(cfg).at(sink, 'tmp')
    assert reaches(cfg, cleanup, sink, blocked=frozenset({header}))


def test_continue_finally_can_reach_the_loop_header():
    cfg = build('while flag:\n    try:\n        continue\n    finally:\n        consume(raw)\n')
    header = next(n for n in cfg.nodes() if n.label.startswith('While'))
    assert reaches(cfg, call(cfg, 'consume'), header)


def test_nested_finally_preserves_inner_mutation_at_outer_sink():
    cfg = build("tmp = 'safe'\ntry:\n    try:\n        return raw\n    finally:\n        tmp = raw\nfinally:\n    consume(tmp)\n")
    cleanup = next(n for n in cfg.nodes() if 'tmp' in n.defs and 'raw' in n.uses)
    assert cleanup in reaching_defs(cfg).at(call(cfg, 'consume'), 'tmp')


def test_return_inside_finally_does_not_reach_its_dead_tail():
    cfg = build('try:\n    return raw\nfinally:\n    return raw\n    consume(raw)\n')
    assert not reaches(cfg, cfg.entry, call(cfg, 'consume'))


def test_inner_loop_break_does_not_get_a_finally_backedge_into_that_loop():
    cfg = build('try:\n    while flag:\n        break\n    prepare()\nfinally:\n    cleanup()\n')
    cleanup = call(cfg, 'cleanup')
    header = next(n for n in cfg.nodes() if n.label.startswith('While'))
    assert not reaches(cfg, cleanup, header)
    assert not reaches(cfg, cleanup, call(cfg, 'prepare'))


def test_cleanup_mutation_reaches_an_enclosing_exception_handler():
    cfg = build("tmp = 'safe'\ntry:\n    try:\n        prepare()\n    finally:\n        tmp = raw\nexcept Exception:\n    consume(tmp)\n")
    cleanup = next(n for n in cfg.nodes() if 'tmp' in n.defs and 'raw' in n.uses)
    assert cleanup in reaching_defs(cfg).at(call(cfg, 'consume'), 'tmp')


def test_normal_handler_and_else_paths_keep_cleanup_before_post_try():
    from core.analysis.dominators import build_dom_tree

    cfg = build('try:\n    prepare()\nexcept Exception:\n    recover()\nelse:\n    success()\nfinally:\n    cleanup()\nconsume(raw)\n')
    assert build_dom_tree(cfg).dominates(call(cfg, 'cleanup'), call(cfg, 'consume'))
