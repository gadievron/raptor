"""A context manager may suppress an exception before the body finishes."""

from textwrap import indent

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs


def build(body, *, asynchronous=False):
    prefix = 'async def' if asynchronous else 'def'
    source = 'import contextlib\nimport werkzeug\n' + prefix + ' handle(raw, cm):\n' + indent(body, '    ')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    return cfg


def call(cfg, name):
    return next(n for n in cfg.nodes() if name in n.calls)


def reaches(cfg, start, goal):
    pending = [start]
    seen = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        if node == goal:
            return True
        seen.add(node)
        pending.extend(cfg.successors(node))
    return False


def test_suppressed_raise_cannot_make_later_sanitizer_mandatory():
    from core.analysis.sanitizer_cut import evaluate_finding

    cfg = build('tmp = raw\nwith contextlib.suppress(ValueError):\n    if raw:\n        raise ValueError()\n    tmp = werkzeug.utils.secure_filename(raw)\nopen(tmp)\n')
    sink = call(cfg, 'open')
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    assert result.all_matched_bindings
    assert result.suppress is False
    original = next(n for n in cfg.nodes() if n.defs == frozenset({'tmp'}) and not n.calls)
    assert original in reaching_defs(cfg).at(sink, 'tmp')


def test_post_with_sink_reachable_after_suppressed_explicit_raise():
    cfg = build('with contextlib.suppress(ValueError):\n    raise ValueError()\nconsume(raw)\n')
    assert reaches(cfg, cfg.entry, call(cfg, 'consume'))


def test_preheader_value_survives_failed_binding_with_multiple_managers():
    cfg = build('tmp = raw\nwith contextlib.suppress(ValueError), contextlib.nullcontext((1,)) as (tmp, missing):\n    pass\nconsume(tmp)\n')
    original = next(n for n in cfg.nodes() if n.defs == frozenset({'tmp'}) and not n.calls)
    assert original in reaching_defs(cfg).at(call(cfg, 'consume'), 'tmp')


def test_finally_mutation_before_suppression_reaches_post_with_sink():
    cfg = build("tmp = 'safe'\nwith contextlib.suppress(ValueError):\n    try:\n        raise ValueError()\n    finally:\n        tmp = raw\nconsume(tmp)\n")
    cleanup = next(n for n in cfg.nodes() if 'tmp' in n.defs and 'raw' in n.uses)
    assert cleanup in reaching_defs(cfg).at(call(cfg, 'consume'), 'tmp')


def test_header_still_dominates_body_without_join_self_loop_or_reentry():
    from core.analysis.dominators import build_dom_tree

    cfg = build('with cm:\n    body(raw)\nafter(raw)\n')
    header = next(n for n in cfg.nodes() if n.label.startswith('With'))
    assert build_dom_tree(cfg).dominates(header, call(cfg, 'body'))
    assert not reaches(cfg, call(cfg, 'after'), call(cfg, 'body'))
    assert all(n not in cfg.successors(n) for n in cfg.nodes())


def test_sanitizer_after_with_retains_the_value_bound_control():
    from core.analysis.sanitizer_cut import evaluate_finding

    cfg = build('with contextlib.suppress(ValueError):\n    if raw:\n        raise ValueError()\ntmp = werkzeug.utils.secure_filename(raw)\nopen(tmp)\n')
    result = evaluate_finding(cfg, [cfg.entry], call(cfg, 'open'), cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    assert result.value_bound_bindings
    assert result.suppress is True


def test_async_manager_can_also_suppress_a_body_exception():
    cfg = build('async with cm:\n    raise ValueError()\nconsume(raw)\n', asynchronous=True)
    assert reaches(cfg, cfg.entry, call(cfg, 'consume'))
