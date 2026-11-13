"""Additive member paths must not multiply iterator-origin traversal."""

import ast
import sys

from core.analysis.python_module_callgraph import module_dynamic_namespace


def test_repeated_iterator_paths_visit_each_origin_once_per_traversal():
    expression = 'iter((werkzeug.utils,))'
    for _ in range(8):
        expression = '({"k":'+expression+'}["k"]).get("ignored")'
    tree = ast.parse('import werkzeug\nsaved=next('+expression+')\nsaved.member=value')
    root = tree.body[1].value
    visits_by_traversal = {}
    previous_profile = sys.getprofile()

    def profile(frame, event, arg):
        if event == 'call' and frame.f_code.co_name == 'sequence_iteration_values':
            parent = frame.f_back
            if parent.f_code.co_name == 'iterator_advance_sources' and parent.f_locals.get('value') is root:
                visits_by_traversal[parent] = visits_by_traversal.get(parent, 0) + 1

    try:
        sys.setprofile(profile)
        result = module_dynamic_namespace(tree)
        counts = list(visits_by_traversal.values())
    finally:
        sys.setprofile(previous_profile)
        visits_by_traversal.clear()
    assert result == (True, frozenset())
    assert counts
    assert max(counts) == 1
