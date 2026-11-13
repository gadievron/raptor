"""Literal set algebra methods retain existing element references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_literal_set_union_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}.union({werkzeug.utils})))', 'saved.secure_filename=replacement') is False


def test_literal_set_difference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}.difference({None})))', 'saved.secure_filename=replacement') is False


def test_literal_set_intersection_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}.intersection({werkzeug.utils})))', 'saved.secure_filename=replacement') is False


def test_literal_set_symmetric_difference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}.symmetric_difference({*[]})))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter({werkzeug.utils}.union()))',
    'next(iter({werkzeug.utils}.intersection()))',
    'next(iter({werkzeug.utils}.difference()))',
    'list({None}.union({werkzeug.utils},{None}))[0]',
])
def test_literal_set_method_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({None}.difference({werkzeug})))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({None}.intersection({werkzeug})))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({werkzeug}.union(holder)))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(holder.union({werkzeug})))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({werkzeug}.symmetric_difference()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({(werkzeug,)}.difference({None})))\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}.union({werkzeug})\nsaved.clear()',
])
def test_right_only_subset_sources_unknown_methods_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
