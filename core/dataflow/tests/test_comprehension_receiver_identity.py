"""Owned comprehension receiver bindings cannot stand in for module libraries."""

import pytest

from core.dataflow.source_identity import known_python_identity_conflict


PREFIX = (
    "import html\nreceivers = []\nclass Local:\n    @classmethod\n"
    "    def escape(cls, value):\n        receivers.append(cls)\n        return value\n"
)


@pytest.mark.parametrize(
    "kind,source",
    [
        (
            "list-body",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = [html.escape("<owned>") for html in (Local,)]\n',
        ),
        (
            "set-body",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = {html.escape("<owned>") for html in (Local,)}\n',
        ),
        (
            "dict-value",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = {0: html.escape("<owned>") for html in (Local,)}\n',
        ),
        (
            "dict-key",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = {html.escape("<owned>"): 0 for html in (Local,)}\n',
        ),
        (
            "generator-body",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = (html.escape("<owned>") for html in (Local,))\n',
        ),
        (
            "filter",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = [value for html in (Local,) for value in ("<owned>",) if html.escape(value)]\n',
        ),
        (
            "later-iterable",
            'import html\nreceivers = []\nclass Local:\n    @classmethod\n    def escape(cls, value):\n        receivers.append(cls)\n        return value\nresult = [value for html in (Local,) for value in (html.escape("<owned>"),)]\n',
        ),
    ],
    ids=[
        "list-body",
        "set-body",
        "dict-value",
        "dict-key",
        "generator-body",
        "filter",
        "later-iterable",
    ],
)
def test_comprehension_owned_receiver_requires_identity_refusal(kind, source):
    namespace = {"__name__": "owned_comprehension_identity"}
    exec(
        compile(source, "<owned-comprehension-identity>", "exec", dont_inherit=True),
        namespace,
    )
    result = namespace["result"]
    if kind == "generator-body":
        result = list(result)
    assert namespace["receivers"]
    assert all(receiver is namespace["Local"] for receiver in namespace["receivers"])
    assert "<owned>" in repr(result)
    assert known_python_identity_conflict(source, 8, ("html.escape",))


def test_first_iterable_preserves_module_receiver():
    source = (
        PREFIX
        + 'result = [value for html, value in ((None, html.escape("<owned>")),)]\n'
    )
    namespace = {"__name__": "owned_first_iterable"}
    exec(
        compile(source, "<owned-first-iterable>", "exec", dont_inherit=True), namespace
    )
    assert namespace["result"] == ["&lt;owned&gt;"]
    assert namespace["receivers"] == []
    assert known_python_identity_conflict(source, 8, ("html.escape",)) is None


@pytest.mark.parametrize('expression', [
    '[html.escape("<owned>") for html, other in ((Local, None),)]',
    '[html.escape("<owned>") for html, *others in ((Local, None),)]',
    '[[value for value in (html.escape("<owned>"),)] for html in (Local,)]',
])
def test_nested_or_unpacked_comprehension_receiver_is_owned(expression):
    source = PREFIX + 'result = ' + expression + '\n'
    namespace = {'__name__': 'owned_nested_comprehension'}
    exec(compile(source, '<owned-nested-comprehension>', 'exec', dont_inherit=True), namespace)
    assert namespace['receivers'] == [namespace['Local']]
    assert known_python_identity_conflict(source, 8, ('html.escape',))


def test_comprehension_receiver_uses_written_import_spelling():
    source = PREFIX.replace('import html\n', 'import html as escaped\n') + 'result = [escaped.escape("owned") for escaped in (Local,)]\n'
    assert known_python_identity_conflict(source, 8, ('html.escape',))


def test_unrelated_comprehension_target_preserves_module_receiver():
    source = PREFIX + 'result = [html.escape("<owned>") for other in (Local,)]\n'
    namespace = {'__name__': 'owned_unrelated_comprehension'}
    exec(compile(source, '<owned-unrelated-comprehension>', 'exec', dont_inherit=True), namespace)
    assert namespace['result'] == ['&lt;owned&gt;']
    assert namespace['receivers'] == []
    assert known_python_identity_conflict(source, 8, ('html.escape',)) is None


def test_target_subscript_expression_does_not_bind_its_nested_names():
    source = PREFIX + 'holder = [None]\nresult = [html.escape("<owned>") for holder[[0 for html in (0,)][0]] in (None,)]\n'
    namespace = {'__name__': 'owned_target_expression'}
    exec(compile(source, '<owned-target-expression>', 'exec', dont_inherit=True), namespace)
    assert namespace['result'] == ['&lt;owned&gt;']
    assert namespace['receivers'] == []
    assert known_python_identity_conflict(source, 9, ('html.escape',)) is None


def test_nested_lambda_retains_existing_comprehension_refusal():
    source = PREFIX + 'result = [(lambda: html.escape("<owned>"))() for html in (Local,)]\n'
    assert known_python_identity_conflict(source, 8, ('html.escape',))


def test_first_iterable_existing_object_escape_refusal_is_preserved():
    source = PREFIX + 'result = [html for html in (html.escape("<owned>"),)]\n'
    assert known_python_identity_conflict(source, 8, ('html.escape',))


def test_comprehension_target_does_not_leak_to_module_call():
    source = PREFIX + 'result = [0 for html in (Local,)]\nvalue = html.escape("<owned>")\n'
    namespace = {'__name__': 'owned_comprehension_nonleakage'}
    exec(compile(source, '<owned-comprehension-nonleakage>', 'exec', dont_inherit=True), namespace)
    assert namespace['value'] == '&lt;owned&gt;'
    assert known_python_identity_conflict(source, 9, ('html.escape',)) is None
