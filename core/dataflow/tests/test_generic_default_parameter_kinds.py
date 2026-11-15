"""Owned generic default receivers qualify parameter-kind identity refusals."""

import pytest

from core.dataflow.source_identity import known_python_identity_conflict


@pytest.mark.parametrize(
    "source,name,selected,receiver",
    [
        (
            'import html\ndef helper[**html = html.escape("<owned>")]():\n    pass\n',
            "helper",
            0,
            0,
        ),
        (
            'import html\ndef helper[*html = *html.escape("<owned>")]():\n    pass\n',
            "helper",
            0,
            0,
        ),
        (
            'import html\ndef helper[**html, Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            1,
            0,
        ),
        (
            'import html\ndef helper[*html, Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            1,
            0,
        ),
        (
            'import html\ndef helper[Other = html.escape("<owned>"), html = int]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\nasync def helper[html = html.escape("<owned>")]():\n    pass\n',
            "helper",
            0,
            0,
        ),
        (
            'import html\nasync def helper[**html = html.escape("<owned>")]():\n    pass\n',
            "helper",
            0,
            0,
        ),
        (
            'import html\nasync def helper[*html = *html.escape("<owned>")]():\n    pass\n',
            "helper",
            0,
            0,
        ),
        (
            'import html\nasync def helper[html, Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            1,
            0,
        ),
        (
            'import html\nasync def helper[**html, Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            1,
            0,
        ),
        (
            'import html\nasync def helper[*html, Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            1,
            0,
        ),
        (
            'import html\nasync def helper[Other = html.escape("<owned>"), html = int]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\nclass Holder[**html = html.escape("<owned>")]:\n    pass\n',
            "Holder",
            0,
            0,
        ),
        (
            'import html\nclass Holder[*html = *html.escape("<owned>")]:\n    pass\n',
            "Holder",
            0,
            0,
        ),
        (
            'import html\nclass Holder[**html, Other = html.escape("<owned>")]:\n    pass\n',
            "Holder",
            1,
            0,
        ),
        (
            'import html\nclass Holder[Other = html.escape("<owned>"), html = int]:\n    pass\n',
            "Holder",
            0,
            1,
        ),
        (
            'import html\ntype Alias[**html = html.escape("<owned>")] = int\n',
            "Alias",
            0,
            0,
        ),
        (
            'import html\ntype Alias[*html = *html.escape("<owned>")] = int\n',
            "Alias",
            0,
            0,
        ),
        (
            'import html\ntype Alias[**html, Other = html.escape("<owned>")] = int\n',
            "Alias",
            1,
            0,
        ),
        (
            'import html\ntype Alias[*html, Other = html.escape("<owned>")] = int\n',
            "Alias",
            1,
            0,
        ),
        (
            'import html\ntype Alias[Other = html.escape("<owned>"), html = int] = int\n',
            "Alias",
            0,
            1,
        ),
        (
            'import html\ndef helper[Other = html.escape("<owned>"), **html = int]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\ndef helper[Other = html.escape("<owned>"), *html = *tuple[int]]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\nasync def helper[Other = html.escape("<owned>"), **html = int]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\nasync def helper[Other = html.escape("<owned>"), *html = *tuple[int]]():\n    pass\n',
            "helper",
            0,
            1,
        ),
        (
            'import html\nclass Holder[Other = html.escape("<owned>"), **html = int]:\n    pass\n',
            "Holder",
            0,
            1,
        ),
        (
            'import html\nclass Holder[Other = html.escape("<owned>"), *html = *tuple[int]]:\n    pass\n',
            "Holder",
            0,
            1,
        ),
        (
            'import html\ntype Alias[Other = html.escape("<owned>"), **html = int] = int\n',
            "Alias",
            0,
            1,
        ),
        (
            'import html\ntype Alias[Other = html.escape("<owned>"), *html = *tuple[int]] = int\n',
            "Alias",
            0,
            1,
        ),
    ],
    ids=[
        "function-own-paramspec",
        "function-own-tuple",
        "function-earlier-paramspec",
        "function-earlier-tuple",
        "function-later-typevar",
        "async-own-typevar",
        "async-own-paramspec",
        "async-own-tuple",
        "async-earlier-typevar",
        "async-earlier-paramspec",
        "async-earlier-tuple",
        "async-later-typevar",
        "class-own-paramspec",
        "class-own-tuple",
        "class-earlier-paramspec",
        "class-later-typevar",
        "alias-own-paramspec",
        "alias-own-tuple",
        "alias-earlier-paramspec",
        "alias-earlier-tuple",
        "alias-later-typevar",
        "function-later-paramspec",
        "function-later-tuple",
        "async-later-paramspec",
        "async-later-tuple",
        "class-later-paramspec",
        "class-later-tuple",
        "alias-later-paramspec",
        "alias-later-tuple",
    ],
)
def test_generic_default_runtime_receiver_requires_refusal(
    source, name, selected, receiver
):
    namespace = {"__name__": "owned_generic_default_kind"}
    exec(
        compile(source, "<owned-generic-default-kind>", "exec", dont_inherit=True),
        namespace,
    )
    parameters = namespace[name].__type_params__
    with pytest.raises(AttributeError, match="escape") as failure:
        _ = parameters[selected].__default__
    assert failure.value.obj is parameters[receiver]
    assert known_python_identity_conflict(source, 2, ("html.escape",))


@pytest.mark.parametrize(
    "source,name,unpacked",
    [
        (
            'import html\ndef helper[**Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            False,
        ),
        (
            'import html\nasync def helper[Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            False,
        ),
        (
            'import html\nasync def helper[**Other = html.escape("<owned>")]():\n    pass\n',
            "helper",
            False,
        ),
        (
            'import html\nclass Holder[**Other = html.escape("<owned>")]:\n    pass\n',
            "Holder",
            False,
        ),
        (
            'import html\ntype Alias[**Other = html.escape("<owned>")] = int\n',
            "Alias",
            False,
        ),
        (
            'import html\ndef helper[*Other = *tuple[html.escape("<owned>")]]():\n    pass\n',
            "helper",
            True,
        ),
        (
            'import html\nasync def helper[*Other = *tuple[html.escape("<owned>")]]():\n    pass\n',
            "helper",
            True,
        ),
        (
            'import html\nclass Holder[*Other = *tuple[html.escape("<owned>")]]:\n    pass\n',
            "Holder",
            True,
        ),
        (
            'import html\ntype Alias[*Other = *tuple[html.escape("<owned>")]] = int\n',
            "Alias",
            True,
        ),
    ],
    ids=[
        "function-module-paramspec",
        "async-module-typevar",
        "async-module-paramspec",
        "class-module-paramspec",
        "alias-module-paramspec",
        "function-module-tuple-wrapped",
        "async-module-tuple-wrapped",
        "class-module-tuple-wrapped",
        "alias-module-tuple-wrapped",
    ],
)
def test_generic_default_module_receiver_remains_available(source, name, unpacked):
    namespace = {"__name__": "owned_module_default_kind"}
    exec(
        compile(source, "<owned-module-default-kind>", "exec", dont_inherit=True),
        namespace,
    )
    value = namespace[name].__type_params__[0].__default__
    if unpacked:
        assert value.__args__ == ("&lt;owned&gt;",)
    else:
        assert value == "&lt;owned&gt;"
    assert known_python_identity_conflict(source, 2, ("html.escape",)) is None


@pytest.mark.parametrize("definition", [
    'async def helper[**escaped = escaped.escape("owned")]():\n    pass\n',
    'def helper[*escaped = *escaped.escape("owned")]():\n    pass\n',
    'class Holder[Other = escaped.escape("owned"), **escaped = int]:\n    pass\n',
    'type Alias[Other = escaped.escape("owned"), *escaped = *tuple[int]] = int\n',
])
def test_default_parameter_kind_uses_written_import_spelling(definition):
    assert known_python_identity_conflict('import html as escaped\n' + definition, 2, ('html.escape',))


def test_generic_default_kinds_do_not_leak_to_module_call():
    source = ('import html\nasync def helper[**html = int]():\n    pass\n'
              'class Holder[*html = *tuple[int]]:\n    pass\n'
              'type Alias[**html = int] = int\nvalue = html.escape("owned")\n')
    assert known_python_identity_conflict(source, 7, ('html.escape',)) is None
