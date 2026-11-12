"""Character-valued RHSs cannot bypass local assignment conversions."""

import pytest

pytest.importorskip("tree_sitter_java")


def constant_sink(declarations, condition):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = (
        'class T {\nvoid handle(String raw, java.io.PrintWriter w) {\n'
        + declarations + '\nString out = ' + condition + ' ? "safe" : raw;\n'
        + 'w.println(out);\n}\n}'
    )
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    index = JavaConstIndex(source, (1, source.count('\n') + 1))
    return all_definers_constant(reaching_defs(cfg), sink, 'out', index,
                                union_member_check=lambda _values: True)


def test_widened_character_local_cannot_select_character_string_length():
    # Runtime code is int 97; String.valueOf(code) has length 2, not 1.
    assert constant_sink("int code = 'a';", 'String.valueOf(code).length() == 1') is None


@pytest.mark.parametrize("declaration", [
    "long code = 'a';", 'int code = "a".charAt(0);',
    "char initial = 'a';\nint code = initial;",
    "int code = 0;\ncode = 'a';",
])
def test_unmodelled_character_assignment_conversions_refuse(declaration):
    assert constant_sink(declaration, 'String.valueOf(code).length() == 1') is None


@pytest.mark.parametrize("declaration", ["char code = 'a';", "var code = 'a';"])
def test_declared_or_inferred_character_local_keeps_character_semantics(declaration):
    assert constant_sink(declaration, 'String.valueOf(code).length() == 1') is not None


def test_integer_assignment_without_character_conversion_still_folds():
    assert constant_sink('int code = 97;', 'String.valueOf(code).length() == 2') is not None


def test_untyped_character_reassignment_refuses_instead_of_guessing():
    assert constant_sink("char code = 'b';\ncode = 'a';",
                         'String.valueOf(code).length() == 1') is None
