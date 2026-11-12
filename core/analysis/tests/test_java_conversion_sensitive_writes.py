"""Later numeric writes cannot bypass a conversion-sensitive declaration."""

import pytest

pytest.importorskip("tree_sitter_java")


def constant_sink(declarations, condition, *, parameters='', extra=''):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    suffix = ', ' + parameters if parameters else ''
    source = (
        'class T {\nvoid handle(String raw, java.io.PrintWriter w' + suffix + ') {\n'
        + declarations + '\nString out = ' + condition + ' ? "safe" : raw;\n'
        'w.println(out);\n}\n' + extra + '\n}'
    )
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    return all_definers_constant(reaching_defs(cfg), sink, 'out',
                                JavaConstIndex(source, (1, source.count('\n') + 1)),
                                union_member_check=lambda _: True)


def test_float_reassignment_cannot_reenter_the_integer_model():
    assert constant_sink('float ratio = 0;\nratio = 1;', 'ratio / 2 == 0') is None


@pytest.mark.parametrize('type_name', ['float', 'double'])
def test_floating_parameter_reassignment_also_refuses(type_name):
    assert constant_sink('ratio = 1;', 'ratio / 2 == 0',
                         parameters=type_name + ' ratio') is None


def test_character_reassignment_cannot_keep_the_integer_rhs_value():
    assert constant_sink("char code = 'b';\ncode = 97;",
                         'String.valueOf(code).length() == 2') is None


def test_character_parameter_reassignment_refuses():
    assert constant_sink('code = 97;', 'String.valueOf(code).length() == 2',
                         parameters='char code') is None


@pytest.mark.parametrize('type_name', ['int', 'long'])
def test_ordinary_integer_reassignment_control_remains(type_name):
    assert constant_sink(type_name + ' ratio = 0;\nratio = 1;', 'ratio / 2 == 0') is not None


def test_name_ambiguity_across_methods_only_causes_refusal():
    # File-wide name poisoning grants no type authority to the other method.
    assert constant_sink('int ratio = 0;\nratio = 1;', 'ratio / 2 == 0',
                         extra='void other() { float ratio = 1; }') is None


def test_direct_character_declaration_still_retains_its_known_kind():
    assert constant_sink("char code = 'a';", 'String.valueOf(code).length() == 1') is not None


def test_declaration_outside_the_indexed_line_span_still_blocks_conversion():
    from core.analysis.const_fold_java import JavaConstIndex

    source = "class T {\nvoid handle() {\nfloat ratio = 0;\nratio = 1;\n}\n}"
    index = JavaConstIndex(source, (4, 4))
    assert index.ok
    assert index.rhs_at(4, 'ratio') is None


def test_enhanced_for_character_binding_also_blocks_later_numeric_rhs():
    from core.analysis.const_fold_java import JavaConstIndex

    source = "class T {\nvoid handle(char[] values) {\nfor (char code : values) {\ncode = 97;\n}\n}\n}"
    index = JavaConstIndex(source, (1, 8))
    assert index.ok
    assert index.rhs_at(4, 'code') is None
