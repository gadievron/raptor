"""Constant int narrowing plus Character boxing is outside the value model."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE  # noqa: E402


def constant_sink(type_name, initializer, *, reassign=False, parameter=False):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    params = ', ' + type_name + ' code' if parameter else ''
    declaration = '' if parameter else type_name + ' code = ' + initializer + ';\n'
    if reassign or parameter:
        declaration += 'code = 97;\n'
    source = (
        'class T {\nvoid handle(String raw, java.io.PrintWriter w' + params + ') {\n'
        + declaration + 'String out = String.valueOf(code).length() == 2 ? "safe" : raw;\n'
        'w.println(out);\n}\n}'
    )
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    return all_definers_constant(reaching_defs(cfg), sink, 'out',
                                JavaConstIndex(source, (1, source.count('\n') + 1)),
                                union_member_check=lambda _: True)


def test_boxed_character_cannot_keep_the_integer_initializer_string_value():
    # Assignment context permits constant 97 -> char 'a' -> Character.
    assert constant_sink('Character', '97') is None


@pytest.mark.parametrize('type_name', ['Character', 'java.lang.Character'])
@pytest.mark.parametrize('mode', ['declaration', 'reassignment', 'parameter'])
def test_boxed_character_numeric_conversions_refuse(type_name, mode):
    assert constant_sink(type_name, '98', reassign=mode == 'reassignment',
                         parameter=mode == 'parameter') is None


@pytest.mark.parametrize('type_name', ['int', 'Integer', 'java.lang.Integer'])
def test_numeric_string_conversion_controls_remain(type_name):
    assert constant_sink(type_name, '97') is not None


@pytest.mark.parametrize('type_name', ['Character', 'java.lang.Character'])
@pytest.mark.parametrize('kind', ['field', 'method'])
def test_cross_file_boxed_character_conversion_refuses(tmp_path, type_name, kind):
    from core.analysis.java_xfile_const import make_xfile_resolver

    declaration = (f'static final {type_name} CODE = 97;' if kind == 'field'
                   else f'static {type_name} code() {{ return 97; }}')
    (tmp_path / 'Cfg.java').write_text('class Cfg { ' + declaration + ' }', encoding='utf-8')
    caller = tmp_path / 'T.java'
    caller.write_text('class T {}', encoding='utf-8')
    resolver = make_xfile_resolver(str(caller), str(tmp_path))
    assert resolver is not None and resolver.ok
    if kind == 'field':
        assert resolver.resolve_field('Cfg', 'CODE', False) is REFUSE
    else:
        assert resolver.resolve_method('Cfg', 'code', 0, False) is REFUSE
