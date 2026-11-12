"""An integer RHS does not establish integer semantics after float widening."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE  # noqa: E402


def constant_sink(type_name, expression):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = (
        'class T {\nvoid handle(String raw, java.io.PrintWriter w) {\n'
        + type_name + ' ratio = 1;\nString out = ' + expression
        + ' ? "safe" : raw;\nw.println(out);\n}\n}'
    )
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    return all_definers_constant(reaching_defs(cfg), sink, 'out',
                                JavaConstIndex(source, (1, 8)),
                                union_member_check=lambda _: True)


def test_float_local_cannot_use_integer_division_to_select_the_sink_value():
    # Java ratio / 2 is 0.5f; integer folding previously selected the safe arm.
    assert constant_sink('float', 'ratio / 2 == 0') is None


@pytest.mark.parametrize('type_name', ['float', 'double'])
@pytest.mark.parametrize('expression', ['ratio / 2 == 0', 'String.valueOf(ratio).length() == 1'])
def test_floating_declaration_refuses_before_integer_value_consumption(type_name, expression):
    assert constant_sink(type_name, expression) is None


@pytest.mark.parametrize('type_name', ['int', 'long', 'var'])
def test_existing_integer_division_control_remains(type_name):
    assert constant_sink(type_name, 'ratio / 2 == 0') is not None


@pytest.mark.parametrize('type_name', ['float', 'double'])
@pytest.mark.parametrize('kind', ['field', 'method'])
def test_cross_file_floating_boundaries_cannot_serve_integer_rhs(tmp_path, type_name, kind):
    from core.analysis.java_xfile_const import make_xfile_resolver

    declaration = (f'static final {type_name} RATIO = 1;' if kind == 'field'
                   else f'static {type_name} ratio() {{ return 1; }}')
    (tmp_path / 'Cfg.java').write_text('class Cfg { ' + declaration + ' }', encoding='utf-8')
    caller = tmp_path / 'T.java'
    caller.write_text('class T {}', encoding='utf-8')
    resolver = make_xfile_resolver(str(caller), str(tmp_path))
    assert resolver is not None and resolver.ok
    if kind == 'field':
        assert resolver.resolve_field('Cfg', 'RATIO', False) is REFUSE
    else:
        assert resolver.resolve_method('Cfg', 'ratio', 0, False) is REFUSE
