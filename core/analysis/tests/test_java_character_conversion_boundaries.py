"""Source-declared character conversions must not expose an unchanged RHS."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE  # noqa: E402
from core.analysis.java_xfile_const import make_xfile_resolver  # noqa: E402


def resolver(tmp_path, declaration):
    (tmp_path / 'Cfg.java').write_text('class Cfg { ' + declaration + ' }', encoding='utf-8')
    caller = tmp_path / 'T.java'
    caller.write_text('class T {}', encoding='utf-8')
    result = make_xfile_resolver(str(caller), str(tmp_path))
    assert result is not None and result.ok
    return result


def test_method_character_widening_cannot_expose_a_character_value(tmp_path):
    result = resolver(tmp_path, "static int code() { return 'a'; }")
    assert result.resolve_method('Cfg', 'code', 0, False) is REFUSE


@pytest.mark.parametrize('kind,declaration', [
    ('method', 'static char code() { return 97; }'),
    ('field', "static final int CODE = 'a';"),
    ('field', 'static final char CODE = 97;'),
    ('method', "static long code() { return 'a'; }"),
])
def test_unmodelled_character_conversions_refuse_at_the_source_boundary(tmp_path, kind, declaration):
    result = resolver(tmp_path, declaration)
    if kind == 'method':
        assert result.resolve_method('Cfg', 'code', 0, False) is REFUSE
    else:
        assert result.resolve_field('Cfg', 'CODE', False) is REFUSE


@pytest.mark.parametrize('kind,declaration,expected', [
    ('method', "static char code() { return 'a'; }", 'a'),
    ('field', "static final char CODE = 'a';", 'a'),
    ('method', 'static int code() { return 97; }', 97),
    ('field', 'static final int CODE = 97;', 97),
    ('method', 'static String code() { return "a"; }', 'a'),
])
def test_identity_return_and_field_conversions_still_resolve(tmp_path, kind, declaration, expected):
    result = resolver(tmp_path, declaration)
    if kind == 'method':
        assert result.resolve_method('Cfg', 'code', 0, False) == expected
    else:
        assert result.resolve_field('Cfg', 'CODE', False) == expected


def test_same_class_field_indirection_cannot_bypass_the_conversion_check(tmp_path):
    result = resolver(tmp_path, "static final int CODE = 'a'; static int code() { return CODE; }")
    assert result.resolve_method('Cfg', 'code', 0, False) is REFUSE


def test_local_character_narrowing_cannot_select_integer_string_length():
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = '''class T {
void handle(String raw, java.io.PrintWriter w) {
char code = 97;
String out = String.valueOf(code).length() == 2 ? "safe" : raw;
w.println(out);
}
}'''
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    assert all_definers_constant(reaching_defs(cfg), sink, 'out',
                                JavaConstIndex(source, (1, 8)),
                                union_member_check=lambda _: True) is None
