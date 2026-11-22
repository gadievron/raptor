"""Sink copy facts are exact by construction or absent entirely."""

import pytest

from core.audit.sink_extents import (
    sink_buffer_sizes,
    sink_copy_facts,
    sink_size_signedness,
)

SINKS = frozenset({"memcpy", "memmove", "strncpy", "strncat", "bcopy", "wmemcpy"})


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip('tree_sitter_c')


def guards_for(source, file_path='unit.c'):
    from core.audit.condition_extraction import extract_sink_guards
    guards = extract_sink_guards(source, file_path, sink_names=SINKS)
    assert guards, 'test source must contain a recognized sink call'
    return guards


def derive(source, *, integer_abi='lp64', file_path='unit.c'):
    return sink_buffer_sizes(source, guards_for(source, file_path),
                             file_path=file_path, integer_abi=integer_abi)


def signedness(source, *, integer_abi='lp64', file_path='unit.c'):
    return sink_size_signedness(source, guards_for(source, file_path),
                                file_path=file_path, integer_abi=integer_abi)


GUARDED = """void F(unsigned n, const char *s) {
    char buf[64];
    if (n < 64) {
        memcpy(buf, s, n);
    }
}"""


@pytest.mark.parametrize('file_path', ['unit.c', 'unit.cc'])
def test_a_guarded_character_copy_derives_its_capacity(file_path):
    if file_path.endswith('.cc'):
        pytest.importorskip('tree_sitter_cpp')
    assert derive(GUARDED, file_path=file_path) == {4: 64}


def test_scope_inert_statements_may_precede_the_call():
    # Declarations with literal initializers cannot splice a hidden
    # macro declaration into the scope, and control statements reclose
    # any scope they open before the call runs.
    source = """void F(unsigned n, const char *s) {
    char buf[64];
    int limit = 64;
    if (n > 63) return;
    memcpy(buf, s, n);
}"""
    assert derive(source) == {5: 64}


def test_comments_may_precede_the_call_in_an_inner_scope():
    source = """void F(unsigned n, const char *s) {
    char buf[64];
    if (n < 64) {
        /* bounded copy */
        memcpy(buf, s, n);
    }
}"""
    assert derive(source) == {5: 64}


@pytest.mark.parametrize('abi, capacity', [('lp64', 64), ('llp64', 64), ('i16', 32)])
def test_element_width_follows_the_resolved_abi(abi, capacity):
    source = """void F(unsigned n, const int *s) {
    int buf[16];
    if (n < 64) memcpy(buf, s, n);
}"""
    assert derive(source, integer_abi=abi) == {3: capacity}


def test_without_an_abi_only_character_elements_have_a_sizeof():
    ints = """void F(unsigned n, const int *s) {
    int buf[16];
    memcpy(buf, s, n);
}"""
    chars = """void F(unsigned n, const char *s) {
    unsigned char buf[64];
    memcpy(buf, s, n);
}"""
    assert derive(ints, integer_abi=None) == {}
    assert derive(chars, integer_abi=None) == {3: 64}


def test_bcopy_takes_its_destination_second():
    source = """void F(unsigned n, const char *s) {
    char buf[32];
    if (n < 32) bcopy(s, buf, n);
}"""
    assert derive(source) == {3: 32}


def test_an_initializer_never_changes_a_literal_extent():
    source = """void F(unsigned n, const char *s) {
    char buf[64] = {0};
    memmove(buf, s, n);
}"""
    assert derive(source) == {3: 64}


@pytest.mark.parametrize('spelling, verdict', [
    ('unsigned', 'unsigned'), ('unsigned long', 'unsigned'),
    ('size_t', 'unsigned'), ('uint32_t', 'unsigned'),
    ('int', 'signed'), ('long', 'signed'),
    ('ssize_t', 'signed'), ('int64_t', 'signed'),
])
def test_the_size_arguments_declared_signedness_is_read_exactly(spelling, verdict):
    source = """void F(%s n, const char *s) {
    char buf[64];
    if (n < 64) {
        memcpy(buf, s, n);
    }
}""" % spelling
    assert signedness(source) == {4: verdict}


def test_a_local_size_declaration_also_binds_signedness():
    source = """void F(const char *s) {
    char buf[64];
    size_t n = 8;
    memcpy(buf, s, n);
}"""
    assert signedness(source) == {4: 'unsigned'}
    assert derive(source) == {4: 64}


@pytest.mark.parametrize('source', [
    # An unknown type spelling binds nothing.
    'void F(myint n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n);\n}',
    # A typedef of a size-type word could change its signedness.
    'typedef int size_t;\nvoid F(size_t n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n);\n}',
    # A second visible declaration of the size name is ambiguous.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    if (s) {\n        int n = 1;\n        memcpy(buf, s, n);\n    }\n}',
    # A pointer parameter is not a plain size object.
    'void F(unsigned *n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n);\n}',
    # A non-literal initializer on the size declaration could be a macro.
    'void F(const char *s) {\n    char buf[64];\n    size_t n = g();\n    memcpy(buf, s, n);\n}',
    # The size declaration must already be in scope at the call.
    'void F(const char *s) {\n    char buf[64];\n    memcpy(buf, s, n);\n    size_t n = 8;\n}',
])
def test_unprovable_signedness_binds_nothing(source):
    assert signedness(source) == {}


@pytest.mark.parametrize('source', [
    # The wide copier counts wide characters, not bytes.
    'void F(unsigned n, const int *s) {\n    int buf[16];\n    wmemcpy(buf, s, n);\n}',
    # The appender also writes after existing content.
    'void F(unsigned n, const char *s) {\n    char buf[16];\n    strncat(buf, s, n);\n}',
    # A parameter destination has no visible extent.
    'void F(char *buf, const char *s, unsigned n) {\n    memcpy(buf, s, n);\n}',
    # Only a bare identifier binds the whole object at offset zero.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    memcpy(buf + 1, s, n);\n}',
    # A non-identifier size expression breaks the per-variable length model.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n + 1);\n}',
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n / 2);\n}',
    # A third occurrence of the name is unaccounted use.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, sizeof(buf));\n}',
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    memset(buf, 0, 64);\n    memcpy(buf, s, n);\n}',
    # A visible nested redeclaration changes what the name denotes.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    if (n < 64) {\n        char buf[4];\n        memcpy(buf, s, n);\n    }\n}',
    # A preceding statement anywhere on the scope chain could be a
    # macro splicing a declaration into a still-open scope.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    g();\n    memcpy(buf, s, n);\n}',
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    if (n < 64) {\n        n = n + 1;\n        memcpy(buf, s, n);\n    }\n}',
    # So could a declaration whose initializer is not literal.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    int q = g();\n    memcpy(buf, s, n);\n}',
    # A variable extent is not a literal capacity.
    'void F(unsigned n, const char *s) {\n    char buf[n];\n    memcpy(buf, s, n);\n}',
    # Nested extents, pointer elements and aggregates are other objects.
    'void F(unsigned n, const char *s) {\n    char buf[4][8];\n    memcpy(buf, s, n);\n}',
    'void F(unsigned n, const char *s) {\n    char *buf[8];\n    memcpy(buf, s, n);\n}',
    'struct T { int x; };\nvoid F(unsigned n, const char *s) {\n    struct T buf[4];\n    memcpy(buf, s, n);\n}',
    # Storage specifiers and extra declarators leave the canonical shape.
    'void F(unsigned n, const char *s) {\n    static char buf[64];\n    memcpy(buf, s, n);\n}',
    'void F(unsigned n, const char *s) {\n    char buf[64], *p;\n    memcpy(buf, s, n);\n}',
    # Preprocessor expansion could change resolution or extents.
    '#define buf other\nvoid F(unsigned n, const char *s) {\n    char buf[64];\n    memcpy(buf, s, n);\n}',
    'void F(unsigned n, const char *s) {\n    char buf[64];\n#ifdef X\n    g();\n#endif\n    memcpy(buf, s, n);\n}',
    # A shadowed callee is not the modeled library routine.
    'void F(unsigned n, const char *s, void (*memcpy)(void *, const void *, unsigned)) {\n    char buf[64];\n    memcpy(buf, s, n);\n}',
    # Two matching calls on one line cannot share a per-line capacity.
    'void F(unsigned n, const char *s) {\n    char buf[64];\n    char two[8];\n    memcpy(buf, s, n); memcpy(two, s, n);\n}',
    # The declaration must precede the call.
    'void F(unsigned n, const char *s) {\n    memcpy(buf, s, n);\n    char buf[64];\n}',
])
def test_unmodeled_shapes_derive_no_capacity(source):
    assert derive(source) == {}


def test_non_c_sources_and_hostile_inputs_derive_nothing():
    assert sink_copy_facts(GUARDED, [], file_path='unit.c', integer_abi='lp64') == {}
    assert sink_copy_facts(None, [object()], file_path='unit.c', integer_abi='lp64') == {}
    guards = guards_for(GUARDED)
    assert sink_copy_facts(GUARDED, guards, file_path='unit.py', integer_abi='lp64') == {}
    assert sink_copy_facts('x' * ((1 << 21) + 1), guards, file_path='unit.c',
                           integer_abi='lp64') == {}


def sufficiency_verdicts(source):
    from core.audit.condition_smt import check_all_sufficiency
    guards = guards_for(source)
    sizes = sink_buffer_sizes(source, guards, file_path='unit.c', integer_abi='lp64')
    signs = sink_size_signedness(source, guards, file_path='unit.c', integer_abi='lp64')
    results = check_all_sufficiency(guards, buffer_sizes=sizes, size_signedness=signs)
    return [r for group in results for r in group]


def test_facts_decide_the_copy_length_sufficiency_verdict():
    pytest.importorskip('z3')
    # An unsigned length under a strict upper bound within capacity is a
    # proof of sufficiency: no non-negative value exceeds 64.
    safe = [r.feasible for r in sufficiency_verdicts(GUARDED)]
    assert safe == [False], safe
    # The same guard fails for a wider bound, with a real witness.
    insufficient = sufficiency_verdicts("""void F(unsigned n, const char *s) {
    char buf[64];
    if (n <= 128) {
        memcpy(buf, s, n);
    }
}""")
    assert [r.feasible for r in insufficient] == [True]
    assert all(value >= 0 for value in insufficient[0].witness.values())
    # A signed length under the same guard admits a negative value that
    # reinterprets as a huge copy — the classic signedness bypass.
    signed = sufficiency_verdicts("""void F(int n, const char *s) {
    char buf[64];
    if (n < 64) {
        memcpy(buf, s, n);
    }
}""")
    assert [r.feasible for r in signed] == [True]
    assert any(value < 0 for value in signed[0].witness.values())


def test_underived_signedness_never_mints_a_negative_witness_verdict():
    pytest.importorskip('z3')
    # The size argument's type is unknown (unknown spelling), so the
    # negative-range witness is not evidence in either direction.
    results = sufficiency_verdicts("""void F(myint n, const char *s) {
    char buf[64];
    if (n < 64) {
        memcpy(buf, s, n);
    }
}""")
    assert [r.feasible for r in results] == [None]
    assert 'signedness' in results[0].reasoning


def test_the_orchestrator_wires_derived_facts_into_sufficiency():
    import inspect

    from core.audit import orchestrator
    text = inspect.getsource(orchestrator)
    assert 'from .sink_extents import sink_copy_facts as _sink_extents' in text
    assert 'size_signedness=sink_signs' in text
    assert 'str(_sink_extents is not None)' in text
