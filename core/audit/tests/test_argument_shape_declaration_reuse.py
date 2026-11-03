"""Declaration reuse keeps function scope, first-match rules and retries."""

from dataclasses import asdict

import pytest

from core.audit import consistency_dimensions as dim
from core.testing import requires_ts

SOURCE = """
void pointer(char *buf) {
    take(sizeof(buf)); take(sizeof(buf));
    take(sizeof(unknown_t)); take(sizeof(unknown_t));
}
void array(void) {
    char buf[32];
    take(sizeof(buf)); take(sizeof(buf));
}
void value(void) {
    int buf;
    take(sizeof(buf)); take(sizeof(buf));
    take(sizeof(*buf)); take(sizeof(buf[0]));
}
"""


@requires_ts("c")
def test_full_site_output_and_function_isolation(monkeypatch):
    original = dim._classify_arg_shape
    calls = []
    declaration = dim._declared_kind

    def counted(node, ident, src):
        calls.append((node.id, ident))
        return declaration(node, ident, src)

    monkeypatch.setattr(dim, "_declared_kind", counted)
    actual = dim._extract_shape_sites({"a.c": SOURCE})
    assert len(calls) == 4  # buf in three functions plus unknown_t.
    assert {site.shape for sites in actual.values() for site in sites} == {
        "sizeof_pointer", "sizeof_array", "sizeof_other", "sizeof_type", "sizeof_deref"}
    calls.clear()
    monkeypatch.setattr(dim, "_classify_arg_shape",
                        lambda arg, node, src, **kw: original(arg, node, src))
    expected = dim._extract_shape_sites({"a.c": SOURCE})
    assert len(calls) == 8
    assert {key: [asdict(site) for site in sites] for key, sites in actual.items()} == {
        key: [asdict(site) for site in sites] for key, sites in expected.items()}


@requires_ts("c")
def test_different_files_and_changed_source_do_not_share(monkeypatch):
    declaration = dim._declared_kind
    calls = []

    def counted(*args):
        calls.append(args[1])
        return declaration(*args)

    monkeypatch.setattr(dim, "_declared_kind", counted)
    dim._extract_shape_sites({"a.c": SOURCE, "b.c": SOURCE})
    assert len(calls) == 8
    changed = dim._extract_shape_sites({"a.c": SOURCE.replace("char *buf", "char buf[8]")})
    assert len(calls) == 12
    assert changed[("take", 0)][0].shape == "sizeof_array"


def test_overflow_still_classifies(monkeypatch):
    calls = []
    monkeypatch.setattr(dim, "_declared_kind", lambda *args: calls.append(1) or ("pointer", "char *p"))
    cache = {(index, "other"): ("value", "int other") for index in range(256)}
    for _ in range(2):
        assert dim._classify_arg_shape("sizeof(p)", None, b"", _declaration_cache=cache) == (
            "sizeof_pointer", "char *p")
    assert len(calls) == 2
    assert len(cache) == 256


def test_exception_is_not_cached(monkeypatch):
    calls = []

    def declaration(*args):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("transient extraction failure")
        return "array", "char buf[8]"

    monkeypatch.setattr(dim, "_declared_kind", declaration)
    cache = {}
    with pytest.raises(ValueError):
        dim._classify_arg_shape("sizeof(buf)", None, b"", _declaration_cache=cache)
    assert cache == {}
    assert dim._classify_arg_shape("sizeof(buf)", None, b"", _declaration_cache=cache) == (
        "sizeof_array", "char buf[8]")
