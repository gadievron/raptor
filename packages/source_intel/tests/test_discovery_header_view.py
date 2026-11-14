"""Macro-family classification consumes an owned unambiguous header view."""

from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery


def _discover(tmp_path, monkeypatch, raw, blanked, ambiguous=False, joined=None):
    header, source = tmp_path / "owned.h", tmp_path / "owned.c"
    for path in (header, source):
        path.write_text("owned metadata placeholder\n")
    reads, views = [], []

    def read(path):
        reads.append(path)
        return (raw if path == header else "OWNED_CHECK int owned(void);\n"), False

    def view(text, file_path):
        if file_path == str(source):
            assert text == "OWNED_CHECK int owned(void);\n"
            return SimpleNamespace(text=text, ambiguous=False)
        assert file_path == str(header)
        assert text == (raw if joined is None else joined)
        views.append(file_path)
        return SimpleNamespace(text=blanked, ambiguous=ambiguous)

    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(discovery, "_iter_source_files", lambda *_: iter([source]))
    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    result = discovery.discover_aliases(tmp_path)
    assert reads[0] == header
    return result, views, header


@pytest.mark.parametrize("raw", [
    "#define OWNED_CHECK /* warn_unused_result */\n",
    '#define OWNED_CHECK "warn_unused_result"\n',
], ids=["comment", "string"])
def test_noncode_markers_do_not_classify_alias(tmp_path, monkeypatch, raw):
    blanked = "#define OWNED_CHECK " + " " * (len(raw) - len("#define OWNED_CHECK ") - 1) + "\n"
    result, views, header = _discover(tmp_path, monkeypatch, raw, blanked)
    assert not any(result.aliases_by_family.values())
    assert views == [str(header)]


@pytest.mark.parametrize("family,marker", [
    ("wur", "warn_unused_result"), ("nonnull", "nonnull"),
    ("alloc_size", "alloc_size"), ("returns_nonnull", "returns_nonnull"),
])
def test_code_markers_keep_family_classification(tmp_path, monkeypatch, family, marker):
    text = f"#define OWNED_CHECK __attribute__(({marker}))\n"
    result, views, header = _discover(tmp_path, monkeypatch, text, text)
    assert result.aliases_by_family[family] == ("OWNED_CHECK",)
    assert views == [str(header)]


def test_ambiguous_header_does_not_mint_alias(tmp_path, monkeypatch):
    text = "#define OWNED_CHECK __attribute__((warn_unused_result))\n"
    result, views, header = _discover(tmp_path, monkeypatch, text, text, ambiguous=True)
    assert not any(result.aliases_by_family.values())
    assert views == [str(header)]


def test_continuations_are_joined_before_view(tmp_path, monkeypatch):
    raw = "#define OWNED_CHECK \\\n__attribute__((warn_unused_result))\n"
    joined = "#define OWNED_CHECK  __attribute__((warn_unused_result))\n"
    result, _, _ = _discover(tmp_path, monkeypatch, raw, joined, joined=joined)
    assert result.aliases_by_family["wur"] == ("OWNED_CHECK",)


def test_refused_header_never_requests_view(tmp_path, monkeypatch):
    (tmp_path / "owned.h").write_text("owned metadata placeholder\n")
    monkeypatch.setattr(discovery, "read_text_capped", lambda *_: None)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", lambda *_: pytest.fail(
        "refused header must not request a lexical view",
    ))
    assert not any(discovery.discover_aliases(tmp_path).aliases_by_family.values())
