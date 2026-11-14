"""Curated alias observations require an owned unambiguous code view."""

import importlib
from types import SimpleNamespace

import pytest

from core.audit import source_view

analyze = importlib.import_module("packages.source_intel.analyze")


def _scan(tmp_path, monkeypatch, raw, blanked, ambiguous=False):
    path = tmp_path / "owned.c"
    path.write_text("owned metadata placeholder\n")
    reads, views = [], []

    def reader(entry):
        assert entry == path
        reads.append(entry)
        return raw, False

    def view(text, file_path):
        assert text == raw and file_path == str(path)
        views.append(file_path)
        return SimpleNamespace(text=blanked, ambiguous=ambiguous)

    monkeypatch.setattr(analyze, "read_text_capped", reader)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    records = analyze._scan_alias_in_file(path)
    assert reads == [path]
    return records, views, path


@pytest.mark.parametrize("raw", [
    "/* __must_check is documentation */\nint owned(char *p);\n",
    'const char *s = "__must_check";\nint owned(char *p);\n',
], ids=["comment", "string"])
def test_curated_alias_mentions_require_code_view(tmp_path, monkeypatch, raw):
    blanked = " " * len(raw.split("\n")[0]) + "\nint owned(char *p);\n"
    records, views, path = _scan(tmp_path, monkeypatch, raw, blanked)
    assert records == [] and views == [str(path)]


@pytest.mark.parametrize("spelling", [
    "__must_check", "__attribute__((warn_unused_result))", "[[nodiscard]]",
])
@pytest.mark.parametrize("ambiguous", [False, True])
def test_curated_alias_code_and_ambiguity(tmp_path, monkeypatch, spelling, ambiguous):
    text = f"\n{spelling} int owned(char *p);\n"
    records, views, path = _scan(tmp_path, monkeypatch, text, text, ambiguous)
    assert views == [str(path)]
    if ambiguous:
        assert records == []
    else:
        assert len(records) == 1
        record = records[0]
        assert record.kind == "wur" and record.function_name == "owned"
        assert record.location == (str(path), 2)
        assert record.match_source == "known_alias" and record.raw_match == spelling


def test_curated_alias_definition_stays_excluded(tmp_path, monkeypatch):
    text = "#define __must_check __attribute__((warn_unused_result))\n"
    records, _, _ = _scan(tmp_path, monkeypatch, text, text)
    assert records == []


def test_curated_alias_read_refusal_never_requests_view(tmp_path, monkeypatch):
    path = tmp_path / "owned.c"
    path.write_text("owned metadata placeholder\n")
    monkeypatch.setattr(analyze, "read_text_capped", lambda _: None)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", lambda *_: pytest.fail(
        "refused read must not request a lexical view",
    ))
    assert analyze._scan_alias_in_file(path) == []
