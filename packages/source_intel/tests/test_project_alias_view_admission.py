"""Project aliases consume an owned blanked-view boundary, not raw mentions."""

import importlib
from types import SimpleNamespace

import pytest

from core.audit import source_view

analyze = importlib.import_module("packages.source_intel.analyze")


def _scan(tmp_path, monkeypatch, raw, blanked, ambiguous=False):
    path = tmp_path / "owned.c"
    path.write_text("owned metadata placeholder\n")
    reads = []
    views = []

    def read(entry):
        assert entry == path
        reads.append(entry)
        return raw, False

    def view(text, file_path):
        assert text == raw and file_path == str(path)
        views.append(file_path)
        return SimpleNamespace(text=blanked, ambiguous=ambiguous)

    monkeypatch.setattr(analyze, "read_text_capped", read)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    observations = analyze._scan_project_alias_observations(
        tmp_path, (("nonnull", ("OWNED_ALIAS",)),),
    )
    assert reads == [path]
    return observations, views, path


def test_project_alias_comment_requires_code_view(tmp_path, monkeypatch):
    observations, views, path = _scan(
        tmp_path, monkeypatch,
        "/* OWNED_ALIAS */\nint owned(char *p);\n",
        "                 \nint owned(char *p);\n",
    )
    assert observations == []
    assert views == [str(path)]


@pytest.mark.parametrize("raw,blanked", [
    ('const char *s = "OWNED_ALIAS";\n', "const char *s =              ;\n"),
    ('const char *s = R"x(\nOWNED_ALIAS\n)x";\n', "                    \n           \n    \n"),
])
def test_project_alias_literal_mentions_do_not_emit(tmp_path, monkeypatch, raw, blanked):
    observations, _, _ = _scan(tmp_path, monkeypatch, raw, blanked)
    assert observations == []


@pytest.mark.parametrize("ambiguous,expected", [(False, 1), (True, 0)])
def test_project_alias_code_requires_unambiguous_view(tmp_path, monkeypatch, ambiguous, expected):
    text = "\nOWNED_ALIAS int owned(char *p);\n"
    observations, views, path = _scan(tmp_path, monkeypatch, text, text, ambiguous)
    assert len(observations) == expected and views == [str(path)]
    if expected:
        record = observations[0]
        assert record.kind == "nonnull" and record.function_name == "owned"
        assert record.location == (str(path), 2)
        assert record.match_source == "project_alias" and record.raw_match == "OWNED_ALIAS"


def test_project_alias_definition_stays_excluded(tmp_path, monkeypatch):
    text = "#define OWNED_ALIAS __attribute__((nonnull))\n"
    observations, _, _ = _scan(tmp_path, monkeypatch, text, text)
    assert observations == []


def test_project_alias_read_refusal_never_requests_view(tmp_path, monkeypatch):
    path = tmp_path / "owned.c"
    path.write_text("owned metadata placeholder\n")
    monkeypatch.setattr(analyze, "read_text_capped", lambda _: None)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", lambda *_: pytest.fail(
        "refused read must not request a lexical view",
    ))
    assert analyze._scan_project_alias_observations(
        tmp_path, (("nonnull", ("OWNED_ALIAS",)),),
    ) == []
