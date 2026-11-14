"""Alias frequency caps count owned code views, not prose mentions."""

import importlib
from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery

analyze = importlib.import_module("packages.source_intel.analyze")


def _count(tmp_path, monkeypatch, raw, blanked, ambiguous=False, forbid_view=False):
    path = tmp_path / "owned.c"
    path.touch()
    views = []
    monkeypatch.setattr(discovery, "_iter_source_files", lambda _: iter([path]))
    monkeypatch.setattr(discovery, "read_text_capped", lambda _: None if raw is None else (raw, False))

    def view(text, file_path):
        assert not forbid_view, "irrelevant/refused input must not request a view"
        assert text == raw and file_path == str(path)
        views.append(file_path)
        return SimpleNamespace(text=blanked, ambiguous=ambiguous)

    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    return discovery._count_usage([tmp_path], {"REAL_ALIAS", "DECOY"}), views


@pytest.mark.parametrize("raw", [
    'const char *s = "DECOY DECOY";\nREAL_ALIAS int owned(void);\n',
    '/* DECOY DECOY */\nREAL_ALIAS int owned(void);\n',
], ids=["string", "comment"])
def test_noncode_mentions_do_not_outweigh_code(tmp_path, monkeypatch, raw):
    blanked = " " * len(raw.split("\n")[0]) + "\nREAL_ALIAS int owned(void);\n"
    counts, views = _count(tmp_path, monkeypatch, raw, blanked)
    assert counts == {"REAL_ALIAS": 1, "DECOY": 0}
    assert len(views) == 1


def test_ambiguous_usage_view_does_not_mint_frequency(tmp_path, monkeypatch):
    raw = "REAL_ALIAS int owned(void);\n"
    counts, _ = _count(tmp_path, monkeypatch, raw, raw, ambiguous=True)
    assert counts == {"REAL_ALIAS": 0, "DECOY": 0}


def test_definition_exclusion_and_cross_macro_use_are_preserved(tmp_path, monkeypatch):
    raw = "#define REAL_ALIAS DECOY\nREAL_ALIAS int owned(void);\n"
    counts, _ = _count(tmp_path, monkeypatch, raw, raw)
    assert counts == {"REAL_ALIAS": 1, "DECOY": 1}


@pytest.mark.parametrize("raw", [None, "int unrelated(void);\n"], ids=["refused", "unrelated"])
def test_no_admitted_match_avoids_lexical_work(tmp_path, monkeypatch, raw):
    counts, views = _count(tmp_path, monkeypatch, raw, "", forbid_view=True)
    assert counts == {"REAL_ALIAS": 0, "DECOY": 0}
    assert views == []


def test_literal_only_decoys_do_not_fill_alias_cap(tmp_path, monkeypatch):
    header, source = tmp_path / "owned.h", tmp_path / "owned.c"
    header.touch()
    source.touch()
    decoys = [f"A{index:02}" for index in range(30)]
    header_text = "".join(
        f"#define {name} __attribute__((warn_unused_result))\n"
        for name in [*decoys, "REAL_ALIAS"]
    )
    prefix = "static const char *examples = "
    literal = '"' + " ".join(name for name in decoys for _ in range(2)) + '"'
    raw = prefix + literal + ";\nREAL_ALIAS int owned(void);\n"
    blanked = prefix + " " * len(literal) + ";\nREAL_ALIAS int owned(void);\n"
    texts = {header: header_text, source: raw}

    def read(path):
        assert path in texts
        return texts[path], False

    def view(text, file_path):
        path = type(header)(file_path)
        assert text == texts[path]
        return SimpleNamespace(text=header_text if path == header else blanked, ambiguous=False)

    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(discovery, "_iter_source_files", lambda _: iter([source]))
    monkeypatch.setattr(analyze, "read_text_capped", read)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    result = discovery.discover_aliases(tmp_path)
    assert result.aliases_by_family["wur"] == ("REAL_ALIAS",)
    observations = analyze._scan_project_alias_observations(
        tmp_path, tuple(sorted(result.aliases_by_family.items())),
    )
    assert len(observations) == 1 and observations[0].function_name == "owned"
