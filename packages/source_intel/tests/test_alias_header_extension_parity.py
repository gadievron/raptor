"""Declared C++ header spellings participate in alias usage frequency."""

from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery


@pytest.mark.parametrize("suffix", [".h", ".hpp", ".hh", ".hxx", ".HH", ".HXX"],
                         ids=["h", "hpp", "hh", "hxx", "upper-hh", "upper-hxx"])
def test_header_only_alias_use_survives_frequency_filter(tmp_path, monkeypatch, suffix):
    header = tmp_path / ("owned" + suffix)
    header.write_text("owned metadata placeholder\n")
    text = "#define OWNED_CHECK __attribute__((warn_unused_result))\nOWNED_CHECK int owned(void);\n"
    reads = []

    def read(path):
        assert path == header
        reads.append(path)
        return text, False

    def view(raw, file_path):
        assert raw == text and file_path == str(header)
        return SimpleNamespace(text=raw, ambiguous=False)

    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(source_view, "sanitized_view_with_status", view)
    result = discovery.discover_aliases(tmp_path)
    assert result.aliases_by_family["wur"] == ("OWNED_CHECK",)
    assert result.sources_scanned == 1
    assert reads == [header, header]


def test_new_header_spellings_still_share_existing_source_cap(tmp_path, monkeypatch):
    paths = {tmp_path / "one.hh", tmp_path / "two.hxx"}
    for path in paths:
        path.touch()
    monkeypatch.setattr(discovery, "_MAX_FILES_SOURCE_SCAN", 1)
    selected = list(discovery._iter_source_files([tmp_path]))
    assert len(selected) == 1 and selected[0] in paths


def test_header_like_suffix_stays_outside_frequency_inputs(tmp_path):
    (tmp_path / "owned.hh.bak").touch()
    assert list(discovery._iter_source_files([tmp_path])) == []
