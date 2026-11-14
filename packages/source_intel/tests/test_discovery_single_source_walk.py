"""Usage counting and its scan census share one admitted iterator."""

from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery


def test_discovery_enumerates_usage_sources_once(tmp_path, monkeypatch):
    header = tmp_path / "owned.h"
    header.touch()
    source = tmp_path / "owned.c"
    source.touch()
    texts = {header: "#define OWNED __attribute__((warn_unused_result))\n",
             source: "OWNED int owned(void);\n"}
    walks = []

    def sources(roots):
        walks.append(tuple(roots))
        return iter([source])

    monkeypatch.setattr(discovery, "_iter_source_files", sources)
    monkeypatch.setattr(discovery, "read_text_capped", lambda p: (texts[p], False))
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda text, path: SimpleNamespace(text=text, ambiguous=False))
    result = discovery.discover_aliases(tmp_path)
    assert result.aliases_by_family["wur"] == ("OWNED",)
    assert result.sources_scanned == 1
    assert len(walks) == 1


@pytest.mark.parametrize("state", ["read-refused", "ambiguous", "no-mention", "counted"],
                         ids=["read-refused", "ambiguous", "no-mention", "counted"])
def test_scan_census_counts_admitted_entries_even_without_mentions(tmp_path, monkeypatch, state):
    source = tmp_path / "owned.c"
    monkeypatch.setattr(discovery, "_iter_source_files", lambda _: iter([source]))
    monkeypatch.setattr(discovery, "read_text_capped", lambda _: None if state == "read-refused" else
                        ("ordinary" if state == "no-mention" else "OWNED", False))
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda text, path: SimpleNamespace(text=text, ambiguous=state == "ambiguous"))
    counts, scanned = discovery._count_usage_with_scan_count([tmp_path], {"OWNED"})
    assert scanned == 1
    assert counts == {"OWNED": int(state == "counted")}


def test_empty_candidates_do_not_create_source_iterator(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "_iter_source_files", lambda _: pytest.fail("unexpected walk"))
    assert discovery._count_usage_with_scan_count([tmp_path], set()) == ({}, 0)
