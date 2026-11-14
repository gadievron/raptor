"""Overlapping roots share the existing header-admission budget."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery


@pytest.mark.parametrize("state", ["readable", "read-refused", "view-refused", "in-root-link"],
                         ids=["readable", "read-refused", "view-refused", "in-root-link"])
def test_repeated_confined_header_does_not_spend_budget_twice(tmp_path, monkeypatch, state):
    include = tmp_path / "project" / "include"
    target = include / "subsystem"
    target.mkdir(parents=True)
    first = target / "first.h"
    second = include / "second.h"
    first.touch()
    second.touch()
    repeated = first
    if state == "in-root-link":
        repeated = include / "alias.h"
        repeated.symlink_to(first)
    reads = []
    texts = {first: "#define FIRST __attribute__((nonnull(1)))\n",
             second: "#define SECOND __attribute__((warn_unused_result))\n"}

    def entries(root, pattern):
        assert pattern == "*"
        assert root in (target, include)
        return iter([first] if root == target else [repeated, second])

    def read(path):
        reads.append(path)
        return None if state == "read-refused" and path == first else (texts[path], False)

    monkeypatch.setattr(Path, "rglob", entries)
    monkeypatch.setattr(discovery, "_MAX_FILES_HEADER_SCAN", 2)
    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(discovery, "_count_usage_with_scan_count",
                        lambda roots, names: (dict.fromkeys(names, 1), 0))
    monkeypatch.setattr(source_view, "sanitized_view_with_status",
                        lambda text, path: SimpleNamespace(
                            text=text, ambiguous=state == "view-refused" and path == str(first)))
    result = discovery.discover_aliases(target)
    assert reads == [first, second]
    assert result.headers_scanned == 2
    assert result.aliases_by_family["wur"] == ("SECOND",)
    assert result.aliases_by_family["nonnull"] == (() if state in {"read-refused", "view-refused"} else ("FIRST",))


def test_confinement_refusals_still_spend_header_budget(tmp_path, monkeypatch):
    header = tmp_path / "owned.h"
    header.touch()
    monkeypatch.setattr(discovery, "_MAX_FILES_HEADER_SCAN", 1)
    monkeypatch.setattr(Path, "rglob", lambda root, pattern: iter([header, header]))
    monkeypatch.setattr(discovery, "confine", lambda root, entry: None)
    monkeypatch.setattr(discovery, "read_text_capped", lambda _: pytest.fail("refused read"))
    result = discovery.discover_aliases(tmp_path)
    assert result.headers_scanned == 1
    assert result.sources_scanned == 0
