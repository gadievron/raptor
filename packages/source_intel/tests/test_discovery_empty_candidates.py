"""Empty alias candidates must not trigger a diagnostic source walk."""

from types import SimpleNamespace

import pytest

from core.audit import source_view
from packages.source_intel import discovery


@pytest.fixture(autouse=True)
def _owned_header_view(monkeypatch):
    monkeypatch.setattr(
        source_view, "sanitized_view_with_status",
        lambda text, _: SimpleNamespace(text=text, ambiguous=False),
    )


@pytest.mark.parametrize("header", [False, True], ids=["no-header", "unrelated-header"])
def test_empty_candidates_do_not_enumerate_sources(tmp_path, monkeypatch, header):
    (tmp_path / "owned.c").write_text("owned metadata placeholder\n")
    header_path = tmp_path / "owned.h"
    if header:
        header_path.write_text("owned metadata placeholder\n")
    reads = []

    def read(path):
        assert path == header_path
        reads.append(path)
        return "#define OWNED_VALUE 7\n", False

    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(discovery, "_iter_source_files", lambda *_: pytest.fail(
        "no alias candidates must not enumerate frequency-count sources",
    ))
    result = discovery.discover_aliases(tmp_path)
    assert not any(result.aliases_by_family.values())
    assert result.sources_scanned == 0
    assert reads == ([header_path] if header else [])


def test_nonempty_candidates_keep_frequency_count_path(tmp_path, monkeypatch):
    header = tmp_path / "owned.h"
    source = tmp_path / "owned.c"
    for path in (header, source):
        path.write_text("owned metadata placeholder\n")
    texts = {
        header: "#define OWNED_CHECK __attribute__((warn_unused_result))\n",
        source: "OWNED_CHECK int owned(void);\n",
    }
    reads = []

    def read(path):
        reads.append(path)
        return texts[path], False

    monkeypatch.setattr(discovery, "read_text_capped", read)
    monkeypatch.setattr(discovery, "_iter_source_files", lambda *_: iter([source]))
    result = discovery.discover_aliases(tmp_path)
    assert result.aliases_by_family["wur"] == ("OWNED_CHECK",)
    assert result.sources_scanned == 1
    assert reads == [header, source]
