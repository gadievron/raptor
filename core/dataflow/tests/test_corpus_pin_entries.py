"""Documented fixture paths must not disappear from pin verification."""

import pytest

from core.dataflow.corpus_sources import CorpusPinError, load_pinned_sources, parse_pinned_sources


def test_path_without_pin_is_refused_and_existing_kernel_cases_are_pinned():
    with pytest.raises(CorpusPinError, match="local path but no pin"):
        parse_pinned_sources("## Fixture\n- Local path: `out/fixture/`\n")
    sources = load_pinned_sources()
    for cve in ("2019-12382", "2019-12614", "2019-12615"):
        matches = [s for s in sources if s.local_path == f"out/dataflow-corpus-fixtures/linux-cve-{cve}"]
        assert len(matches) == 1
        assert matches[0].pinned_sha == "e93c9c99a629c61837d5a7fc2120cd2b6c70dbdd"
    assert parse_pinned_sources("## Notes\nNo fixture here.\n") == []
