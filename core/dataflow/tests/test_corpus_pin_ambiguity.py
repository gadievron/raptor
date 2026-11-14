"""Pin sections must identify one unambiguous documented fixture."""

import pytest

from core.dataflow.corpus_sources import CorpusPinError, PinnedSource, parse_pinned_sources


@pytest.mark.parametrize(
    "text",
    [
        "## Fixture\n- Pinned sha: `abcdef1`\n- Pinned sha: `abcdef2`\n- Local path: `out/fixture/`\n",
        "## Fixture\n- Pinned sha: `abcdef1`\n- Local path: `out/one/`\n- Local path: `out/two/`\n",
        "- Pinned sha: `abcdef1`\n## Fixture\n- Local path: `out/fixture/`\n",
        "- Local path: `out/fixture/`\n## Fixture\n- Pinned sha: `abcdef1`\n",
    ],
    ids=["duplicate-sha", "duplicate-path", "unscoped-sha", "unscoped-path"],
)
def test_ambiguous_pin_document_is_refused(text):
    with pytest.raises(CorpusPinError):
        parse_pinned_sources(text)


def test_qualified_pin_and_annotation_remain_supported():
    text = (
        "# Sources\n## Notes\nPlain prose.\n### Fixture\n"
        "- Pinned sha (vulnerable): `ABCDEF1` (before the fix)\n"
        "- Local path: `out/fixture/`\n"
    )
    assert parse_pinned_sources(text) == [PinnedSource("Fixture", "abcdef1", "out/fixture")]
