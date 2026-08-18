"""Tests for packages.codeql.dataflow_visualizer.

Scoped to the pure escaping helpers — the label escapers must keep
generated DOT / Mermaid output well-formed for any input text.
"""

import sys
from pathlib import Path

import pytest

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.dataflow_visualizer import DataflowVisualizer


@pytest.fixture
def visualizer(tmp_path):
    return DataflowVisualizer(tmp_path)


def _dot_string_is_closed(escaped: str) -> bool:
    """A DOT quoted string stays closed when the escaped text does not
    end in an odd run of backslashes (which would escape the closing
    quote) and contains no unescaped quote."""
    trailing = len(escaped) - len(escaped.rstrip("\\"))
    if trailing % 2 == 1:
        return False
    # Every quote must be preceded by an odd run of backslashes.
    for i, ch in enumerate(escaped):
        if ch != '"':
            continue
        run = 0
        j = i - 1
        while j >= 0 and escaped[j] == "\\":
            run += 1
            j -= 1
        if run % 2 == 0:
            return False
    return True


class TestEscapeDot:
    def test_plain_text_unchanged(self, visualizer):
        assert visualizer._escape_dot("memcpy(dst, src, n)") == "memcpy(dst, src, n)"

    def test_quotes_escaped(self, visualizer):
        assert visualizer._escape_dot('say "hi"') == 'say \\"hi\\"'

    def test_newlines_escaped(self, visualizer):
        assert visualizer._escape_dot("a\nb") == "a\\nb"

    def test_trailing_backslash_round_trips(self, visualizer):
        # A label ending in a backslash must not swallow the closing
        # quote of the DOT string it is embedded in.
        escaped = visualizer._escape_dot("foo\\")
        assert escaped == "foo\\\\"
        assert _dot_string_is_closed(escaped)

    def test_backslash_quote_sequence_stays_closed(self, visualizer):
        # Backslashes are escaped before quotes; escaping quotes first
        # would leave the pre-existing backslash re-arming the quote.
        escaped = visualizer._escape_dot('\\"')
        assert escaped == '\\\\\\"'
        assert _dot_string_is_closed(escaped)

    def test_backslash_heavy_label_stays_closed(self, visualizer):
        escaped = visualizer._escape_dot('C:\\path\\"dir"\\')
        assert _dot_string_is_closed(escaped)

    def test_truncation_before_escaping(self, visualizer):
        escaped = visualizer._escape_dot("a" * 60)
        assert escaped == "a" * 47 + "..."


class TestEscapeMermaid:
    def test_quote_becomes_entity(self, visualizer):
        # Quotes are replaced with HTML entities, so no raw quote can
        # terminate the Mermaid label string.
        escaped = visualizer._escape_mermaid('say "hi"')
        assert '"' not in escaped
        assert "&quot;" in escaped

    def test_trailing_backslash_leaves_no_raw_quote(self, visualizer):
        # Unlike DOT, Mermaid labels carry no backslash-escape
        # semantics; a trailing backslash is inert as long as no raw
        # quote remains in the escaped text.
        escaped = visualizer._escape_mermaid('foo\\"')
        assert '"' not in escaped
