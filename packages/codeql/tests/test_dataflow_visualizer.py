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


class TestEscapeMermaidNewlinesAndHash:
    def test_newlines_collapsed_to_space(self, visualizer):
        # Node labels are single-line: a literal newline splits the
        # node declaration and the whole .mmd fails to render.
        escaped = visualizer._escape_mermaid("first line\nsecond line")
        assert "\n" not in escaped
        assert escaped == "first line second line"

    def test_hash_escaped_before_entities(self, visualizer):
        # '#' must be escaped FIRST: every entity replacement
        # introduces '&#NN;', so escaping '#' afterwards mangled the
        # entities of previously-escaped characters.
        escaped = visualizer._escape_mermaid("a[b]#c")
        assert escaped == "a&#91;b&#93;&#35;c"


class TestSanitizersSanitised:
    def test_sanitizer_labels_defanged_in_markdown(self, visualizer, tmp_path):
        # Sanitizer labels come from SARIF flow-step text quoting the
        # target's source — same provenance/threat as rule_id/message,
        # which the two lines above them already defang.
        from types import SimpleNamespace

        step = SimpleNamespace(label="src", file_path="a.c", line=1)
        dataflow = SimpleNamespace(
            source=step,
            sink=SimpleNamespace(label="snk", file_path="b.c", line=2),
            intermediate_steps=[],
            rule_id="cpp/rule",
            message="msg",
            sanitizers=["validate_x![](http://collector.invalid/x)"],
        )
        out = visualizer.generate_mermaid(dataflow, "f1")
        text = Path(out).read_text()
        assert "![](http://collector.invalid/x)" not in text
        # The label itself still appears (defanged), not dropped.
        assert "validate_x" in text


class TestAsciiControlScrub:
    def test_ascii_output_scrubs_control_bytes(self, visualizer):
        # generate_ascii echoes its block line-by-line through
        # logger.info to the operator terminal, and labels/snippets
        # come from SARIF over the UNTRUSTED repo (snippet text IS
        # target source). ESC/BEL/bidi must not survive — the mermaid
        # sibling already sanitises the same fields.
        from types import SimpleNamespace

        evil = "san\x1b]0;pwn\x07itize"
        step = SimpleNamespace(
            label="mid\x1b[2J", file_path="a\x07.c", line=3, column=1,
            snippet="x = re.sub('\x1b[31m', '', y)",
        )
        dataflow = SimpleNamespace(
            source=SimpleNamespace(
                label="src‮lbl", file_path="s.c", line=1, column=1,
                snippet="get\x1b(input)",
            ),
            sink=SimpleNamespace(
                label="snk", file_path="k.c", line=9, column=2,
                snippet="run(x)\x07",
            ),
            intermediate_steps=[step],
            rule_id="cpp/rule\x1b",
            message="msg\x1b[1m",
            sanitizers=[evil],
        )
        out = visualizer.generate_ascii(dataflow, "f2")
        text = Path(out).read_text()
        assert "\x1b" not in text
        assert "\x07" not in text
        assert "‮" not in text
        assert "itize" in text  # content survives, escaped


def _flow(repo: Path, rel: str = "a.c", line: int = 2):
    from packages.codeql.dataflow_validator import DataflowPath, DataflowStep
    return DataflowPath(
        source=DataflowStep(file_path=rel, line=line, column=1,
                            snippet="s", label="source"),
        sink=DataflowStep(file_path=rel, line=line, column=1,
                          snippet="x", label="sink"),
        intermediate_steps=[],
        sanitizers=[],
        rule_id="cpp/unbounded-write",
        message="m",
    )


class TestGenerateHtmlCappedRead:
    """generate_html adopts the shared capped read like its two
    siblings — it runs per node per finding under the analyzer's
    default enable_visualization=True, and pre-fix readlines()
    pulled a repo's multi-hundred-MB generated/blob file into
    memory each time."""

    def test_normal_file_context_renders(self, visualizer, tmp_path):
        (tmp_path / "a.c").write_text(
            "int a;\nint marker_line_2;\nint c;\n",
        )
        out = visualizer.generate_html(_flow(tmp_path), "f1", tmp_path)
        html = out.read_text(encoding="utf-8")
        assert "marker_line_2" in html

    def test_truncated_read_annotates_instead_of_loading(
            self, visualizer, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text("int a;\n" * 10)
        import packages.codeql.dataflow_visualizer as viz_mod
        monkeypatch.setattr(
            viz_mod, "read_text_capped",
            lambda p, *a, **kw: ("int a;\n", True),
        )
        out = visualizer.generate_html(
            _flow(tmp_path, line=5), "f2", tmp_path,
        )
        html = out.read_text(encoding="utf-8")
        assert "capped read" in html

    def test_unreadable_file_degrades(self, visualizer, tmp_path,
                                      monkeypatch):
        (tmp_path / "a.c").write_text("int a;\n")
        import packages.codeql.dataflow_visualizer as viz_mod
        monkeypatch.setattr(
            viz_mod, "read_text_capped", lambda p, *a, **kw: None,
        )
        out = visualizer.generate_html(_flow(tmp_path), "f3", tmp_path)
        html = out.read_text(encoding="utf-8")
        assert "Error reading file" in html


class TestSafeJsonHtmlParserStates:
    """The embedded-JSON defang covers every `<` — the previous
    `</`-only defang left `<!--<script` able to drive the browser's
    script-data-double-escaped state (render-break)."""

    def _html(self, visualizer, tmp_path, snippet):
        (tmp_path / "a.c").write_text("int a;\nint b;\nint c;\n")
        flow = _flow(tmp_path)
        flow.source.snippet = snippet
        out = visualizer.generate_html(flow, "fsj", tmp_path)
        return out.read_text(encoding="utf-8")

    def test_no_raw_lt_survives_in_embedded_json(
            self, visualizer, tmp_path):
        html = self._html(visualizer, tmp_path, "<!--<script>evil()")
        import re
        m = re.search(r"const nodes = (.*);", html)
        assert m, "embedded nodes JSON not found"
        assert "<" not in m.group(1)
        # Round-trip: the data is byte-identical after JSON parse.
        import json as _json
        nodes = _json.loads(m.group(1))
        assert any(
            n.get("snippet") == "<!--<script>evil()" for n in nodes
        )

    def test_script_close_still_defanged(self, visualizer, tmp_path):
        html = self._html(visualizer, tmp_path, "</script><script>x()")
        import re
        m = re.search(r"const nodes = (.*);", html)
        assert "</script" not in m.group(1)


class TestHtmlOfflineHardening:
    def test_d3_tag_hardened_and_fallback_present(
            self, visualizer, tmp_path):
        (tmp_path / "a.c").write_text("int a;\n")
        out = visualizer.generate_html(_flow(tmp_path), "fh", tmp_path)
        html = out.read_text(encoding="utf-8")
        assert 'crossorigin="anonymous"' in html
        assert 'referrerpolicy="no-referrer"' in html
        # Offline degradation is visible, not a silent blank page.
        assert 'typeof d3 === "undefined"' in html
        assert "d3 failed to load" in html


class TestMermaidLabelSanitised:
    def test_control_and_bidi_bytes_escaped_in_labels(
            self, visualizer, tmp_path):
        """Node label/path text gets escape_nonprintable before the
        Mermaid syntax escapes — raw control/bidi bytes must not
        reach the artifact file."""
        (tmp_path / "a.c").write_text("int a;\n")
        flow = _flow(tmp_path)
        flow.sink.label = "sink\x1b]0;PWNED\x07‮"
        out = visualizer.generate_mermaid(flow, "fm")
        text = out.read_text(encoding="utf-8")
        assert "\x1b" not in text
        assert "\x07" not in text
        assert "‮" not in text
