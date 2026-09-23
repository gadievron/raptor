r"""One inventory, ONE line model.

Function extractors number lines with tree-sitter rows / split('\n')
(the \n model every downstream consumer assumes: staleness's
docstring pins "inventory ranges count \n", coverage gaps, review
display, DWARF joins).  The macro/interstitial/SLOC passes counted
lines with str.splitlines(), which also breaks on \f and five other
in-literal-plantable bytes — so a single string-literal form feed
made the SAME extract_items() call return items in two different
line models, and no consumer could recover either coordinate space
after the fact.
"""

from __future__ import annotations

from core.inventory.extractors import count_sloc, extract_items

# \n-model layout:
#  1  static const char *BANNER = "p1\x0cp2";   <- FF inside a literal
#  2  int check(int x) {
#  3      return x > 0;
#  4  }
#  5  #define UNSAFE_COPY(d, s) strcpy((d), (s))
_CONTENT = (
    'static const char *BANNER = "p1\x0cp2";\n'
    "int check(int x) {\n"
    "    return x > 0;\n"
    "}\n"
    "#define UNSAFE_COPY(d, s) strcpy((d), (s))\n"
)


class TestSingleLineModel:
    def test_macro_and_function_share_the_nl_model(self):
        items = {it.name: it for it in extract_items("t.c", "c", _CONTENT)}
        # Editor / compiler / semgrep / DWARF all say: check at line 2,
        # macro at line 5.
        assert items["check"].line_start == 2
        assert (items["UNSAFE_COPY"].line_start,
                items["UNSAFE_COPY"].line_end) == (5, 5)

    def test_every_item_line_resolves_in_the_nl_view(self):
        nl_lines = _CONTENT.split("\n")
        for it in extract_items("t.c", "c", _CONTENT):
            assert 1 <= it.line_start <= len(nl_lines), it.name
            line = nl_lines[it.line_start - 1]
            assert it.name.split("(")[0] in line or it.name in line, (
                it.name, line)

    def test_sloc_counts_nl_lines(self):
        # 5 \n lines, none blank, none comment-only — a splitlines()
        # count saw six.
        assert count_sloc(_CONTENT, "c") == 5

    def test_clean_twin_differential(self):
        clean = _CONTENT.replace("\x0c", "")
        items_c = [(it.name, it.kind, it.line_start, it.line_end)
                   for it in extract_items("t.c", "c", clean)]
        items_e = [(it.name, it.kind, it.line_start, it.line_end)
                   for it in extract_items("t.c", "c", _CONTENT)]
        assert items_c == items_e

    def test_bare_carriage_return_shares_the_model(self):
        # tree-sitter keeps a bare \r inside the line; so must every
        # other pass in the same inventory.
        content = _CONTENT.replace("\x0c", "\r")
        items = {it.name: it for it in extract_items("t.c", "c", content)}
        assert items["check"].line_start == 2
        assert (items["UNSAFE_COPY"].line_start,
                items["UNSAFE_COPY"].line_end) == (5, 5)
        assert count_sloc(content, "c") == 5
