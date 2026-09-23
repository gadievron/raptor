r"""Emitted line numbers speak the \n model their consumers assume.

Sites that number lines with ``enumerate(x.splitlines(), 1)`` emit
coordinates into findings/evidence records consumed under \n
assumptions (reports, review windows, editors, cross-references
against tree-sitter/inventory spans).  splitlines() also breaks on
\f — plantable in string literals and (as code whitespace) in C and
Python — so one byte skewed every subsequent emitted line number.
Representative form-feed twins here; the census gate pins the
structural rule for every emitter.
"""

from __future__ import annotations

from core.analysis.lifecycle_collector import collect_field_sites_from_source
from core.audit.invariant_smt import find_mutation_sites


class TestInvariantSmtSites:
    def test_mutation_site_line_is_nl_counted(self):
        # The form feed is CODE whitespace (line 1's trailing byte) —
        # sanitized_view blanks literal contents but keeps layout, so
        # this byte survives into the scanned view.
        src = (
            "x = 1;\x0c\n"     # 1
            "y = 2;\n"         # 2
            "len += n;\n"      # 3
        )
        sites = find_mutation_sites(src, {"len"})
        assert [(s[0], s[2]) for s in sites] == [(3, "len")]

    def test_clean_twin_differential(self):
        view = "x = 1\nlen += n\n"
        assert [(s[0], s[2]) for s in find_mutation_sites(view, {"len"})] \
            == [(2, "len")]


class TestLifecycleCollectorSites:
    def test_field_site_lines_are_nl_counted(self):
        src = (
            'const char *B = "a\x0c\x0cb";\n'  # 1
            "void f(struct s *o) {\n"          # 2
            "    o->refcnt = 1;\n"             # 3
            "    use(o->refcnt);\n"            # 4
            "}\n"                              # 5
        )
        got = collect_field_sites_from_source(src, "t.c", "refcnt")
        assert got["writes"] == [3]
        # the write line also matches the access pattern by design
        assert got["reads"] == [3, 4]
