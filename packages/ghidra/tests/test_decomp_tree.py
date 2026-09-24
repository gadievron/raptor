"""Decomp-tree materialization: grouping, sidecar, caps, citations."""

from __future__ import annotations

import json

from packages.ghidra.decomp_tree import (
    SIDECAR_NAME,
    TYPES_HEADER,
    resolve_citation,
    write_decomp_tree,
)
from packages.ghidra.model import REDatabase, REFunction, REType, REXref


def _db(**kw) -> REDatabase:
    defaults = dict(source_tool="ghidra", binary_path="/fw/demo")
    defaults.update(kw)
    return REDatabase(**defaults)


def _fn(name, addr, size=0x20, decomp=None, sig=None, **kw):
    return REFunction(name=name, address=addr, size=size,
                      source_tool="ghidra", decompilation=decomp,
                      signature=sig, **kw)


class TestWriter:
    def test_connected_functions_share_a_file(self, tmp_path):
        db = _db(functions=[
            _fn("main", 0x1000, decomp="int main(void){parse();}"),
            _fn("parse", 0x1100, decomp="void parse(void){}"),
            _fn("orphan", 0x2000),
        ], xrefs=[REXref(from_addr=0x1010, to_addr=0x1100, kind="call")])
        tree = write_decomp_tree(db, tmp_path)
        # main+parse together, orphan pooled separately
        grouped = [f for f in tree.files if "main" in f]
        assert grouped, tree.files
        text = (tmp_path / grouped[0]).read_text()
        assert "int main" in text and "void parse" in text
        assert "orphan" not in text

    def test_sidecar_resolves_citations_to_addresses(self, tmp_path):
        db = _db(functions=[
            _fn("a", 0x1000, decomp="void a(void){\n/*x*/\n}"),
            _fn("b", 0x1100, decomp="void b(void){}"),
        ], xrefs=[REXref(from_addr=0x1004, to_addr=0x1100,
                         kind="call")])
        tree = write_decomp_tree(db, tmp_path)
        fname = [f for f in tree.files if f.endswith(".c")][0]
        side = json.loads(tree.sidecar_path.read_text())
        entries = side["files"][fname]
        # every emitted line is covered by exactly one entry
        total_lines = (tmp_path / fname).read_text().count("\n") + 1
        covered = set()
        for e in entries:
            for ln in range(e["start_line"], e["end_line"] + 1):
                assert ln not in covered, "overlapping sidecar ranges"
                covered.add(ln)
        assert max(covered) <= total_lines
        hit = resolve_citation(tmp_path, fname, entries[1]["start_line"])
        assert hit is not None and hit["function"] == "b"
        assert hit["address"] == 0x1100

    def test_coverage_line_is_honest(self, tmp_path):
        db = _db(functions=[
            _fn("a", 0x1000, decomp="void a(void){}"),
            _fn("b", 0x1100),
        ])
        tree = write_decomp_tree(db, tmp_path)
        assert "1/2 functions carry decompilation" in \
            tree.coverage_line()

    def test_hostile_names_and_signatures_clipped(self, tmp_path):
        db = _db(functions=[
            _fn("n" * 100_000, 0x1000, sig="s" * 1_000_000,
                decomp="void f(void){}"),
        ])
        tree = write_decomp_tree(db, tmp_path)
        fname = [f for f in tree.files if f.endswith(".c")][0]
        text = (tmp_path / fname).read_text()
        # header lines bounded despite MB-scale inputs
        assert max(len(line) for line in text.splitlines()) < 1000
        # filesystem-safe, bounded filename
        assert len(fname) < 100

    def test_hostile_names_control_scrubbed_like_match_layer(
        self, tmp_path,
    ):
        # Same scrub class as match._clip / diff._display, "so the
        # layers cannot drift": names land in the jq'd sidecar, in .c
        # doc-comment headers, and in the byte-ceiling warning — none
        # may carry raw ESC/BEL/bidi bytes.
        db = _db(functions=[
            _fn("evil\x1b]0;pwn\x07‮name", 0x1000,
                sig="void evil\x1b[2J(void)",
                decomp=("void f(void){\n"
                        "  puts(\"lit\x1b]0;pwn\x07\x9b2J‮lit\");\n"
                        "}")),
        ])
        tree = write_decomp_tree(db, tmp_path)
        fname = [f for f in tree.files if f.endswith(".c")][0]
        text = (tmp_path / fname).read_text()
        sidecar = tree.sidecar_path.read_text()
        for emitted in (text, sidecar):
            assert "\x1b" not in emitted
            assert "\x07" not in emitted
            assert "\x9b" not in emitted
            assert "‮" not in emitted
        assert "evil" in text
        # The multi-line body survives structurally (newlines intact).
        assert "  puts(" in text

    def test_byte_ceiling_truncates_loudly(self, tmp_path, monkeypatch):
        import packages.ghidra.decomp_tree as mod
        monkeypatch.setattr(mod, "_MAX_TREE_BYTES", 512)
        db = _db(functions=[
            _fn(f"f{i}", 0x1000 + 0x100 * i,
                decomp="void f(void){/*" + "x" * 400 + "*/}")
            for i in range(10)
        ])
        tree = write_decomp_tree(db, tmp_path)
        assert tree.truncated
        assert "TRUNCATED" in tree.coverage_line()
        # sidecar still written and consistent with emitted files
        side = json.loads(tree.sidecar_path.read_text())
        assert side["truncated"] is True
        for fname in side["files"]:
            assert (tmp_path / fname).is_file()

    def test_types_header_renders_aggregates_only_as_defs(
        self, tmp_path,
    ):
        db = _db(functions=[_fn("a", 0x1000)], types=[
            REType(name="hdr", kind="struct", size=8,
                   fields=[{"name": "len", "type": "int",
                            "offset": 0}], source_tool="ghidra"),
            REType(name="main", kind="function_sig",
                   source_tool="ghidra"),
            REType(name="color", kind="enum",
                   fields=[{"name": "RED", "offset": 0}],
                   source_tool="ghidra"),
        ])
        write_decomp_tree(db, tmp_path)
        text = (tmp_path / TYPES_HEADER).read_text()
        assert "struct hdr {" in text
        assert "enum color {" in text
        # function_sig never becomes a struct-looking definition
        assert "struct main" not in text
        assert "/* function_sig main */" in text

    def test_deterministic_across_runs(self, tmp_path):
        db = _db(functions=[
            _fn("b", 0x2000, decomp="void b(void){}"),
            _fn("a", 0x1000, decomp="void a(void){}"),
        ])
        t1 = write_decomp_tree(db, tmp_path / "one")
        t2 = write_decomp_tree(db, tmp_path / "two")
        assert t1.files == t2.files
        for f in t1.files:
            assert (tmp_path / "one" / f).read_text() == \
                (tmp_path / "two" / f).read_text()

    def test_no_decompilation_emits_declaration_stub(self, tmp_path):
        db = _db(functions=[_fn("mystery", 0x1000,
                                sig="int mystery(char *p)")])
        tree = write_decomp_tree(db, tmp_path)
        fname = [f for f in tree.files if f.endswith(".c")][0]
        text = (tmp_path / fname).read_text()
        assert "no decompilation available" in text
        assert "int mystery(char *p);" in text


class TestResolveCitation:
    def test_degrades_on_missing_or_corrupt_sidecar(self, tmp_path):
        assert resolve_citation(tmp_path, "x.c", 1) is None
        (tmp_path / SIDECAR_NAME).write_text("{not json")
        assert resolve_citation(tmp_path, "x.c", 1) is None
        (tmp_path / SIDECAR_NAME).write_text('{"files": "prose"}')
        assert resolve_citation(tmp_path, "x.c", 1) is None

    def test_out_of_range_line_returns_none(self, tmp_path):
        db = _db(functions=[_fn("a", 0x1000, decomp="void a(void){}")])
        tree = write_decomp_tree(db, tmp_path)
        fname = [f for f in tree.files if f.endswith(".c")][0]
        assert resolve_citation(tmp_path, fname, 10_000) is None


class TestWriterHardening:
    def test_oversized_group_does_not_starve_later_groups(
        self, tmp_path, monkeypatch,
    ):
        """One giant early community must skip, not break — the old
        break reduced the whole tree to types.h."""
        import packages.ghidra.decomp_tree as mod
        monkeypatch.setattr(mod, "_MAX_TREE_BYTES", 2000)
        db = _db(functions=[
            _fn("giant", 0x1000, decomp="void g(void){/*" + "x" * 5000 + "*/}"),
            _fn("small", 0x9000, decomp="void s(void){}"),
        ])
        tree = write_decomp_tree(db, tmp_path)
        assert tree.truncated
        body = "".join((tmp_path / f).read_text()
                       for f in tree.files if f.endswith(".c"))
        assert "void s(void)" in body      # small survived
        assert "xxxxx" not in body         # giant's body omitted

    def test_stale_files_removed_on_rewrite(self, tmp_path):
        """A shrunken database must not leave the previous tree's
        files behind — prep would study stale decompilation as if it
        were live."""
        big = _db(functions=[
            _fn("keep", 0x1000, decomp="void k(void){}"),
            _fn("gone", 0x9000, decomp="void gone_fn(void){}"),
        ])
        write_decomp_tree(big, tmp_path)
        small = _db(functions=[
            _fn("keep", 0x1000, decomp="void k(void){}"),
        ])
        tree = write_decomp_tree(small, tmp_path)
        on_disk = {p.name for p in tmp_path.glob("*.c")}
        assert on_disk == {f for f in tree.files if f.endswith(".c")}
        assert not any("gone" in n for n in on_disk)

    def test_planted_dangling_symlink_swept_never_followed(
        self, tmp_path,
    ):
        """The stale sweep gated on is_file(), which is False for a
        DANGLING symlink — a link planted at a tree name survived and
        the write then created the attacker-chosen target."""
        db = _db(functions=[
            _fn("keep", 0x1000, decomp="void k(void){}"),
        ])
        probe = write_decomp_tree(db, tmp_path)
        emitted = next(f for f in probe.files if f.endswith(".c"))
        victim = tmp_path / "victim"
        (tmp_path / emitted).unlink()
        (tmp_path / emitted).symlink_to(victim)

        write_decomp_tree(db, tmp_path)

        assert not victim.exists()
        assert not (tmp_path / emitted).is_symlink()
        assert "keep" in (tmp_path / emitted).read_text()

    def test_types_header_over_budget_marks_truncated(
        self, tmp_path, monkeypatch,
    ):
        import packages.ghidra.decomp_tree as mod
        monkeypatch.setattr(mod, "_MAX_TREE_BYTES", 64)
        db = _db(functions=[_fn("a", 0x1000)], types=[
            REType(name="big", kind="struct", size=8,
                   fields=[{"name": f"f{i}", "type": "int",
                            "offset": i} for i in range(50)],
                   source_tool="ghidra"),
        ])
        tree = write_decomp_tree(db, tmp_path)
        assert tree.truncated
        assert not (tmp_path / TYPES_HEADER).exists()


def test_body_control_is_match_control_minus_structural_ws() -> None:
    # ``_BODY_CONTROL`` must scrub exactly what ``match._CONTROL``
    # scrubs, minus \t and \n (structural in multi-line decompiled C).
    # Exact set equality over every codepoint: neither layer may gain
    # or lose a control/bidi/invisible character without the other —
    # a silent divergence would let a hostile binary pick whichever
    # emission path forgot a character.
    from packages.ghidra.decomp_tree import _BODY_CONTROL
    from packages.ghidra.match import _CONTROL
    every_codepoint = "".join(map(chr, range(0x110000)))
    body = set(_BODY_CONTROL.findall(every_codepoint))
    ctrl = set(_CONTROL.findall(every_codepoint))
    assert body == ctrl - {"\t", "\n"}
    # Spot anchors: terminal-escape (ESC, CSI), bidi override, BOM and
    # C0 boundaries stay scrubbed; structural whitespace stays legal.
    assert {"\x00", "\x0b", "\x1b", "\x7f", "\x9b",
            "‮", "﻿"} <= body
    assert "\t" not in body and "\n" not in body
