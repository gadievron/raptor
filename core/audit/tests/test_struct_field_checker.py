"""Tests for core.audit.struct_field_checker — hermetic, synthetic C.

The two verified dead spots: the var-to-struct binding regex expected
the struct name AFTER the cast (it lives inside), so layout/REType
knowledge never bound; and ``char *name;`` fields were skipped,
leaving every later offset 8 bytes short.
"""

from __future__ import annotations

from core.audit.struct_field_checker import (
    _extract_struct_layouts,
    _struct_var_binding_re,
    check_struct_field_copy,
)

_SRC = (
    "struct pkt {\n"
    "    int type;\n"
    "    char *name;\n"
    "    char tag[8];\n"
    "};\n"
    "void f(char *src) {\n"
    "    pkt *p = (pkt *)malloc(0x20);\n"
    "    memcpy((char *)p + 0xc, src, 64);\n"
    "}\n"
)


class TestVarBinding:
    def test_cast_assignment_binds(self):
        m = _struct_var_binding_re("pkt").search(
            "p = (pkt *)malloc(0x20);",
        )
        assert m is not None
        assert (m.group(1) or m.group(2)) == "p"

    def test_struct_keyword_cast_binds(self):
        m = _struct_var_binding_re("pkt").search(
            "q = (struct pkt *)buf;",
        )
        assert m is not None
        assert (m.group(1) or m.group(2)) == "q"

    def test_pointer_declaration_binds(self):
        m = _struct_var_binding_re("pkt").search(
            "struct pkt *hdr;",
        )
        assert m is not None
        assert (m.group(1) or m.group(2)) == "hdr"

    def test_unrelated_name_does_not_bind(self):
        assert _struct_var_binding_re("pkt").search(
            "x = packet_count + 1;",
        ) is None


class TestLayoutExtraction:
    def test_pointer_field_star_on_name_counted(self):
        # `char *name;` used to be skipped entirely: `tag` then sat at
        # offset 4 instead of 12.
        layouts = _extract_struct_layouts(_SRC)
        fields = {f["name"]: f for f in layouts["pkt"]}
        assert fields["name"]["offset"] == 4
        assert fields["name"]["size"] == 8
        assert fields["tag"]["offset"] == 12
        assert fields["tag"]["size"] == 8


class TestEndToEnd:
    def test_overflowing_field_copy_detected(self):
        findings = check_struct_field_copy("f", _SRC, file="t.c")
        assert len(findings) == 1
        f = findings[0]
        assert f.field_name == "tag"
        assert f.field_offset == 12
        assert f.field_size == 8
        assert f.copy_call == "memcpy"
        assert f.confidence == "high"

    def test_fitting_copy_clean(self):
        src = _SRC.replace("src, 64", "src, 8")
        assert check_struct_field_copy("f", src, file="t.c") == []

    def test_re_types_binding(self):
        # The REType path shares the binding regex — it was equally
        # dead.
        src = (
            "void f(char *src) {\n"
            "    hdr_t *h = (hdr_t *)malloc(0x10);\n"
            "    memcpy((char *)h + 0x4, src, 32);\n"
            "}\n"
        )
        re_types = [{
            "kind": "struct",
            "name": "hdr_t",
            "fields": [
                {"offset": 0, "name": "len", "type": "int", "size": 4},
                {"offset": 4, "name": "tag", "type": "char[4]", "size": 4},
            ],
        }]
        findings = check_struct_field_copy(
            "f", src, file="t.c", re_types=re_types,
        )
        assert len(findings) == 1
        assert findings[0].field_name == "tag"


class TestXrefSeamSeparator:
    def test_seam_junction_cannot_assemble_a_token(self):
        # Bare concatenation let a regex token assemble from the
        # primary's tail + the xref's head — a fabricated match
        # attributed to the primary function (seam-match start <
        # primary_len => is_xref=False). The newline separator breaks
        # the junction.
        from core.audit.struct_field_checker import _COPY_INTO_OFFSET_RE

        primary = "void f(void) { int x = 1; } memcp"
        xref = "y(dst + 8, src, n);"
        # Pre-fix junction: the spanning token matches.
        assert _COPY_INTO_OFFSET_RE.search(primary + xref)
        # Separated: it cannot.
        assert not _COPY_INTO_OFFSET_RE.search(primary + "\n" + xref)

    def test_checker_joins_with_separator(self, monkeypatch):
        import core.audit.struct_field_checker as sfc

        captured = {}
        real = sfc._extract_struct_layouts

        def spy(text):
            captured["text"] = text
            return real(text)

        monkeypatch.setattr(sfc, "_extract_struct_layouts", spy)
        sfc.check_struct_field_copy("f", "int a;", xref_source="int b;")
        assert captured["text"] == "int a;\nint b;"
