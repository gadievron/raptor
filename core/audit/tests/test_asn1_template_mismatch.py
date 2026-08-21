"""Tests for the ASN.1 declared-vs-accessed type witness."""

from __future__ import annotations

import textwrap

from core.audit.asn1_template_mismatch import scan_source, scan_sources

_TEMPLATE = textwrap.dedent("""\
    ASN1_SEQUENCE(OTHER) = {
            ASN1_SIMPLE(OTHER, type_id, ASN1_OBJECT),
            ASN1_EXP(OTHER, value, ASN1_ANY, 0)
    } ASN1_SEQUENCE_END(OTHER)

    ASN1_CHOICE(NAME) = {
            ASN1_IMP(NAME, d.mailbox, ASN1_IA5STRING, 1),
            ASN1_IMP(NAME, d.addr, ASN1_SEQUENCE, 3),
            ASN1_EXP(NAME, d.dir, X509_NAME, 4)
    } ASN1_CHOICE_END(NAME)
""")


class TestPositive:
    def test_concrete_slot_compared_as_any_fires(self):
        src = _TEMPLATE + textwrap.dedent("""\
            int name_cmp(NAME *a, NAME *b)
            {
                return ASN1_TYPE_cmp(a->d.addr, b->d.addr);
            }
        """)
        findings = scan_source("x.c", src)
        assert len(findings) == 1
        f = findings[0]
        assert f.field == "addr"
        assert f.declared == "ASN1_SEQUENCE"
        assert f.struct == "NAME"
        assert f.line == src[:src.index("ASN1_TYPE_cmp")].count("\n") + 1
        assert "declared-type vs accessed-type" in f.description()


class TestNegatives:
    def test_any_declared_slot_is_correct_access(self):
        src = _TEMPLATE + textwrap.dedent("""\
            int other_cmp(OTHER *a, OTHER *b)
            {
                return ASN1_TYPE_cmp(a->value, b->value);
            }
        """)
        assert scan_source("x.c", src) == []

    def test_string_cmp_access_does_not_fire(self):
        # The fixed shape: the slot is compared as what the template
        # declares.
        src = _TEMPLATE + textwrap.dedent("""\
            int name_cmp(NAME *a, NAME *b)
            {
                return ASN1_STRING_cmp(a->d.addr, b->d.addr);
            }
        """)
        assert scan_source("x.c", src) == []

    def test_no_template_in_unit_stays_silent(self):
        src = textwrap.dedent("""\
            int cmp(TYPE *a, TYPE *b)
            {
                return ASN1_TYPE_cmp(a->value, b->value);
            }
        """)
        assert scan_source("x.c", src) == []

    def test_access_of_unknown_field_stays_silent(self):
        src = _TEMPLATE + textwrap.dedent("""\
            int cmp(NAME *a, NAME *b)
            {
                return ASN1_TYPE_cmp(a->d.unrelated, b->d.unrelated);
            }
        """)
        assert scan_source("x.c", src) == []


class TestScanSources:
    def test_non_c_files_skipped(self):
        texts = {
            "a.py": _TEMPLATE + "ASN1_TYPE_cmp(a->d.addr, b->d.addr);",
            "b.c": _TEMPLATE + "ASN1_TYPE_cmp(a->d.addr, b->d.addr);",
        }
        findings = scan_sources(texts)
        assert [f.file for f in findings] == ["b.c"]
