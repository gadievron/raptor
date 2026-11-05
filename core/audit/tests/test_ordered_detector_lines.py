"""Detector coordinates survive skipped matches and independent passes."""

from core.audit.asn1_template_mismatch import scan_source
from core.audit.block_sibling_analysis import _collect_branches_regex
from core.audit.fail_open_detector import (
    _detect_optional_not_checked,
    _extract_c_functions,
)


def test_case_cursors_restart_for_each_indentation_group():
    source = ('def f():\n'
              '    case 1:\n      case 10:\n'
              '    case 2:\n      case 20:\n'
              '    case 3:\n      case 30:\n')
    groups = _collect_branches_regex('x.py', source)
    assert [[line for _, _, line in branches] for _, _, branches in groups] == [
        [2, 4, 6], [3, 5, 7],
    ]


def test_optional_locations_include_skipped_matches():
    source = ('def f():\n'
              '    if ignored is None: pass\n'
              '    if ignored is False: pass\n'
              '    if first is False: pass\n'
              '    if ignored is False: pass\n'
              '    if second is False: pass\n')
    hits = _detect_optional_not_checked('x.py', source)
    assert [(hit.function, hit.line) for hit in hits] == [('f', 4), ('f', 6)]


def test_asn1_locations_include_non_findings_and_crlf():
    source = ('ASN1_SIMPLE(NAME, slot, ASN1_INTEGER)\r\n'
              'ASN1_SIMPLE(NAME, any, ASN1_ANY)\r\n'
              'ASN1_TYPE_cmp(a->any,b->any);\r\n'
              'ASN1_TYPE_cmp(a->slot,b->slot);\r\n'
              'ASN1_TYPE_cmp(a->unknown,b->unknown);\r\n'
              'ASN1_TYPE_cmp(a->slot,b->slot);\r\n')
    assert [hit.line for hit in scan_source('x.c', source)] == [4, 6]


def test_c_fallback_retains_nested_function_bodies_and_lines():
    source = 'int outer(void) {\nint inner(void) {\n}\n}\n'
    # An unsupported suffix selects the regex fallback without a parser.
    assert _extract_c_functions(source, 'x.unsupported') == [
        ('outer', 1, source.rstrip('\n')),
        ('inner', 2, 'int inner(void) {\n}'),
    ]
