"""Necessary prefilters retain regex semantics and avoid absent scans."""

import pytest

from core.audit import parser_shape as ps


@pytest.mark.parametrize('identifier', ['size', 'SIZE', 'ſize', 'sİze', 'sıze'],
                         ids=['lowercase', 'uppercase', 'long-s', 'dotted-i', 'dotless-i'])
def test_length_prefilter_uses_same_unicode_case_rules(identifier):
    shape = ps.parser_shape('alpha = beta;\n' * 30 + f'{identifier} - 4;', sloc=1)
    assert shape.length_arith_sites == 1


def test_absent_morphemes_and_keywords_skip_expensive_scans(monkeypatch):
    class UnexpectedScan:
        def findall(self, text):
            pytest.fail('An impossible match triggered a full metric scan')

    monkeypatch.setattr(ps, '_LEN_ARITH_RE', UnexpectedScan())
    monkeypatch.setattr(ps, '_ERROR_PATH_RE', UnexpectedScan())
    shape = ps.parser_shape('alpha = beta; consume(alpha);\n' * 30, sloc=1)
    assert shape.length_arith_sites == shape.error_path_sites == 0


def test_subclass_keeps_original_regex_path():
    class Source(str):
        def __contains__(self, other):
            pytest.fail('Native-only keyword prefilter called a custom method')

    shape = ps.parser_shape(Source('len - 4; return NULL;'), sloc=1)
    assert shape.length_arith_sites == 1
    assert shape.error_path_sites == 1
