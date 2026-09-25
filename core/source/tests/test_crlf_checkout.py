r"""CRLF-checkout fixtures for the ``\n``-only line model.

``\r`` is exercised elsewhere as an attack byte
(``test_lines.py``); these fixtures pin it as an ENVIRONMENT: a
CRLF-normalised checkout (``core.autocrlf=true`` on a Windows-side
clone) of the same code must split to the same line content as its
LF twin, so line-addressed consumers behave identically across the
two encodings of one codebase.
"""

from __future__ import annotations

import pytest

from core.source.lines import slice_text, split_lines

pytestmark = pytest.mark.wsl

_LF = (
    "int main(void) {\n"
    "    char buf[16];\n"
    "    return read(0, buf, sizeof buf);\n"
    "}\n"
)
_CRLF = _LF.replace("\n", "\r\n")


class TestCrlfCheckoutParity:
    def test_split_lines_identical_for_lf_and_crlf(self):
        assert split_lines(_CRLF) == split_lines(_LF)

    def test_split_lines_identical_without_final_newline(self):
        lf = _LF.rstrip("\n")
        assert split_lines(lf.replace("\n", "\r\n")) == split_lines(lf)

    def test_slice_text_identical_for_lf_and_crlf(self):
        assert slice_text(_CRLF, 2, 3) == slice_text(_LF, 2, 3)
        assert slice_text(_CRLF, 2, 3) != ""

    def test_line_numbers_agree_with_lf_editors(self):
        # A CRLF checkout must not shift external line numbers: line 3
        # is the read() line in both encodings.
        assert split_lines(_CRLF)[2] == "    return read(0, buf, sizeof buf);"
