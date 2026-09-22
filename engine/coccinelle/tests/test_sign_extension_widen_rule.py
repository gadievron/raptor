"""Fixture tests for the sign_extension_widen rule.

Verification-role rule (fires mint confirmed CWE-194 verdicts). The
rule emits two ids — sign_extension_char and sign_extension_short —
for signed-narrow-to-unsigned-wide widenings in declaration-init and
cast form. Negatives pin the intentional-mask guard the rule's own
header documents and the unsigned-source shape that has no sign bit
to extend.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules"
    / "sign_extension_widen.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_signed_char_to_size_t_decl_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long widen(signed char c)
            {
                size_t n = c;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sign_extension_char"
        assert results[0]["line"] == 3

    def test_signed_char_cast_to_unsigned_long_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void widen(signed char c, unsigned long *out)
            {
                *out = (unsigned long) c;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sign_extension_char"
        assert results[0]["line"] == 3

    def test_signed_short_to_unsigned_long_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long widen(short s)
            {
                unsigned long n = s;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sign_extension_short"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_masked_widening_does_not_fire(self, tmp_path):
        # The intentional-byte-value guard from the rule header.
        results = _run_rule(tmp_path, """\
            unsigned long masked(signed char c, short s)
            {
                size_t n = c & 0xFF;
                unsigned long m = s & 0xFFFF;
                return n + m;
            }
        """)
        assert results == []

    def test_unsigned_source_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long no_sign_bit(unsigned char c, unsigned short s)
            {
                size_t n = c;
                unsigned long m = s;
                return n + m;
            }
        """)
        assert results == []

    def test_signed_to_signed_widening_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long same_signedness(signed char c)
            {
                long n = c;
                return n;
            }
        """)
        assert results == []
