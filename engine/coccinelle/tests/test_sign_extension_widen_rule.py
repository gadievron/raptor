"""Fixture tests for the sign_extension_widen rule.

Detection-role rule (reports conversion candidates for CWE-194 review). The
rule emits two ids — sign_extension_char and sign_extension_short —
for signed-narrow-to-unsigned-wide widenings in declaration-init and
cast form. Negatives pin the intentional-mask guard the rule's own
header documents and the unsigned-source shape that has no sign bit
to extend.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

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
    return run_rule(tmp_path, source, rule)


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


@pytest.mark.slow
def test_guarded_widening_requires_value_range_review(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    source = """unsigned long guarded_char(signed char c) {
    if (c < 0) return 0;
    unsigned long n = c;
    return n;
}
unsigned long guarded_short(short s) {
    if (s < 0) return 0;
    unsigned long n = s;
    return n;
}
unsigned long unguarded(signed char c) {
    unsigned long n = c;
    return n;
}
unsigned long unsigned_source(unsigned char c) {
    unsigned long n = c;
    return n;
}
"""
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff'],
        timeout=45, context='Owned signed widening candidate syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr)
            for line in stream.splitlines() if line.startswith('COCCIRESULT:')]
    assert sorted((row['line'], row['rule']) for row in rows) == [
        (3, 'sign_extension_char'), (8, 'sign_extension_short'),
        (12, 'sign_extension_char'),
    ]
    assert all(row['message'].startswith('Candidate:')
               and 'negative values' in row['message'] for row in rows)
