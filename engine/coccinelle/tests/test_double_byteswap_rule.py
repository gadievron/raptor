"""Fixture tests for the double_byteswap rule.

Same-width, same-byte-order-family pairs are review candidates.
They can narrow a wider input or intentionally check a round trip. Cross-family (BE wire data to LE) and mixed-width nesting
perform real conversions and must stay silent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_byteswap.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_same_function_twice_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned short f(unsigned short x)
            {
                return htons(htons(x));
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_byteswap"

    def test_inverse_pair_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int g(unsigned int y)
            {
                return ntohl(htonl(y));
            }
        """)
        assert len(results) == 1

    def test_kernel_inverse_pair_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int k(unsigned int w)
            {
                return cpu_to_be32(be32_to_cpu(w));
            }
        """)
        assert len(results) == 1

    def test_double_bswap_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int h(unsigned int z)
            {
                return bswap_32(bswap_32(z));
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_cross_family_conversion_does_not_fire(self, tmp_path):
        # Genuine big-endian to little-endian conversion.
        results = _run_rule(tmp_path, """\
            unsigned int conv(unsigned int x)
            {
                return cpu_to_le32(be32_to_cpu(x));
            }
        """)
        assert results == []

    def test_mixed_width_chain_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int mixed(unsigned short y)
            {
                return htobe32(le16toh(y));
            }
        """)
        assert results == []

    def test_widening_net_chain_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int widen(unsigned short z)
            {
                return htonl(ntohs(z));
            }
        """)
        assert results == []


def test_input_width_and_roundtrip_intent_require_review(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    source = '\n'.join([
        'typedef unsigned short uint16_t;',
        'typedef unsigned int uint32_t;',
        'uint32_t narrow(uint32_t x) {',
        ' return ntohs(htons(x));', '}',
        'int roundtrip(uint16_t x) {',
        ' return ntohs(htons(x)) == x;', '}',
        'uint32_t cross(uint32_t x) {',
        ' return cpu_to_le32(be32_to_cpu(x));', '}',
        'uint32_t mixed(uint16_t x) {',
        ' return htonl(ntohs(x));', '}', ''])
    target = tmp_path / 'width.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Byte-order width and intent candidates',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert sorted(row['line'] for row in rows) == [4, 7]
    assert all(row['rule'] == 'double_byteswap' for row in rows)
    assert all('review input width and conversion intent' in row['message'] for row in rows)
