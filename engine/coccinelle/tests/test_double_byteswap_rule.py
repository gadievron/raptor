"""Fixture tests for the double_byteswap rule.

Only a same-width, same-byte-order-family nested pair is a no-op
identity. Cross-family (BE wire data to LE) and mixed-width nesting
perform real conversions and must stay silent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_byteswap.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


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
