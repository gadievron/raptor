"""Fixture tests for the alloc_narrow_count detection-grade rule.

A 32-bit count produced by a division helper whose round-up
arithmetic feeds an allocation size can wrap in the narrow type
before the allocator sees it — an undersized-allocation lead.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "alloc_narrow_count.cocci"
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


class TestPositive:
    def test_div_count_roundup_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                unsigned int count;
                size_t bits;
                void *p;

                count = sector_div_up(t->len, rsize);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "alloc_narrow_count"


class TestNegatives:
    def test_wide_count_does_not_fire(self, tmp_path):
        # size_t count: the arithmetic happens at allocator width.
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                size_t count;
                size_t bits;
                void *p;

                count = sector_div_up(t->len, rsize);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert results == []

    def test_alloc_unrelated_to_count_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                unsigned int count;
                void *p;

                count = sector_div_up(t->len, rsize);
                p = vmalloc(sizeof(struct tgt));
                return p != 0 && count;
            }
        """)
        assert results == []

    def test_count_not_from_division_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(unsigned int n)
            {
                unsigned int count;
                size_t bits;
                void *p;

                count = clamp_helper(n);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert results == []
