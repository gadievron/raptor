"""Fixture tests for the strncpy_no_nul verification-grade rule.

Two shapes must stay silent: a copy sized ``strlen(src) + 1`` (the
terminator is included by construction) and a later snprintf that
takes the buffer as its DESTINATION (an overwrite, not a string read).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "strncpy_no_nul.cocci"
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
    def test_unterminated_then_printf_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *dst, char *src, int n)
            {
                strncpy(dst, src, n);
                printf("%s", dst);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "strncpy_no_nul"

    def test_buffer_read_by_snprintf_format_arg_fires(self, tmp_path):
        # The buffer as a VALUE argument (after dest and size) is a
        # genuine string read.
        results = _run_rule(tmp_path, """\
            void bug(char *dst, char *src, int n, char *out, int sz)
            {
                strncpy(dst, src, n);
                snprintf(out, sz, "%s", dst);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_strlen_plus_one_size_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *dst, char *src)
            {
                strncpy(dst, src, strlen(src) + 1);
                printf("%s", dst);
            }
        """)
        assert results == []

    def test_snprintf_overwrite_of_dest_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, char *s, int n, int sz)
            {
                strncpy(buf, s, n);
                snprintf(buf, sz, "reset");
            }
        """)
        assert results == []

    def test_manual_nul_then_use_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *dst, char *src, int n)
            {
                strncpy(dst, src, n);
                dst[n - 1] = '\\0';
                printf("%s", dst);
            }
        """)
        assert results == []
