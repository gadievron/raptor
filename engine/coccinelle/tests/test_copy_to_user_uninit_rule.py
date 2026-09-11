"""Fixture tests for the copy_to_user_uninit rule.

Exactly one report per copy site, and only for the
zero-initialization shape: memset, whole-struct assignment, member
assignment, and helper calls taking the address all count as
initialization (spatch cannot prove FULL field coverage, so
partially-assigned structs are undecidable and stay silent).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "copy_to_user_uninit.cocci"
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
    def test_uninitialized_struct_fires_once(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int leak(struct info *up)
            {
                struct info out;
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_to_user_uninit"


class TestNegatives:
    def test_member_assigned_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                out.a = 1;
                out.b = 2;
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []

    def test_memset_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                memset(&out, 0, sizeof(out));
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []

    def test_helper_initialized_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                fill_info(&out, 3);
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []
