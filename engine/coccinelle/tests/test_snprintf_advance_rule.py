"""Fixture tests for the snprintf_advance rule.

The rules are some-path (`exists`): an advance guarded by the WRONG
condition (`if (n > 0) buf += n;`) is still unchecked on that path,
and the direct `buf += snprintf(...)` form leaves no room for any
check at all. Paths passing through `n >= remaining` stay excluded.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "snprintf_advance.cocci"
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
    def test_plain_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                buf += n;
            }
        """)
        assert len(results) == 1

    def test_wrongly_guarded_advance_fires(self, tmp_path):
        # `n > 0` is a guard, but not the truncation check — the
        # advance is still unchecked on the taken path.
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n > 0)
                    buf += n;
            }
        """)
        assert len(results) == 1

    def test_direct_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                buf += snprintf(buf, remaining, "x");
            }
        """)
        assert len(results) == 1
        assert "no truncation check possible" in results[0]["message"]


class TestNegatives:
    def test_truncation_checked_advance_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n >= remaining)
                    return;
                buf += n;
            }
        """)
        assert results == []

    def test_unused_return_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                snprintf(buf, remaining, "x");
            }
        """)
        assert results == []
