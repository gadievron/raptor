"""Fixture tests for the unchecked_strtol rule.

Verification-role rule (fires mint confirmed CWE-20 verdicts). The
rule emits two ids: unchecked_strtol (endptr captured but neither it
nor errno is consulted) and strtol_null_endptr (NULL endptr — partial
conversion undetectable by construction). Negatives pin every
documented check shape: *endptr, endptr == s / endptr != s, and
errno.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "unchecked_strtol.cocci"
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
    def test_endptr_captured_but_never_checked_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                return v;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "unchecked_strtol"
        assert results[0]["line"] == 4

    def test_null_endptr_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long parse(const char *s)
            {
                return strtoul(s, NULL, 10);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "strtol_null_endptr"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_endptr_deref_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                if (*end != 0)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_endptr_equals_input_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                if (end == s)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_errno_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v;
                errno = 0;
                v = strtol(s, &end, 10);
                if (errno != 0)
                    return -1;
                return v;
            }
        """)
        assert results == []
