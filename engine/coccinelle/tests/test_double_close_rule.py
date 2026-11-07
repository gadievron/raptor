"""Fixture tests for the double_close rule.

Verification-role rule (fires mint confirmed CWE-675 verdicts):
closing the same fd twice without reassignment races against fd
reuse. The positive pins the back-to-back close pair; the negative
pins the rule's documented guard — fd reassigned (open) between
the closes.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_close_twice_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void teardown(int fd)
            {
                close(fd);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_close"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_fd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void recycle(int fd, const char *path)
            {
                close(fd);
                fd = open(path, 0);
                close(fd);
            }
        """)
        assert results == []


@pytest.mark.parametrize("first", ["fclose", "pclose"])
@pytest.mark.parametrize("second", ["fclose", "pclose"])
def test_stream_release_pairs_and_lifetime_barriers(tmp_path, first, second):
    lines = ["typedef struct stream FILE;"]
    expected = set()
    cases = (
        ("", "fp", True),
        ('fp = fopen("fresh", "r");', "fp", False),
        ('fp = popen("true", "r");', "fp", False),
        ("fp = other;", "fp", False),
        ("replace(&fp);", "fp", False),
        ("", "other", False),
    )
    for barrier, operand, should_report in cases:
        lines += [f"void case_{len(lines)}(FILE *fp, FILE *other) {{",
                  f"{first}(fp);", barrier, f"{second}({operand});", "}"]
        if should_report:
            expected.add(len(lines) - 1)
    # Similar names are wrappers, not modeled standard-library releases.
    for before, after in ((f"my_{first}", second), (first, f"my_{second}")):
        lines += [f"void wrapper_{len(lines)}(FILE *fp) {{",
                  f"{before}(fp);", f"{after}(fp);", "}"]
    for index in range(120):
        lines += [f"void repeated_{index}(FILE *fp) {{", f"{first}(fp);",
                  f"{second}(fp);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"double_fclose"}
