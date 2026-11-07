"""Fixture tests for the open_creat_no_mode rule.

Verification-role rule (fires mint confirmed CWE-732 verdicts):
open() with O_CREAT but only two arguments reads uninitialised
stack data for the permission bits. The positive pins the two-arg
O_CREAT call; the negatives pin the mode-supplied call and a
two-arg open without O_CREAT (mode legitimately omitted).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "open_creat_no_mode.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_two_arg_o_creat_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int make_log(const char *path)
            {
                return open(path, O_CREAT | O_WRONLY);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "open_creat_no_mode"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_mode_supplied_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int make_log(const char *path)
            {
                return open(path, O_CREAT | O_WRONLY, 0600);
            }
        """)
        assert results == []

    def test_rdonly_without_creat_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int read_log(const char *path)
            {
                return open(path, O_RDONLY);
            }
        """)
        assert results == []


@pytest.mark.parametrize("api", ["open", "open64", "openat", "openat64"])
def test_mode_requirement_depends_on_exact_surviving_flags(tmp_path, api):
    cases = (
        ("O_CREAT", True), ("O_TMPFILE", True),
        ("O_WRONLY | O_CREAT", True), ("O_CREAT | O_WRONLY", True),
        ("(O_TMPFILE | O_RDWR)", True), ("O_CREAT | O_TMPFILE", True),
        ("(O_CREAT | flags) & O_CREAT", True),
        ("O_CREAT | (flags & MASK)", True),
        ("O_CREAT & O_CREAT", True),
        ("O_CREAT | 0UL", True), ("O_TMPFILE | 010U", True),
        ("O_CREAT | 0x0UL", True),
        ("O_RDONLY", False), ("MY_O_CREAT", False),
        ("O_CREAT_BACKUP", False), ("MY_O_TMPFILE", False),
        ("O_CREAT & 0", False), ("flags & O_CREAT", False),
        ("flags & ~O_CREAT", False), ("O_CREAT ^ O_CREAT", False),
        ("O_CREAT && flags", False), ("flags || O_CREAT", False),
        ("contains(O_CREAT)", False), ("O_TMPFILE & O_DIRECTORY", False),
        ("0x40", False), ("O_CREAT | " + "0 | " * 160 + "0", False),
    )
    prefix = "dirfd, path, " if api in ("openat", "openat64") else "path, "
    lines = []
    expected = set()
    for flags, should_report in cases:
        for mode in ("", ", 0600"):
            lines += [f"int case_{len(lines)}(int dirfd, char *path, int flags) {{",
                      f"return {api}({prefix}{flags}{mode});", "}"]
            if should_report and not mode:
                expected.add(len(lines) - 1)
    # Similarly named wrappers are outside the standard-library model.
    lines += ["int wrapper(int dirfd, char *path) {",
              f"return my_{api}({prefix}O_CREAT);", "}"]
    for index in range(120):
        lines += [f"int repeated_{index}(int dirfd, char *path) {{",
                  f"return {api}({prefix}O_CREAT | O_WRONLY);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"open_creat_no_mode"}


@pytest.mark.integration
def test_missing_mode_filter_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'int missing(char *p) { return open64(p, O_CREAT | O_WRONLY); }\n'
        'int supplied(char *p) { return open64(p, O_CREAT, 0600); }\n'
        'int masked(char *p) { return open(p, O_CREAT & 0); }\n'
        'int named(char *p) { return open(p, MY_O_CREAT); }\n'
        'void twice(int fd) { close(fd); close(fd); }\n',
    )
    original = runner._confined_default_runner
    invocations = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("double_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"open_creat_no_mode", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["open_creat_no_mode"].matches) == 1
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations
