"""Fixture tests for the fcntl_flag_domain rule.

Verification-role rule (fires mint confirmed CWE-688 verdicts):
FD_CLOEXEC belongs to the F_SETFD domain and O_NONBLOCK to the
F_SETFL domain — crossing them silently sets the wrong bits. The
positives pin both cross-domain directions; the negatives pin the
two correct pairings.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fcntl_flag_domain.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_setfl_with_fd_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_cloexec(int fd)
            {
                return fcntl(fd, F_SETFL, FD_CLOEXEC);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fcntl_flag_domain"
        assert results[0]["line"] == 3

    def test_setfd_with_o_nonblock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_nonblock(int fd)
            {
                return fcntl(fd, F_SETFD, O_NONBLOCK);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fcntl_flag_domain"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_setfd_with_fd_cloexec_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_cloexec(int fd)
            {
                return fcntl(fd, F_SETFD, FD_CLOEXEC);
            }
        """)
        assert results == []

    def test_setfl_with_o_nonblock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_nonblock(int fd)
            {
                return fcntl(fd, F_SETFL, O_NONBLOCK);
            }
        """)
        assert results == []


@pytest.mark.parametrize("api", ["fcntl", "fcntl64"])
def test_exact_flag_domains_and_mixed_flags(tmp_path, api):
    cases = (
        ("F_SETFL", "FD_CLOEXEC", True),
        ("F_SETFL", "FD_CLOEXEC | O_NONBLOCK", True),
        ("F_SETFL", "O_APPEND | FD_CLOEXEC", True),
        ("F_SETFL", "FD_CLOEXEC | flags", True),
        ("F_SETFL", "(FD_CLOEXEC | flags) & FD_CLOEXEC", True),
        ("F_SETFL", "FD_CLOEXEC | 0UL", True),
        ("F_SETFD", "O_NONBLOCK", True),
        ("F_SETFD", "FD_CLOEXEC | O_NONBLOCK", True),
        ("F_SETFD", "O_APPEND | FD_CLOEXEC", True),
        ("F_SETFD", "O_ASYNC | flags", True),
        ("F_SETFD", "O_DIRECT", True),
        ("F_SETFD", "O_NOATIME", True),
        ("(F_SETFD)", "O_NONBLOCK", True),
        ("F_SETFD", "(O_APPEND | flags) & O_APPEND", True),
        ("F_SETFD", "O_ASYNC | 00U", True),
        ("F_SETFL", "O_NONBLOCK", False),
        ("F_SETFD", "FD_CLOEXEC", False),
        ("F_SETFL", "MY_FD_CLOEXEC", False),
        ("F_SETFL", "FD_CLOEXEC_BACKUP", False),
        ("F_SETFD", "MY_O_NONBLOCK", False),
        ("F_SETFD", "O_APPEND_BACKUP", False),
        ("F_SETFL", "FD_CLOEXEC & 0", False),
        ("F_SETFD", "O_NONBLOCK & 0", False),
        ("F_SETFD", "flags & ~O_NONBLOCK", False),
        ("F_SETFL", "flags & FD_CLOEXEC", False),
        ("F_SETFL", "FD_CLOEXEC ^ FD_CLOEXEC", False),
        ("F_SETFL", "FD_CLOEXEC && flags", False),
        ("F_SETFD", "contains(O_NONBLOCK)", False),
        ("F_GETFD", "O_NONBLOCK", False),
        ("MY_F_SETFD", "O_NONBLOCK", False),
        ("F_SETFD + 0", "O_NONBLOCK", False),
        ("F_SETFL", "1", False),
        ("F_SETFD", "O_NONBLOCK | " + "0 | " * 160 + "0", False),
    )
    lines = []
    expected = set()
    for command, flags, should_report in cases:
        lines += [f"int case_{len(lines)}(int fd, int flags) {{",
                  f"return {api}(fd, {command}, {flags});", "}"]
        if should_report:
            expected.add(len(lines) - 1)
    lines += ["int wrapper(int fd) {",
              f"return my_{api}(fd, F_SETFL, FD_CLOEXEC);", "}"]
    for index in range(120):
        lines += [f"int repeated_{index}(int fd) {{",
                  f"return {api}(fd, F_SETFD, O_NONBLOCK | FD_CLOEXEC);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"fcntl_flag_domain"}


@pytest.mark.integration
def test_domain_filter_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'int mixed(int fd) { return fcntl64(fd, F_SETFL, FD_CLOEXEC | O_NONBLOCK); }\n'
        'int status(int fd) { return fcntl(fd, F_SETFD, O_APPEND | FD_CLOEXEC); }\n'
        'int correct(int fd) { return fcntl(fd, F_SETFL, O_NONBLOCK); }\n'
        'int masked(int fd) { return fcntl(fd, F_SETFL, FD_CLOEXEC & 0); }\n'
        'int missing(char *p) { return open(p, O_CREAT | O_WRONLY); }\n',
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
        source, [_RULE, _RULE.with_name("open_creat_no_mode.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"fcntl_flag_domain", "open_creat_no_mode"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["fcntl_flag_domain"].matches) == 2
    assert len(results["open_creat_no_mode"].matches) == 1
    assert len(invocations) == 1, invocations
