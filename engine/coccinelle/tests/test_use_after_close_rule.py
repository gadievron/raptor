"""Native descriptor-lifetime candidate contracts; validity needs review."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_read_after_close_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int drain(int fd, char *buf, unsigned long n)
            {
                close(fd);
                return read(fd, buf, n);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_close"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_fd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int reopen_read(int fd, const char *path, char *buf,
                            unsigned long n)
            {
                close(fd);
                fd = open(path, 0);
                return read(fd, buf, n);
            }
        """)
        assert results == []


@pytest.mark.parametrize("consumer", ["read", "write", "ioctl", "recv", "send", "recvfrom", "sendto", "pread", "pwrite", "readv", "writev"])
def test_each_later_io_use_is_retained(tmp_path, consumer):
    lines = ["void f(int fd, int other) {", "close(fd);", "observe(fd);",
             f"{consumer}(fd, 0, 0);", f"fd = {consumer}(fd, 0, 0);", "}",
             "void g(int fd, int other) {", "close(fd);", f"{consumer}(other, fd, 0);", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == {
        lines.index(f"{consumer}(fd, 0, 0);") + 1,
        lines.index(f"fd = {consumer}(fd, 0, 0);") + 1,
    }
    assert len(rows) == 2


def test_multiple_origins_do_not_duplicate_io_reports(tmp_path):
    rows = _run_rule(tmp_path, "void f(int fd) { close(fd); close(fd); read(fd, 0, 0); write(fd, 0, 0); }\n")
    assert len(rows) == 2


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_resource_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = ''
    source = prefix + 'void partial(int *fds, int index, char *buf) { close(fds[index + 1]); read(fds[index + 1], buf, 1); }' + "\n"
    partial_line = 1 + prefix.count("\n")
    if other_hit:
        source += 'void other(int fd, char *buf) { close(fd); read(fd, buf, 1); }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["rule"] == 'use_after_close'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=partial_line, line_end=partial_line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
    assert len(result.matches) == int(other_hit)
