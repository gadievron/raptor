"""Fixture tests for the socket_no_cloexec rule.

Descriptors that reach the portable post-call idiom
``fcntl(fd, F_SETFD, ...)`` are close-on-exec by the time any exec can
happen, so neither the socket() nor the accept() leg may report them.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "socket_no_cloexec.cocci"
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
    def test_socket_without_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(void)
            {
                int fd = socket(2, SOCK_STREAM, 0);
                return fd;
            }
        """)
        assert [r["rule"] for r in results] == ["socket_no_cloexec"]

    def test_accept_without_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int s)
            {
                int c = accept(s, 0, 0);
                return c;
            }
        """)
        assert [r["rule"] for r in results] == ["accept_no_cloexec"]


class TestNegatives:
    def test_sock_cloexec_flag_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(void)
            {
                int fd = socket(2, SOCK_STREAM | SOCK_CLOEXEC, 0);
                return fd;
            }
        """)
        assert results == []

    def test_socket_then_fcntl_setfd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(void)
            {
                int fd = socket(2, SOCK_STREAM, 0);
                fcntl(fd, F_SETFD, FD_CLOEXEC);
                return fd;
            }
        """)
        assert results == []

    def test_accept_then_fcntl_setfd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c = accept(s, 0, 0);
                fcntl(c, F_SETFD, FD_CLOEXEC);
                return c;
            }
        """)
        assert results == []

    def test_accept4_with_cloexec_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c = accept4(s, 0, 0, SOCK_CLOEXEC);
                return c;
            }
        """)
        assert results == []

    def test_plain_assignment_form_fcntl_does_not_fire(self, tmp_path):
        # Safe set must also cover the assignment (non-declaration)
        # binding of the descriptor.
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c;
                c = accept(s, 0, 0);
                fcntl(c, F_SETFD, FD_CLOEXEC);
                return c;
            }
        """)
        assert results == []
