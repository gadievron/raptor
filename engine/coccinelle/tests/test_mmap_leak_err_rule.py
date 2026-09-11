"""Fixture tests for the mmap_leak_err verification-grade rule.

The rule carries ``@role: verification`` — a false positive mints a
false "confirmed" leak verdict. The negatives pin the wrapper-shape
regression: an unanchored ``return`` match flagged both the mandatory
MAP_FAILED error return (the mapping never existed) and the success
``return addr;`` (ownership transfer), so every correct mmap wrapper
double-flagged. The match is now anchored on the MAP_FAILED check and
excludes ownership-transfer returns.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "mmap_leak_err.cocci"
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
    def test_error_return_after_successful_mmap_fires_decl(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0)
                    return -22;
                munmap(addr, len);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "mmap_leak_err"
        assert results[0]["line"] == 7

    def test_error_return_after_successful_mmap_fires_assign(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr;
                addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0)
                    return -22;
                munmap(addr, len);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 8


class TestNegatives:
    def test_correct_wrapper_does_not_fire(self, tmp_path):
        # The canonical shape of every correct mmap wrapper: the
        # MAP_FAILED return releases nothing (mapping never existed)
        # and `return addr;` transfers ownership to the caller.
        results = _run_rule(tmp_path, """\
            void *map_file(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return 0;
                return addr;
            }
        """)
        assert results == []

    def test_munmap_before_error_return_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0) {
                    munmap(addr, len);
                    return -22;
                }
                munmap(addr, len);
                return 0;
            }
        """)
        assert results == []
