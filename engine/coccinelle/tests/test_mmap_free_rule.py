"""Fixture tests for the mmap_free rule.

Verification-role rule (fires mint confirmed CWE-762 verdicts):
mmap'd memory passed to free() corrupts heap allocator metadata —
it must be released with munmap(). The positive pins free on the
mapping; the negative pins the correct munmap release.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "mmap_free.cocci"
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
    def test_free_of_mapping_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                free(map);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "mmap_free"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_munmap_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                munmap(map, len);
            }
        """)
        assert results == []
