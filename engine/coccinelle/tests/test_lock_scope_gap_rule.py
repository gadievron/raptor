"""Fixture tests for the lock_scope_gap rule.

Only a re-access of the SAME field that was touched under the lock
is reported; a different field of the same object after unlock is the
normal shape of correct code (a lock protects fields, not objects).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "lock_scope_gap.cocci"
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
    def test_same_field_reread_after_unlock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bump(struct dev *d)
            {
                mutex_lock(&d->m);
                d->count++;
                mutex_unlock(&d->m);
                report(d->count);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "lock_scope_gap"

    def test_spin_same_field_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bump(struct dev *d)
            {
                spin_lock(&d->l);
                d->count++;
                spin_unlock(&d->l);
                report(d->count);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_different_field_after_unlock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bump(struct dev *d)
            {
                int id;
                mutex_lock(&d->m);
                d->count++;
                mutex_unlock(&d->m);
                id = d->id;
                report(id);
            }
        """)
        assert results == []

    def test_reacquired_lock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bump(struct dev *d)
            {
                mutex_lock(&d->m);
                d->count++;
                mutex_unlock(&d->m);
                mutex_lock(&d->m);
                report(d->count);
            }
        """)
        assert results == []
