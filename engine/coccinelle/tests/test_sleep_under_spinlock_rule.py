"""Fixture tests for the sleep_under_spinlock rule.

Pins the literal lock/unlock spellings (including the raw_spin_*
family) in both directions. Vocabulary extension of the release guard
(the ``@vocab: lock_releases`` marker) is exercised by the renderer
tests, not here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sleep_under_spinlock.cocci"
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
    def test_msleep_under_spin_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct dev *d)
            {
                spin_lock(&d->lock);
                msleep(1);
                spin_unlock(&d->lock);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sleep_under_spinlock"

    def test_msleep_under_raw_spin_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct dev *d)
            {
                raw_spin_lock(&d->lock);
                msleep(1);
                raw_spin_unlock(&d->lock);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_sleep_after_unlock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct dev *d)
            {
                spin_lock(&d->lock);
                prep(d);
                spin_unlock(&d->lock);
                msleep(1);
            }
        """)
        assert results == []

    def test_sleep_after_raw_unlock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct dev *d)
            {
                raw_spin_lock(&d->lock);
                prep(d);
                raw_spin_unlock(&d->lock);
                msleep(1);
            }
        """)
        assert results == []
