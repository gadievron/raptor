"""Fixture tests for the use_after_unlock rule.

The negatives pin the field-vs-lifetime regression: generic
spin_lock/mutex_lock legs flagged ANY member access after releasing a
lock embedded in the same object — the shape of virtually all correct
locking code, since an ordinary lock guards fields, not the object's
lifetime. Those legs are gone; only the kernel-IPC leg remains, where
the ipc_lock/ipc_unlock convention makes the lock the object's
liveness pin (access after ipc_unlock races a concurrent IPC_RMID).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_unlock.cocci"
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
    def test_member_access_after_ipc_unlock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int get_mode(struct kern_ipc_perm *ipcp)
            {
                ipc_unlock(ipcp);
                return ipcp->mode;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_unlock"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_object_access_after_spin_unlock_does_not_fire(self, tmp_path):
        # Correct code: the spinlock guards count; the caller owns st
        # and may touch other fields after the critical section.
        results = _run_rule(tmp_path, """\
            void update(struct state *st)
            {
                spin_lock(&st->lock);
                st->count++;
                spin_unlock(&st->lock);
                notify(st->wq);
            }
        """)
        assert results == []

    def test_object_access_after_mutex_unlock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void update2(struct state *st)
            {
                mutex_lock(&st->m);
                st->count++;
                mutex_unlock(&st->m);
                log_count(st->count);
            }
        """)
        assert results == []
