"""Fixture tests for the toctou_check_use rule.

The permission-check leg must match both inode_permission calling
conventions (legacy (inode, mask) and idmap-first (idmap, inode,
mask) — the checked object is the SECOND argument in the latter).
The list_empty legs are retired: whether the caller holds the list
lock is invisible in-function, so they classified the ubiquitous
caller-locked helper idiom as a race.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "toctou_check_use.cocci"
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
    def test_legacy_inode_permission_then_unlocked_write_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(struct inode *ino)
            {
                int err = inode_permission(ino, MAY_WRITE);
                if (err)
                    return err;
                ino->i_size = 0;
                return 0;
            }
        """)
        assert len(results) == 1
        assert "i_size" in results[0]["message"]

    def test_idmap_first_inode_permission_fires(self, tmp_path):
        # Idmap-first convention: the inode is the SECOND argument; a
        # first-argument bind would attach the check to the idmap and
        # never see the inode use.
        results = _run_rule(tmp_path, """\
            int bug(struct mnt_idmap *m, struct inode *ino)
            {
                int err = inode_permission(m, ino, MAY_WRITE);
                if (err)
                    return err;
                ino->i_size = 0;
                return 0;
            }
        """)
        assert len(results) == 1
        assert "i_size" in results[0]["message"]

    def test_free_after_refcount_read_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct obj *o)
            {
                if (atomic_read(&o->refs) == 1)
                    kfree(o);
            }
        """)
        assert len(results) == 1
        assert "refcount" in results[0]["message"]


class TestNegatives:
    def test_lock_between_check_and_use_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(struct inode *ino)
            {
                int err = inode_permission(ino, MAY_WRITE);
                if (err)
                    return err;
                spin_lock(&ino->i_lock);
                ino->i_size = 0;
                return 0;
            }
        """)
        assert results == []

    def test_caller_locked_list_helper_does_not_fire(self, tmp_path):
        # The canonical lockless helper whose caller holds the list
        # lock. In-function matching cannot see the caller's lock, so
        # this shape must never be reported.
        results = _run_rule(tmp_path, """\
            struct entry *ok(struct pool *p)
            {
                struct entry *e = 0;
                if (!list_empty(&p->free))
                    e = list_first_entry(&p->free, struct entry, node);
                return e;
            }
        """)
        assert results == []

    def test_list_del_after_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct pool *p, struct entry *e)
            {
                if (!list_empty(&p->free)) {
                    list_del(&e->node);
                }
            }
        """)
        assert results == []
