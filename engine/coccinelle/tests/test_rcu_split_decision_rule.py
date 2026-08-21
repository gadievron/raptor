"""Fixture tests for the rcu_split_decision detection-grade rule."""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_split_decision.cocci"
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


class TestPositive:
    def test_cred_then_post_section_mm_read_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int may_access(struct task_struct *task, unsigned int mode)
            {
                const struct cred *tcred;
                struct mm_struct *mm;

                rcu_read_lock();
                tcred = __task_cred(task);
                if (!uid_ok(tcred))
                    goto deny;
                rcu_read_unlock();
                mm = task->mm;
                if (mm && !dump_ok(mm))
                    return -1;
                return 0;
            deny:
                rcu_read_unlock();
                return -1;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "rcu_split_decision"


class TestNegatives:
    def test_mm_read_inside_section_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int ok_fn(struct task_struct *task)
            {
                const struct cred *tcred;
                struct mm_struct *mm;

                rcu_read_lock();
                tcred = __task_cred(task);
                mm = task->mm;
                rcu_read_unlock();
                return tcred && mm;
            }
        """)
        assert results == []

    def test_relocked_read_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int ok_fn(struct task_struct *task)
            {
                const struct cred *tcred;
                struct mm_struct *mm;

                rcu_read_lock();
                tcred = __task_cred(task);
                rcu_read_unlock();
                rcu_read_lock();
                mm = task->mm;
                rcu_read_unlock();
                return tcred && mm;
            }
        """)
        assert results == []

    def test_no_cred_read_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int ok_fn(struct task_struct *task)
            {
                struct mm_struct *mm;

                rcu_read_lock();
                do_stuff(task);
                rcu_read_unlock();
                mm = task->mm;
                return mm != 0;
            }
        """)
        assert results == []
