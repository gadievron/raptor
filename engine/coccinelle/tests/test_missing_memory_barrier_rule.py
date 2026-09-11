"""Fixture tests for the missing_memory_barrier rule.

Negatives pin the load-endpoint discipline: the second access must be
a genuine READ (a bare expression endpoint also matches the left-hand
side of an assignment, so consecutive field initialisation — two
stores — fired the rule) and the argument-taking barrier helpers
(``smp_store_mb`` etc.) must suppress like the zero-argument ones.
Positives keep the genuine shape firing: store to one field then an
unordered read of another field through the same pointer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "missing_memory_barrier.cocci"
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
    def test_store_then_assignment_read_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int pub(struct s *p, int v)
            {
                int r;
                p->data = v;
                r = p->flag;
                return r;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "missing_memory_barrier"

    def test_store_then_condition_read_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void pub(struct s *p, int v)
            {
                p->data = v;
                if (p->ready)
                    consume(p);
            }
        """)
        assert len(results) == 1

    def test_store_then_call_argument_read_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void pub(struct s *p, int v)
            {
                p->data = v;
                notify(p->waiters);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_consecutive_field_stores_do_not_fire(self, tmp_path):
        # Two stores, no load: plain struct initialisation.
        results = _run_rule(tmp_path, """\
            void init(struct s *p)
            {
                p->a = 1;
                p->b = 2;
            }
        """)
        assert results == []

    def test_smp_store_mb_suppresses(self, tmp_path):
        # smp_store_mb takes arguments — it must both suppress the
        # rule and never be reported as the unordered load itself.
        results = _run_rule(tmp_path, """\
            void ok(struct s *p, int v)
            {
                p->data = v;
                smp_store_mb(p->flag, 1);
            }
        """)
        assert results == []

    def test_smp_wmb_between_accesses_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(struct s *p, int v)
            {
                int r;
                p->data = v;
                smp_wmb();
                r = p->flag;
                return r;
            }
        """)
        assert results == []

    def test_read_once_load_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct s *p, int v)
            {
                p->data = v;
                if (READ_ONCE(p->ready))
                    consume(p);
            }
        """)
        assert results == []
