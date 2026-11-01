"""A publication lead requires explicit producer/consumer protocol evidence."""

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
    assert proc.returncode == 0, proc.stderr
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


def _protocol(publisher, *, tag="shared", payload="data", flag="ready"):
    return f"""
        void publish(struct shared *p, int value) {{ {publisher} }}
        int consume(struct {tag} *p) {{
            if (READ_ONCE(p->{flag})) {{ return p->{payload}; }}
            return 0;
        }}
    """


class TestPositives:
    def test_write_once_flag_without_release_fires(self, tmp_path):
        results = _run_rule(tmp_path, _protocol("p->data = value; WRITE_ONCE(p->ready, 1);"))
        assert len(results) == 1
        assert results[0]["rule"] == "missing_memory_barrier"


class TestNegatives:
    @pytest.mark.parametrize("publisher", [
        "p->data = value; smp_wmb(); WRITE_ONCE(p->ready, 1);",
        "p->data = value; smp_store_release(&p->ready, 1);",
        "spin_lock(&p->lock); p->data = value; WRITE_ONCE(p->ready, 1); spin_unlock(&p->lock);",
        "write_lock_bh(&p->lock); p->data = value; WRITE_ONCE(p->ready, 1); write_unlock_bh(&p->lock);",
        "p = allocate(); p->data = value; WRITE_ONCE(p->ready, 1);",
        "p->data = value; unknown_helper(p); WRITE_ONCE(p->ready, 1);",
        "p->data = value; p->ready = 1;",
        "p->data = value; WRITE_ONCE(p->ready, 1); handoff(p);",
    ])
    def test_synchronized_private_or_unknown_publisher_refuses(self, tmp_path, publisher):
        assert _run_rule(tmp_path, _protocol(publisher)) == []

    @pytest.mark.parametrize("kwargs", [
        {"tag": "different"}, {"payload": "other"}, {"flag": "other"},
    ])
    def test_consumer_must_bind_same_type_and_fields(self, tmp_path, kwargs):
        source = _protocol("p->data = value; WRITE_ONCE(p->ready, 1);", **kwargs)
        assert _run_rule(tmp_path, source) == []

    def test_no_consumer_is_not_protocol_evidence(self, tmp_path):
        assert _run_rule(tmp_path, """
            void publish(struct shared *p, int value) {
                p->data = value;
                WRITE_ONCE(p->ready, 1);
            }
        """) == []

    def test_plain_field_access_and_stack_object_are_not_concurrency(self, tmp_path):
        assert _run_rule(tmp_path, """
            struct pair { int a; int b; };
            int local(void) {
                struct pair object = {0};
                struct pair *p = &object;
                int value;
                p->a = 1;
                value = p->b;
                return value;
            }
            int locked(struct pair *p) {
                int value;
                spin_lock(&p->lock);
                p->a = 1;
                value = p->b;
                spin_unlock(&p->lock);
                return value;
            }
        """) == []
