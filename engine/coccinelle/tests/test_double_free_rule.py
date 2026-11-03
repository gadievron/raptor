"""Fixture tests for the double_free verification-grade rule.

Same when-clause class as use_after_free (U12-F1): the header claimed
any reassignment between the two frees suppresses the match, but the
clause only excluded allocator calls / NULL — ``free(p); p = q;
free(p);`` frees two different objects and was flagged as a confirmed
double free. The rule carries ``@role: verification`` (direct status
promotion), so the negative fixtures below are verdict-integrity
regressions.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_free.cocci"
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
    assert proc.returncode == 0, proc.stdout + proc.stderr
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_sequential_double_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                free(p);
                free(p);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_free"

    def test_same_line_double_free_fires(self, tmp_path):
        # The self-pairing guard must compare positions, not lines:
        # the identical two-free sequence on ONE line is the same bug.
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                free(p); free(p);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_free"

    def test_kfree_double_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct s *p)
            {
                kfree(p);
                log_it();
                kfree(p);
            }
        """)
        assert len(results) == 1

    def test_branch_free_without_return_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(struct s *p)
            {
                if (bad(p)) {
                    kfree(p);
                }
                kfree(p);
                return 0;
            }
        """)
        assert len(results) >= 1


class TestNegatives:
    def test_reassignment_between_frees_does_not_fire(self, tmp_path):
        # free(p); p = q; free(p); frees two different objects.
        results = _run_rule(tmp_path, """\
            void ok(char *p, char *q)
            {
                free(p);
                p = q;
                free(p);
            }
        """)
        assert results == []

    def test_list_free_loop_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void teardown(struct node *head)
            {
                struct node *cur = head;
                struct node *nxt;
                while (cur) {
                    nxt = cur->next;
                    free(cur);
                    cur = nxt;
                }
            }
        """)
        assert results == []

    def test_error_cleanup_branch_with_return_does_not_fire(self, tmp_path):
        # Branch frees AND returns: no CFG path connects the frees —
        # the canonical error-cleanup idiom.
        results = _run_rule(tmp_path, """\
            int ok(struct s *p)
            {
                if (setup(p) < 0) {
                    kfree(p);
                    return -1;
                }
                finish(p);
                kfree(p);
                return 0;
            }
        """)
        assert results == []

    def test_branch_reassignment_does_not_fire(self, tmp_path):
        # Branch frees then reassigns (no return): the fallthrough
        # free targets the new object.
        results = _run_rule(tmp_path, """\
            int ok(struct s *p, struct s *q)
            {
                if (bad(p)) {
                    kfree(p);
                    p = q;
                }
                kfree(p);
                return 0;
            }
        """)
        assert results == []

    def test_allocator_reassignment_still_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct s *p)
            {
                kfree(p);
                p = kmalloc(sizeof(*p), GFP_KERNEL);
                kfree(p);
            }
        """)
        assert results == []


@pytest.mark.parametrize(("body", "fires"), [
    ("if (flag) { kfree(p); p = kmalloc(16, 0); } kfree(p);", False),
    ("if (flag) { kfree(p); p = q; } kfree(p);", False),
    ("if (flag) { kfree(p); p = 0; } kfree(p);", False),
    ("if (flag) { if (other) { kfree(p); p = q; } } kfree(p);", False),
    ("if (flag) { kfree(p); goto out; } kfree(p); out: return;", False),
    ("if (flag) { kfree(p); } else { kfree(p); }", False),
    ("while (flag--) { if (other) { kfree(p); p = q; } kfree(p); p = 0; }", False),
    ("while (flag--) { if (other) { kfree(p); p = kmalloc(16, 0); if (!p) goto fail; } if (flag) { kfree(p); p = 0; } } kfree(p); return; fail: kfree(p);", False),
    ("if (flag) { if (other) { kfree(p); } } kfree(p);", True),
    ("if (flag) { kfree(p); log_it(); } kfree(p);", True),
    ("if (flag) { kfree(p); if (other) p = q; } kfree(p);", True),
    ("while (flag--) { kfree(p); if (other) kfree(p); }", True),
    ("kfree(p); while (flag--) { kfree(p); }", True),
    ("if (flag) { kfree(p); goto fail; } return; fail: kfree(p);", True),
    ("if (flag) { kvfree(p); } kvfree(p);", True),
    ("if (flag) { free(p); } free(p);", True),
])
def test_branch_and_loop_paths(tmp_path, body, fires):
    results = _run_rule(tmp_path, "void sample(char *p, char *q, int flag, int other) { " + body + " }\n")
    assert bool(results) is fires


def test_single_free_site_loop_remains_a_documented_miss(tmp_path):
    # A repeated execution of one free site is not distinguished from a
    # reflexive position pairing. Do not turn every single free into an alert.
    assert _run_rule(tmp_path, "void sample(char *p, int count) { while (count--) { kfree(p); } }\n") == []
