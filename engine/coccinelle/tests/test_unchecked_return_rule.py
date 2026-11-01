"""Fixture tests for the unchecked_return rule.

The rule must be a working witness in BOTH invocation modes: targeted
(``-D func=<name>``) and bare (no defines). Pre-fix the file only had
``virtual.func`` rules, so a define-less run had zero applicable rules
and spatch exited non-zero — the standing define-less dispatch of this
rule could never fire on anything.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "unchecked_return.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, defines: dict[str, str] | None = None,
) -> tuple[list[dict], int]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    cmd = ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"]
    for key, val in (defines or {}).items():
        cmd.extend(["-D", f"{key}={val}"])
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        cmd, capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results, proc.returncode


_MIXED_CALLERS = """\
    int good_caller(void)
    {
        int r;
        r = do_thing(1);
        if (r < 0)
            return r;
        return 0;
    }
    void bad_caller(void)
    {
        do_thing(2);
    }
"""


class TestBareMode:
    def test_bare_run_exits_zero(self, tmp_path):
        _results, rc = _run_rule(tmp_path, _MIXED_CALLERS)
        assert rc == 0

    def test_unchecked_call_of_checked_function_fires(self, tmp_path):
        results, _rc = _run_rule(tmp_path, _MIXED_CALLERS)
        assert len(results) == 1
        assert results[0]["rule"] == "unchecked_return"
        assert results[0]["line"] == 11
        assert "do_thing" in results[0]["message"]

    def test_function_never_checked_does_not_fire(self, tmp_path):
        # No call site checks the return — there is no in-file evidence
        # that checking is expected, so the bare mode stays silent.
        results, rc = _run_rule(tmp_path, """\
            void caller_a(void)
            {
                fire_and_forget(1);
            }
            void caller_b(void)
            {
                fire_and_forget(2);
            }
        """)
        assert rc == 0
        assert results == []

    def test_direct_condition_use_does_not_fire(self, tmp_path):
        # The return value IS checked, just without an intermediate
        # variable — a stored-checked sibling site must not turn the
        # direct-condition site into a finding.
        results, _rc = _run_rule(tmp_path, """\
            int f(void)
            {
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                if (do_io() < 0)
                    return -1;
                return 0;
            }
        """)
        assert results == []

    def test_return_propagation_does_not_fire(self, tmp_path):
        # `return fn();` hands the value to the caller — not ignored.
        results, _rc = _run_rule(tmp_path, """\
            int f(void)
            {
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                return do_io();
            }
        """)
        assert results == []

    def test_void_cast_discard_does_not_fire(self, tmp_path):
        # `(void)fn();` is the explicit discard idiom — the classic
        # deliberate CWE-252 suppression, never a finding.
        results, _rc = _run_rule(tmp_path, """\
            int f(void)
            {
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                (void)do_io();
                return 0;
            }
        """)
        assert results == []

    def test_while_guard_consumption_does_not_fire(self, tmp_path):
        # A call consumed as a while-loop guard is checked every
        # iteration — not ignored.
        results, _rc = _run_rule(tmp_path, """\
            int f(void)
            {
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                while (do_io() > 0)
                    step();
                return 0;
            }
        """)
        assert results == []

    def test_for_guard_consumption_does_not_fire(self, tmp_path):
        # Same for a for-loop condition slot.
        results, _rc = _run_rule(tmp_path, """\
            int f(void)
            {
                int i;
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                for (i = 0; do_io() > 0; i++)
                    step();
                return 0;
            }
        """)
        assert results == []

    def test_ignored_call_inside_loop_body_still_fires(self, tmp_path):
        # Only the condition slot consumes the value — a value-ignored
        # call in the loop BODY is still a finding.
        results, _rc = _run_rule(tmp_path, """\
            int f(int c)
            {
                int r;
                r = do_io();
                if (r < 0)
                    return r;
                while (c--)
                    do_io();
                return 0;
            }
        """)
        assert len(results) == 1
        assert "do_io" in results[0]["message"]

    def test_all_call_sites_checked_does_not_fire(self, tmp_path):
        results, _rc = _run_rule(tmp_path, """\
            int caller_a(void)
            {
                int r;
                r = do_thing(1);
                if (r < 0)
                    return r;
                return 0;
            }
            int caller_b(void)
            {
                int s;
                s = do_thing(2);
                if (!s)
                    return -1;
                return 0;
            }
        """)
        assert results == []


class TestTargetedMode:
    def test_named_function_unchecked_call_fires(self, tmp_path):
        results, rc = _run_rule(
            tmp_path, _MIXED_CALLERS, defines={"func": "do_thing"},
        )
        assert rc == 0
        assert len(results) == 1
        assert results[0]["line"] == 11
        # Targeted and bare legs must never double-report a position.
        assert results[0]["message"].startswith("Return value not checked")

    def test_other_function_name_does_not_fire(self, tmp_path):
        results, _rc = _run_rule(
            tmp_path, _MIXED_CALLERS, defines={"func": "unrelated_fn"},
        )
        assert results == []


@pytest.mark.parametrize("use", [
    "int result = do_io(); store(result);",
    "result = do_io(); store(result);",
    "store(do_io());",
])
def test_consumed_value_is_not_an_ignored_call(tmp_path, use):
    source = """
        int checked(void) { int n = do_io(); if (n <= 0) return -1; return n; }
        void consumer(void) { int result; %s }
    """ % use
    results, rc = _run_rule(tmp_path, source)
    assert rc == 0
    assert results == []


def test_declaration_only_checked_sibling_seeds_detection(tmp_path):
    source = """
        int checked(void) { int n = do_io(); if (n <= 0) return -1; return n; }
        void ignored(void) { do_io(); }
    """
    results, rc = _run_rule(tmp_path, source)
    assert rc == 0
    assert len(results) == 1


def test_checked_evidence_does_not_leak_between_function_names(tmp_path):
    results, rc = _run_rule(tmp_path, """
        int checked(void) { int n = do_io(); if (n <= 0) return -1; return n; }
        void ignored(void) { do_io(); fire_and_forget(); }
    """)
    assert rc == 0
    assert len(results) == 1
    assert "do_io" in results[0]["message"]


def test_checked_evidence_is_scoped_to_its_source_file(tmp_path):
    (tmp_path / "checked.c").write_text(
        "int checked(void) { int n = do_io(); if (n < 0) return -1; return n; }\n")
    (tmp_path / "ignored.c").write_text("void ignored(void) { do_io(); }\n")
    result = subprocess.run(["spatch", "--sp-file", str(_RULE), "--dir", str(tmp_path),
                             "--no-show-diff"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "COCCIRESULT:" not in result.stdout + result.stderr


def test_boolean_use_alone_does_not_imply_required_return(tmp_path):
    # Diagnostic predicates can return a flag AND perform their intended
    # side effect. Boolean use does not establish a must-check contract.
    results, rc = _run_rule(tmp_path, """
        int diagnostic(void) { if (warn(1)) return -1; return 0; }
        void notify(void) { warn(2); }
    """)
    assert rc == 0
    assert results == []
