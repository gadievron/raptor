"""Fixture tests for the copy_to_user_uninit rule.

Exactly one report per copy site, and only for the
absent-initialization shape: memset, whole-struct assignment, member
assignment, and helper calls taking the address all count as
initialization (spatch cannot prove FULL field coverage, so
partially-assigned structs are undecidable and stay silent).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "copy_to_user_uninit.cocci"
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
    def test_uninitialized_struct_fires_once(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int leak(struct info *up)
            {
                struct info out;
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_to_user_uninit"


class TestNegatives:
    def test_member_assigned_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                out.a = 1;
                out.b = 2;
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []

    def test_memset_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                memset(&out, 0, sizeof(out));
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []

    def test_helper_initialized_struct_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct info { int a; int b; };
            int ok(struct info *up)
            {
                struct info out;
                fill_info(&out, 3);
                if (copy_to_user(up, &out, sizeof(out)))
                    return -14;
                return 0;
            }
        """)
        assert results == []

def test_initialization_and_observer_contracts(tmp_path):
    # Mark the exact unsafe sites in one native scan. Every negative is
    # checked alongside positives, so parse failures cannot pass as silence.
    # Conditional initialization remains outside this conservative proof:
    # silence on those rows means undecidable, not that every path is safe.
    # Repeated copies retain the rule's existing nearest-copy scope; the
    # unmarked later copy is not a safe control.
    # Same-name nested declarations are also conservatively undecidable.
    cases = {
        "uninitialized": "struct info out; copy_to_user(up, &out, sizeof(out)); // finding",
        "scalar": "unsigned char out; copy_to_user(up, &out, sizeof(out)); // finding",
        "explicit_auto": "auto struct info out; copy_to_user(up, &out, sizeof(out)); // finding",
        "typedef_raw": "info_t out; copy_to_user(up, &out, sizeof(out)); // finding",
        "scalar_initializer": "unsigned char out = 42; copy_to_user(up, &out, sizeof(out));",
        "zero_initializer": "struct info out = {0}; copy_to_user(up, &out, sizeof(out));",
        "designated_initializer": "struct info out = {.byte = 42}; copy_to_user(up, &out, sizeof(out));",
        "call_initializer": "struct info out = make_info(); copy_to_user(up, &out, sizeof(out));",
        "typedef_initializer": "info_t out = {0}; copy_to_user(up, &out, sizeof(out));",
        "static_zero": "static struct info out; copy_to_user(up, &out, sizeof(out));",
        "static_initializer": "static struct info out = {0}; copy_to_user(up, &out, sizeof(out));",
        "extern_object": "extern struct info out; copy_to_user(up, &out, sizeof(out));",
        "whole_assignment": "struct info out; out = make_info(); copy_to_user(up, &out, sizeof(out));",
        "member_assignment": "struct info out; out.byte = 42; copy_to_user(up, &out, sizeof(out));",
        "helper_first": "struct info out; fill_first(&out, 42); copy_to_user(up, &out, sizeof(out));",
        "helper_middle": "struct info out; fill_middle(42, &out, 1); copy_to_user(up, &out, sizeof(out));",
        "helper_last": "struct info out; fill_last(42, &out); copy_to_user(up, &out, sizeof(out));",
        "copy_into": "struct info out; memcpy(&out, up, sizeof(out)); copy_to_user(up, &out, sizeof(out));",
        "move_into": "struct info out; memmove(&out, up, sizeof(out)); copy_to_user(up, &out, sizeof(out));",
        "copy_from": "struct info out; memcpy(up, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "move_from": "struct info out; memmove(up, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "compare_first": "struct info out; memcmp(&out, up, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "compare_last": "struct info out; memcmp(up, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "bcmp_last": "struct info out; bcmp(up, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "memchr_first": "struct info out; memchr(&out, 0, sizeof(out)); copy_to_user(up, &out, sizeof(out)); // finding",
        "repeated_copy_nearest_scope": "struct info out;\ncopy_to_user(up, &out, sizeof(out)); // finding\ncopy_to_user(up, &out, sizeof(out));",
        "initialized_sibling": "struct info other = {0}; struct info out; copy_to_user(up, &out, sizeof(out)); // finding",
        "conditional_assignment_undecidable": "struct info out; if (condition()) out = make_info(); copy_to_user(up, &out, sizeof(out));",
        "both_branches": "struct info out; if (condition()) out = make_info(); else out = make_info(); copy_to_user(up, &out, sizeof(out));",
        "conditional_helper_undecidable": "struct info out; if (condition()) fill_last(42, &out); copy_to_user(up, &out, sizeof(out));",
        "both_helpers": "struct info out; if (condition()) fill_first(&out, 42); else fill_last(42, &out); copy_to_user(up, &out, sizeof(out));",
        "initialized_shadow": "struct info out; { struct info out = {0}; copy_to_user(up, &out, sizeof(out)); }",
        "uninitialized_shadow": "struct info out = {0}; { struct info out; copy_to_user(up, &out, sizeof(out)); } // finding",
        "shadow_scope_undecidable": "struct info out; { struct info out = {0}; } copy_to_user(up, &out, sizeof(out));",
        "global_zero": "copy_to_user(up, &global_out, sizeof(global_out));",
        "raw_sibling": "struct info other; struct info out = {0}; copy_to_user(up, &out, sizeof(out));",
    }
    lines = ["struct info { unsigned char byte; };", "typedef struct info info_t;",
             "struct info make_info(void);", "struct info global_out;"]
    for name, body in cases.items():
        lines += [f"void {name}(void *up) {{", body, "}"]
    source = "\n".join(lines) + "\n"
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "// finding" in line}
    results = _run_rule(tmp_path, source)
    assert {r["line"] for r in results} == expected
    assert len(results) == len(expected), "a selected copy site must not have duplicate reports"
