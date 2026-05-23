"""Tests for axis-7 dead-code suppression (Phase 7).

Composes with PR-4's ``packages.coccinelle.prereqs.gather_prereqs``
to mark a finding NOT_EXPLOITABLE when its enclosing function is
both `static` AND has zero callers / pointer-references in the
target subtree.

The static + pointer-ref guards are critical:
  * `static` ensures file-local linkage (no calls in this TU →
    genuinely dead).
  * Pointer-reference scan covers kernel struct ops vtable
    assignments (`.callback = func,`) and address-of uses that
    PR-4's `funcname(args)` matcher misses.
"""

from __future__ import annotations

import shutil

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _finding_in_dead_code,
    _function_is_static,
    _function_referenced_as_pointer,
)


def _finding(file_path: str, sink_line: int, rule_id: str) -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id=rule_id,
        message="t",
        source=Step(file_path=file_path, line=sink_line - 1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=sink_line, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )


# =====================================================================
# _function_is_static — heuristic
# =====================================================================


def test_static_detected_simple(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "static int helper(int a) { return a; }\n"
        "int public_fn(int a) { return a; }\n"
    )
    assert _function_is_static(str(f), "helper") is True
    assert _function_is_static(str(f), "public_fn") is False


def test_static_detected_multiline_signature(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "static int\n"
        "long_signature(struct foo *f,\n"
        "               int b)\n"
        "{ return 0; }\n"
    )
    assert _function_is_static(str(f), "long_signature") is True


def test_static_returns_false_on_missing_file():
    assert _function_is_static("/no/such/file.c", "any") is False


# =====================================================================
# _function_referenced_as_pointer — vtable / callback / addr-of
# =====================================================================


def test_pointer_ref_struct_field_assignment(tmp_path):
    f = tmp_path / "ops.c"
    f.write_text(
        "static int handler(int a) { return a; }\n"
        "struct ops_t my_ops = {\n"
        "    .handler = handler,\n"
        "};\n"
    )
    assert _function_referenced_as_pointer(tmp_path, "handler") is True


def test_pointer_ref_address_of(tmp_path):
    f = tmp_path / "use.c"
    f.write_text(
        "static int cb(int a) { return a; }\n"
        "int register_cb(int (*)(int));\n"
        "void boot(void) { register_cb(&cb); }\n"
    )
    assert _function_referenced_as_pointer(tmp_path, "cb") is True


def test_pointer_ref_passed_as_argument(tmp_path):
    f = tmp_path / "use.c"
    f.write_text(
        "static int cb(int a) { return a; }\n"
        "int register_cb(int (*)(int));\n"
        "void boot(void) { register_cb(cb); }\n"
    )
    assert _function_referenced_as_pointer(tmp_path, "cb") is True


def test_pointer_ref_negative_only_call_present(tmp_path):
    """If the only references are direct calls, the function is NOT
    "referenced as a pointer" — return False so dead-code can fire."""
    f = tmp_path / "use.c"
    f.write_text(
        "static int helper(int a) { return a; }\n"
        "int main(void) { return helper(1); }\n"
    )
    assert _function_referenced_as_pointer(tmp_path, "helper") is False


def test_pointer_ref_searches_recursively(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "def.c").write_text(
        "static int handler(int a) { return a; }\n"
    )
    (sub / "ops.c").write_text(
        "extern int handler(int);\n"
        "struct ops_t my_ops = { .handler = handler, };\n"
    )
    assert _function_referenced_as_pointer(tmp_path, "handler") is True


# =====================================================================
# _finding_in_dead_code — full composition
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip PR-4 prereqs E2E",
)
def test_dead_code_fires_on_static_unreferenced(tmp_path):
    """Static + zero callers + zero pointer-refs → dead-code."""
    f = tmp_path / "dead.c"
    f.write_text(
        "extern int strcpy(char *d, const char *s);\n"
        "static int unsafe_helper(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    return 0;\n"
        "}\n"
    )
    finding = _finding(str(f), 4, "cpp/unbounded-write")
    assert _finding_in_dead_code(finding, tmp_path) is True


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip PR-4 prereqs E2E",
)
def test_dead_code_skipped_for_non_static(tmp_path):
    """Non-static function must not be flagged dead even with zero
    callers in the target — caller may live in another TU."""
    f = tmp_path / "live.c"
    f.write_text(
        "extern int strcpy(char *d, const char *s);\n"
        "int public_fn(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    return 0;\n"
        "}\n"
    )
    finding = _finding(str(f), 4, "cpp/unbounded-write")
    assert _finding_in_dead_code(finding, tmp_path) is False


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip PR-4 prereqs E2E",
)
def test_dead_code_skipped_when_pointer_referenced(tmp_path):
    """Static, no calls, BUT registered as a vtable callback — NOT
    dead. This is the kernel struct ops shape (CVE-2017-7541)."""
    f = tmp_path / "ops.c"
    f.write_text(
        "extern int strcpy(char *d, const char *s);\n"
        "static int handler(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    return 0;\n"
        "}\n"
        "struct ops_t my_ops = { .handler = handler, };\n"
    )
    finding = _finding(str(f), 4, "cpp/unbounded-write")
    assert _finding_in_dead_code(finding, tmp_path) is False


# =====================================================================
# Verdict integration
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip PR-4 prereqs E2E",
)
def test_validator_verdict_dead_code_emits_not_exploitable(tmp_path):
    """Adapter integration: dead-code → NOT_EXPLOITABLE wins over
    other passes (it runs first)."""
    f = tmp_path / "dead.c"
    f.write_text(
        "extern int strcpy(char *d, const char *s);\n"
        "static int unsafe_helper(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    return 0;\n"
        "}\n"
    )
    finding = _finding(str(f), 4, "cpp/unbounded-write")
    v = SourceIntelValidator(repo_root=tmp_path)
    assert v.validate(finding) == ValidatorVerdict.NOT_EXPLOITABLE


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip PR-4 prereqs E2E",
)
def test_validator_verdict_skips_dead_code_for_non_static(tmp_path):
    """A non-static unsafe function with no observed calls in the
    fixture — verdict must NOT be NOT_EXPLOITABLE.

    Note: after axis-7 hazards shipped (deprecated functions
    including strcpy), the unbounded-strcpy in this fixture
    correctly fires axis-7 EXPLOITABLE. The original intent of
    the test (dead-code doesn't fire on non-static) is still
    enforced: any verdict OTHER than NOT_EXPLOITABLE confirms
    dead-code is skipped. The use of `do_copy` instead of
    `strcpy` would yield UNCERTAIN, but keeping `strcpy` is
    more representative of real kernel code.
    """
    f = tmp_path / "live.c"
    f.write_text(
        "extern int strcpy(char *d, const char *s);\n"
        "int public_fn(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    return 0;\n"
        "}\n"
    )
    finding = _finding(str(f), 4, "cpp/unbounded-write")
    v = SourceIntelValidator(repo_root=tmp_path)
    verdict = v.validate(finding)
    assert verdict != ValidatorVerdict.NOT_EXPLOITABLE, (
        f"dead-code MUST NOT fire on non-static fn; got {verdict}"
    )
