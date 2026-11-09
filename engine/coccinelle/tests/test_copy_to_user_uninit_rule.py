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


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_data_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = 'struct packet { int first; int second; };\n'
    source = prefix + 'void partial(void *user) { struct packet value; value.first = 1; copy_to_user(user, &value, sizeof(value)); }' + "\n"
    line = 1 + prefix.count("\n")
    if other_hit:
        source += 'void other(void *user) { struct packet value; copy_to_user(user, &value, sizeof(value)); }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert not result.errors, result.errors
    assert result.outcome == ("confirmed" if other_hit else "inconclusive")
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["line"] > line
        assert result.matches[0]["rule"] == 'copy_to_user_uninit'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=line, line_end=line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert not scoped.matches
    assert scoped.details["confirm_only"]
    assert len(result.matches) == int(other_hit)


def test_zero_byte_transfers_and_initializers_preserve_copy_extent(tmp_path):
    cases = []
    for length in ("0", "00", "0U", "0UL", "0x00", "0X00ULL", "0b00U", "((0))"):
        cases.append((f"copy_to_user(up, &out, {length});", False))
    for length in ("1", "0x1", "0x10", "0b10U", "1UL", "count", "0 + count"):
        cases.append((f"copy_to_user(up, &out, {length});", True))
    for operation, value in (("memset", "0"), ("memcpy", "source"), ("memmove", "source")):
        for length in ("0", "0UL", "0x00", "((0))"):
            cases.append((f"{operation}(&out, {value}, {length});\ncopy_to_user(up, &out, sizeof(out));", True))
        cases.append((f"{operation}(&out, {value}, sizeof(out));\ncopy_to_user(up, &out, sizeof(out));", False))
        cases.append((f"{operation}(&out, {value}, count);\ncopy_to_user(up, &out, sizeof(out));", False))
    # A no-op copy must not prevent the subsequent real copy being examined.
    cases.append(("copy_to_user(up, &out, 0);\ncopy_to_user(up, &out, sizeof(out));", True))
    # Position exclusions must not discard a real operation on the same line.
    cases += [
        ("copy_to_user(up, &out, 0); copy_to_user(up, &out, sizeof(out));", True),
        ("copy_to_user(up, &out, sizeof(out)); copy_to_user(up, &out, 0);", True),
        ("memset(&out, 0, 0); copy_to_user(up, &out, sizeof(out));", True),
        # An unknown helper can initialise even when one argument is zero.
        ("fill_first(&out, source, 0); copy_to_user(up, &out, sizeof(out));", False),
    ]
    lines = ["struct info { int first; int second; };"]
    expected = set()
    for index, (body, reports) in enumerate(cases):
        lines += [f"void transfer_{index}(void *up, void *source, unsigned long count) {{",
                  "struct info out;", *body.splitlines(), "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected), "each nonzero uninitialised copy should report once"
    assert all(row["rule"] == "copy_to_user_uninit" for row in rows)


def test_immediate_byte_array_decay_has_bounded_source_contract(tmp_path):
    cases = []
    for ctype in ("char", "signed char", "unsigned char"):
        for length in ("1", "16", "020", "0x10UL", "0b10000U"):
            cases.append((f"{ctype} out[{length}];\ncopy_to_user(up, out, sizeof(out));", True))
    cases += [
        ("unsigned char out[16];\nreturn copy_to_user(up, out, sizeof(out));", True),
        ("unsigned char out[16] = {0};\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16] = {[2] = 1};\ncopy_to_user(up, out, sizeof(out));", False),
        ("static unsigned char out[16];\ncopy_to_user(up, out, sizeof(out));", False),
        ("extern unsigned char out[16];\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16];\nmemset(out, 0, sizeof(out));\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16];\nunsigned char *alias = out; memset(alias, 0, 16);\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16];\nmemset(out, 0, sizeof(out)), copy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16];\ncopy_to_user(initialize(out), out, sizeof(out));", False),
        ("unsigned char out[16];\ncopy_to_user(out, out, sizeof(out));", False),
        ("unsigned char out[0];\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[count];\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16], *alias = memset(out, 0, sizeof(out));\ncopy_to_user(up, out, sizeof(out));", False),
        ("unsigned char out[16];\nreturn (memset(out, 0, sizeof(out)), copy_to_user(up, out, sizeof(out)));", False),
        ("unsigned char out[16];\nif (0) copy_to_user(up, out, sizeof(out));", False),
    ]
    # These unsupported flows can contain bugs; silence is not a safe verdict.
    cases += [
        ("unsigned char out[16];\ncopy_to_user(up, out, count);", False),
        ("int out[16];\ncopy_to_user(up, out, sizeof(out));", False),
    ]
    lines, expected = [], set()
    for index, (body, reports) in enumerate(cases):
        lines += [f"int array_copy_{index}(void *up, unsigned long count) {{", *body.splitlines(), "}"]
        if reports:
            expected.add(len(lines) - 1)
    # Array-spelled parameters describe caller-owned storage, not a new local.
    lines += ["void parameter(void *up, unsigned char out[16]) {", "copy_to_user(up, out, sizeof(out));", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected), "array/object matching must not duplicate a copy site"
    assert all(row["rule"] == "copy_to_user_uninit" for row in rows)


@pytest.mark.integration
def test_array_decay_receipt_is_detection_only_and_scopes_to_its_function(tmp_path):
    from core.analysis.coccinelle_metadata import curated_rule_role
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    source = (
        "void raw(void *up) { unsigned char out[16]; copy_to_user(up, out, sizeof(out)); }\n"
        "void initialized(void *up) { unsigned char out[16] = {0}; copy_to_user(up, out, sizeof(out)); }\n"
    )
    (tmp_path / "arrays.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="arrays.c", cocci_rule=str(_RULE), language="c",
    )
    assert not result.errors, result.errors
    assert result.outcome == "confirmed"
    assert len(result.matches) == 1
    assert result.matches[0]["rule"] == "copy_to_user_uninit"
    assert curated_rule_role(result.matches[0]["rule"], _RULE.parent) == "detection"
    raw = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="raw", line_start=1, line_end=1, language="c",
    )
    assert raw.outcome == "confirmed" and len(raw.matches) == 1
    initialized_line = 1 + source[:source.index("void initialized")].count("\n")
    initialized = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="initialized",
        line_start=initialized_line, line_end=initialized_line, language="c",
    )
    assert initialized.outcome == "inconclusive"
    assert not initialized.matches
    assert initialized.details["confirm_only"]
    assert len(result.matches) == 1


def test_sibling_initialisers_preserve_object_and_copy_identity(tmp_path):
    cases = [
        ("struct info out; copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, *alias = memset(&out, 0, sizeof(out)); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, other = fill(&out); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, other = make_info(); copy_to_user(up, &out, sizeof(out));", True),
        ("int out, other = (out = 0); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, other; copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, other = fill(&other); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, *alias = memcpy(&out, source, sizeof(out)); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, *alias = memmove(&out, source, sizeof(out)); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, *alias = memcpy(source, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, *alias = memmove(source, &out, sizeof(out)); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, other = (memcmp(&out, source, sizeof(out)), make_info()); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, *alias = memset(&out, 0, 0); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, *alias = memcpy(&out, source, 0); copy_to_user(up, &out, sizeof(out));", True),
        ("struct info out, other = fill((struct info *)&out); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, *alias = memset((void *)&out, 0, sizeof(out)); copy_to_user(up, &out, sizeof(out));", False),
        ("struct info out, other, third = fill(&out); copy_to_user(up, &out, sizeof(out));\ncopy_to_user(up, &other, sizeof(other));", True),
        ("struct info out, *alias = memset(&out, 0, sizeof(out));\nif (condition()) copy_to_user(up, &out, sizeof(out)); else copy_to_user(up, &out, sizeof(out));", False),
    ]
    lines = ["struct info { int value; };", "struct info make_info(void);", "struct info fill(struct info *);",
             "void *memset(void *, int, unsigned long);", "void *memcpy(void *, const void *, unsigned long);",
             "void *memmove(void *, const void *, unsigned long);"]
    expected = set()
    for index, (body, reports) in enumerate(cases):
        lines += [f"void sibling_{index}(void *up, void *source) {{", *body.splitlines(), "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)


@pytest.mark.integration
def test_sibling_initialiser_receipts_survive_confined_file_sweep(tmp_path):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = "struct info { int value; };\nstruct info make_info(void);\nvoid *memset(void *, int, unsigned long);\n"
    cleared = "void initialized(void *up) { struct info out, *alias = memset(&out, 0, sizeof(out)); copy_to_user(up, &out, sizeof(out)); }\n"
    raw = "void raw(void *up) { struct info out, other = make_info(); copy_to_user(up, &out, sizeof(out)); }\n"
    source = prefix + cleared + raw
    (tmp_path / "siblings.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="siblings.c", cocci_rule=str(_RULE), language="c",
    )
    assert not result.errors, result.errors
    assert result.outcome == "confirmed"
    assert len(result.matches) == 1
    raw_line = 1 + (prefix + cleared).count("\n")
    assert result.matches[0]["line"] == raw_line
    assert result.matches[0]["rule"] == "copy_to_user_uninit"
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="initialized",
        line_start=1 + prefix.count("\n"), line_end=1 + prefix.count("\n"), language="c",
    )
    assert scoped.outcome == "inconclusive" and not scoped.matches
    assert scoped.details["confirm_only"]
    raw_result = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="raw", line_start=raw_line, line_end=raw_line, language="c",
    )
    assert raw_result.outcome == "confirmed" and len(raw_result.matches) == 1
    assert len(result.matches) == 1


@pytest.mark.integration
def test_declaration_checks_remain_in_one_native_combined_process(tmp_path, monkeypatch):
    from dataclasses import asdict
    from packages.coccinelle import runner

    source = (
        "struct info { int value; };\nstruct info make_info(void);\n"
        "void *memset(void *, int, unsigned long);\n"
        "void initialized(void *up) { struct info out, *alias = memset(&out, 0, sizeof(out)); copy_to_user(up, &out, sizeof(out)); }\n"
        "void raw(void *up) { struct info out, other = make_info(); copy_to_user(up, &out, sizeof(out)); }\n"
        "void array(void *up) { unsigned char out[16]; copy_to_user(up, out, sizeof(out)); }\n"
        "void clear(char *secret, unsigned long n) { memset(secret, 0, n); free(secret); }\n"
    )
    target = tmp_path / "combined.c"
    target.write_text(source)
    rules = [_RULE, _RULE.with_name("dead_memset_free.cocci")]
    expected = {rule.stem: runner.run_rule(target, rule, no_includes=True, allow_scripting=True)
                for rule in rules}
    real = runner._sandboxed_run
    scan_texts = []

    def observed(command, **scope):
        if "--sp-file" in command:
            scan_texts.append(Path(command[command.index("--sp-file") + 1]).read_text())
        return real(command, **scope)

    monkeypatch.setattr(runner, "_sandboxed_run", observed)
    actual = runner.run_rules_batched(target, rules, no_includes=True, allow_scripting=True)
    assert len(scan_texts) == 1, "declaration checks must retain combined-process execution"
    assert all(f"begin {rule.stem}" in scan_texts[0] for rule in rules)
    assert set(actual) == {rule.stem for rule in rules}
    assert len(actual[_RULE.stem].matches) == 2
    assert len(actual["dead_memset_free"].matches) == 1
    for rule in rules:
        assert expected[rule.stem].ok, expected[rule.stem].errors
        assert actual[rule.stem].ok, actual[rule.stem].errors
        before, after = asdict(expected[rule.stem]), asdict(actual[rule.stem])
        before.pop("elapsed_ms")
        after.pop("elapsed_ms")
        for row in (before, after):
            row["matches"].sort(key=lambda item: (item["file"], item["line"], item["column"]))
        assert before == after


@pytest.mark.slow
@pytest.mark.integration
def test_repeated_sibling_declarations_fit_one_bounded_native_scan(tmp_path):
    from packages.coccinelle import runner

    lines = ["struct info { int value; };", "struct info make_info(void);", "void *memset(void *, int, unsigned long);"]
    expected = set()
    for index in range(400):
        declaration = ("struct info out, *alias = memset(&out, 0, sizeof(out));" if index % 2 == 0
                       else "struct info out, other = make_info();")
        lines += [f"void repeated_{index}(void *up) {{", declaration,
                  "copy_to_user(up, &out, sizeof(out));", "}"]
        if index % 2:
            expected.add(len(lines) - 1)
    target = tmp_path / "repeated.c"
    target.write_text("\n".join(lines) + "\n")
    # Matching declaration effects once avoids a native re-scan for each
    # copy candidate. Keep real parsing, confinement and the invocation cap.
    result = runner.run_rule(target, _RULE, no_includes=True, timeout=30, allow_scripting=True)
    assert result.ok, result.errors
    assert {match.line for match in result.matches} == expected
    assert len(result.matches) == len(expected)
