"""Tests for core.audit.dark_verify — witness-execution verification."""

from __future__ import annotations

import ast
import inspect
import json
import shutil
import sys
import textwrap

import pytest

from core.audit.dark_verify import _execute as ex
from core.audit.dark_verify._execute import (
    _run_native_binary,
    _run_script_witness,
    _sandboxed_compile,
    _toolchain_read_paths,
)
from core.audit.dark_verify import (
    DarkVerifyResult,
    DarkWitnessSpec,
    _classify_output,
    build_witness_prompt,
    execute_witness,
    file_to_import_path,
    generate_c_harness,
    generate_go_harness,
    generate_java_harness,
    generate_js_harness,
    generate_lua_harness,
    generate_perl_harness,
    generate_php_harness,
    generate_ruby_harness,
    generate_rust_harness,
    generate_ts_harness,
    generate_witness_script,
    language_for_file,
    parse_witness_response,
    validate_import_path,
    validate_spec,
)

# -- language_for_file --------------------------------------------------------


class TestLanguageForFile:
    def test_python(self):
        assert language_for_file("core/audit/gate.py") == "python"

    def test_c(self):
        assert language_for_file("src/main.c") == "c"

    def test_cpp(self):
        assert language_for_file("src/main.cpp") == "cpp"

    def test_go(self):
        assert language_for_file("cmd/server.go") == "go"

    def test_javascript(self):
        assert language_for_file("src/auth.js") == "javascript"

    def test_typescript(self):
        assert language_for_file("src/auth.ts") == "typescript"

    def test_lua(self):
        assert language_for_file("scripts/init.lua") == "lua"

    def test_perl(self):
        assert language_for_file("lib/Auth.pm") == "perl"

    def test_perl_script(self):
        assert language_for_file("scripts/check.pl") == "perl"

    def test_unknown(self):
        assert language_for_file("Makefile") is None

    def test_header(self):
        assert language_for_file("include/util.h") == "c"


# -- file_to_import_path -----------------------------------------------------


class TestFileToImportPath:
    def test_simple(self, tmp_path):
        assert file_to_import_path("core/audit/gate.py", tmp_path) == "core.audit.gate"

    def test_init_stripped(self, tmp_path):
        assert file_to_import_path("core/audit/__init__.py", tmp_path) == "core.audit"

    def test_non_python_returns_none(self, tmp_path):
        assert file_to_import_path("src/main.c", tmp_path) is None

    def test_top_level(self, tmp_path):
        assert file_to_import_path("setup.py", tmp_path) == "setup"


# -- validate_import_path ----------------------------------------------------


class TestValidateImportPath:
    def test_valid(self, tmp_path):
        src = tmp_path / "core" / "audit" / "gate.py"
        src.parent.mkdir(parents=True)
        src.write_text("def check(): pass\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="core/audit/gate.py",
            function="check", module_path="core.audit.gate",
        )
        assert validate_import_path(spec, tmp_path) is None

    def test_module_path_mismatch(self, tmp_path):
        src = tmp_path / "core" / "audit" / "gate.py"
        src.parent.mkdir(parents=True)
        src.write_text("def check(): pass\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="core/audit/gate.py",
            function="check", module_path="wrong.module",
        )
        err = validate_import_path(spec, tmp_path)
        assert err is not None
        assert "mismatch" in err

    def test_file_not_found(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="core/audit/missing.py",
            function="check", module_path="core.audit.missing",
        )
        err = validate_import_path(spec, tmp_path)
        assert err is not None
        assert "not found" in err

    def test_non_python(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/main.c",
            function="main", module_path="src.main",
        )
        err = validate_import_path(spec, tmp_path)
        assert err is not None
        assert "non-Python" in err


# -- generate_witness_script --------------------------------------------------


class TestGenerateWitnessScript:
    def test_script_has_import(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/mod.py",
            function="check", module_path="pkg.mod",
            args=[1, "hello"],
        )
        script = generate_witness_script(spec, tmp_path)
        assert "from pkg.mod import check" in script
        assert str(tmp_path.resolve()) in script

    def test_script_has_args(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/mod.py",
            function="check", module_path="pkg.mod",
            args=[42, True],
            kwargs={"key": "val"},
        )
        script = generate_witness_script(spec, tmp_path)
        assert "[42, true]" in script or "[42, True]" in script.replace("true", "True")
        assert "key" in script


# -- generate_c_harness -------------------------------------------------------


class TestGenerateCHarness:
    def test_basic_int_function(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/util.c", function="add",
            language="c",
            lang_config={
                "param_types": ["int", "int"],
                "return_type": "int",
                "arg_expressions": ["3", "4"],
                "includes": ["stdlib.h"],
                "setup_lines": [],
            },
        )
        harness = generate_c_harness(spec, tmp_path)
        assert "extern int add(int, int);" in harness
        assert "add(3, 4)" in harness
        assert "#include <stdlib.h>" in harness
        assert "int main(void)" in harness

    def test_void_function(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/init.c", function="init",
            language="c",
            lang_config={
                "param_types": [],
                "return_type": "void",
                "arg_expressions": [],
                "includes": [],
                "setup_lines": [],
            },
        )
        harness = generate_c_harness(spec, tmp_path)
        assert "init();" in harness
        assert "void" in harness

    def test_setup_lines(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/buf.c", function="copy_buf",
            language="c",
            lang_config={
                "param_types": ["char *", "int"],
                "return_type": "int",
                "arg_expressions": ["buf", "256"],
                "includes": ["string.h"],
                "setup_lines": ['char buf[10] = "AAAA";'],
            },
        )
        harness = generate_c_harness(spec, tmp_path)
        assert 'char buf[10] = "AAAA";' in harness
        assert "copy_buf(buf, 256)" in harness


# -- generate_go_harness ------------------------------------------------------


class TestGenerateGoHarness:
    def test_main_package_function(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="cmd/server.go", function="Validate",
            language="go",
            lang_config={
                "package": "main",
                "arg_expressions": ['"test"', "0"],
                "return_type": "bool",
            },
        )
        harness = generate_go_harness(spec, tmp_path)
        assert "package main" in harness
        assert "Validate" in harness
        assert "recover()" in harness

    def test_external_package(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/auth/check.go", function="Check",
            language="go",
            lang_config={
                "package": "auth",
                "import_path": "github.com/example/auth",
                "import_alias": "target",
                "arg_expressions": ["nil"],
                "return_type": "error",
            },
        )
        harness = generate_go_harness(spec, tmp_path)
        assert 'target "github.com/example/auth"' in harness
        assert "target.Check(nil)" in harness


# -- generate_js_harness ------------------------------------------------------


class TestGenerateJsHarness:
    def test_basic_require(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/auth.js", function="validate",
            language="javascript",
            args=["admin", ""],
            lang_config={"require_path": "./src/auth"},
        )
        harness = generate_js_harness(spec, tmp_path)
        assert "'use strict'" in harness
        assert "require" in harness
        assert "./src/auth" in harness
        assert "validate" in harness

    def test_auto_require_path(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/parser.js", function="parse",
            language="javascript",
            args=["<script>"],
            lang_config={},
        )
        harness = generate_js_harness(spec, tmp_path)
        assert "./lib/parser" in harness


# -- _classify_output ---------------------------------------------------------


class TestClassifyOutput:
    def test_returned_matches(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_return=42,
        )
        stdout = json.dumps({"status": "returned", "value": "42"})
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "confirmed"

    def test_returned_mismatch(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_return=42,
        )
        stdout = json.dumps({"status": "returned", "value": "99"})
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "refuted"

    def test_exception_matches(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_exception="ValueError",
        )
        stdout = json.dumps({
            "status": "exception", "type": "ValueError",
            "message": "bad input",
        })
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "confirmed"

    def test_exception_wrong_type(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_exception="ValueError",
        )
        stdout = json.dumps({
            "status": "exception", "type": "TypeError",
            "message": "wrong",
        })
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "refuted"

    def test_unexpected_exception_is_error_not_confirmed(self):
        """No stated exception expectation: an exception means the
        witness itself failed (bad args, wrong signature), never that
        the hypothesis is confirmed."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        stdout = json.dumps({
            "status": "exception", "type": "ZeroDivisionError",
            "message": "division by zero",
        })
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "error"
        assert "not accepted as confirmation" in r.match_detail

    def test_returned_match_with_crash_expectation_refutes(self):
        """A benign return match cannot confirm a spec whose stated
        expectation was a crash/sanitizer signal."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_return="42", expected_crash=True,
        )
        stdout = json.dumps({"status": "returned", "value": "42"})
        r = _classify_output(spec, stdout, "c")
        assert r.verdict == "refuted"

    def test_returned_match_with_sanitizer_expectation_refutes(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_return="42", expected_sanitizer="heap-buffer-overflow",
        )
        stdout = json.dumps({"status": "returned", "value": "42"})
        r = _classify_output(spec, stdout, "c")
        assert r.verdict == "refuted"

    def test_expected_exception_but_returned(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_exception="ValueError",
        )
        stdout = json.dumps({"status": "returned", "value": "None"})
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "refuted"

    def test_import_error(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        stdout = json.dumps({"status": "import_error", "message": "No module"})
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "error"

    def test_empty_output(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        r = _classify_output(spec, "", "python")
        assert r.verdict == "inconclusive"

    def test_unparseable_json(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        r = _classify_output(spec, "not json at all", "python")
        assert r.verdict == "inconclusive"

    def test_no_expected_return_is_inconclusive(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        stdout = json.dumps({"status": "returned", "value": "42"})
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "inconclusive"


# -- _classify_native_output --------------------------------------------------


def _native_proc(stdout="", returncode=0):
    import subprocess as sp
    return sp.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _native_spec(**kwargs):
    return DarkWitnessSpec(
        finding_key="f1", file="a.c", function="f", language="c", **kwargs,
    )


class TestClassifyNativeOutput:
    """The native oracle is bound to the witness's stated expectation —
    an arbitrary crash/sanitizer report never confirms an arbitrary
    hypothesis."""

    def test_sanitizer_matching_expected_type_confirms(self):
        spec = _native_spec(
            expected_crash=True, expected_sanitizer="heap-buffer-overflow",
        )
        info = {
            "sanitizer": "asan",
            "evidence": "AddressSanitizer: heap-buffer-overflow",
        }
        r = ex._classify_native_output(spec, _native_proc(returncode=1), info, "c")
        assert r.verdict == "confirmed"
        assert "heap-buffer-overflow" in r.match_detail

    def test_sanitizer_matching_family_confirms(self):
        spec = _native_spec(expected_crash=True, expected_sanitizer="asan")
        info = {"sanitizer": "asan", "evidence": "AddressSanitizer: unknown"}
        r = ex._classify_native_output(spec, _native_proc(returncode=1), info, "c")
        assert r.verdict == "confirmed"

    def test_sanitizer_mismatch_is_inconclusive(self):
        spec = _native_spec(
            expected_crash=True, expected_sanitizer="heap-buffer-overflow",
        )
        info = {
            "sanitizer": "ubsan",
            "evidence": "UndefinedBehaviorSanitizer triggered",
        }
        r = ex._classify_native_output(spec, _native_proc(returncode=1), info, "c")
        assert r.verdict == "inconclusive"
        assert "does not match" in r.match_detail

    def test_sanitizer_with_expected_crash_only_confirms(self):
        spec = _native_spec(expected_crash=True)
        info = {"sanitizer": "asan", "evidence": "AddressSanitizer: sega"}
        r = ex._classify_native_output(spec, _native_proc(returncode=1), info, "c")
        assert r.verdict == "confirmed"

    def test_unexpected_sanitizer_never_confirms(self):
        """expected_crash=False: a sanitizer report is NOT confirmation."""
        spec = _native_spec(expected_return="7")
        info = {"sanitizer": "asan", "evidence": "AddressSanitizer: sega"}
        r = ex._classify_native_output(spec, _native_proc(returncode=1), info, "c")
        assert r.verdict == "inconclusive"

    def test_expected_crash_signal_confirms(self):
        spec = _native_spec(expected_crash=True)
        info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
        r = ex._classify_native_output(spec, _native_proc(returncode=-11), info, "c")
        assert r.verdict == "confirmed"
        assert "SIGSEGV" in r.actual_exception

    def test_unexpected_crash_never_confirms(self):
        """expected_crash=False: a crash proves the witness wrong, not
        the hypothesis right."""
        spec = _native_spec(expected_return="7")
        info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
        r = ex._classify_native_output(spec, _native_proc(returncode=-11), info, "c")
        assert r.verdict == "inconclusive"
        assert "not accepted as confirmation" in r.match_detail

    def test_resource_kill_never_confirms(self):
        spec = _native_spec(expected_crash=True)
        info = {"signal": "SIGXCPU", "resource_exceeded": True}
        r = ex._classify_native_output(spec, _native_proc(returncode=-24), info, "c")
        assert r.verdict == "inconclusive"

    def test_seccomp_kill_never_confirms(self):
        spec = _native_spec(expected_crash=True)
        info = {"signal": "SIGSYS", "seccomp_killed": True}
        r = ex._classify_native_output(spec, _native_proc(returncode=-31), info, "c")
        assert r.verdict == "inconclusive"

    def test_expected_crash_normal_exit_refutes(self):
        spec = _native_spec(expected_crash=True)
        r = ex._classify_native_output(spec, _native_proc(stdout="{}"), None, "c")
        assert r.verdict == "refuted"


# -- validate_spec -----------------------------------------------------------


class TestValidateSpec:
    def test_valid_spec_passes(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/main.c", function="parse_input",
            language="c",
            lang_config={
                "arg_expressions": ["buf", "len"],
                "return_type": "int",
            },
        )
        assert validate_spec(spec) is None

    def test_function_name_must_be_identifier(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="system('evil')",
            language="python",
        )
        err = validate_spec(spec)
        assert err is not None
        assert "invalid function name" in err

    def test_function_with_semicolon_rejected(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="foo;bar",
            language="c",
        )
        assert validate_spec(spec) is not None

    def test_dangerous_builtin_ruby(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="system",
            language="ruby",
        )
        err = validate_spec(spec)
        assert err is not None
        assert "dangerous builtin" in err

    def test_dangerous_builtin_php(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.php", function="exec",
            language="php",
        )
        err = validate_spec(spec)
        assert err is not None
        assert "dangerous builtin" in err

    def test_dangerous_builtin_perl(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.pl", function="eval",
            language="perl",
        )
        assert validate_spec(spec) is not None

    def test_safe_function_ruby_passes(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="calculate_sum",
            language="ruby",
        )
        assert validate_spec(spec) is None

    def test_dangerous_builtin_not_blocked_for_c(self):
        """C's system() is declared extern — the compiler rejects if not linked."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="system",
            language="c",
        )
        assert validate_spec(spec) is None

    def test_arg_expression_semicolon_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="parse",
            language="c",
            lang_config={
                "arg_expressions": ['0); system("rm -rf /")'],
                "return_type": "int",
            },
        )
        err = validate_spec(spec)
        assert err is not None
        assert "code injection" in err

    def test_arg_expression_backtick_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="parse",
            language="c",
            lang_config={"arg_expressions": ["`whoami`"]},
        )
        assert validate_spec(spec) is not None

    def test_arg_expression_subprocess_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.java", function="parse",
            language="java",
            lang_config={
                "arg_expressions": ['Runtime.getRuntime().exec("evil")'],
                "return_type": "String",
            },
        )
        assert validate_spec(spec) is not None

    def test_safe_arg_expressions_pass(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="add",
            language="c",
            lang_config={
                "arg_expressions": ["42", "buf"],
                "return_type": "int",
            },
        )
        assert validate_spec(spec) is None

    def test_return_type_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="foo",
            language="c",
            lang_config={"return_type": 'int; system("evil"); int'},
        )
        err = validate_spec(spec)
        assert err is not None
        assert "return_type" in err

    def test_valid_complex_return_type(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="foo",
            language="c",
            lang_config={"return_type": "const char*"},
        )
        assert validate_spec(spec) is None

    def test_class_name_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="A.java", function="run",
            language="java",
            lang_config={
                "class_name": 'Foo; Runtime.getRuntime().exec("evil")',
                "return_type": "void",
            },
        )
        assert validate_spec(spec) is not None

    def test_use_path_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rs", function="run",
            language="rust",
            lang_config={
                "use_path": 'std::process::Command; fn evil()',
                "return_type": "i32",
            },
        )
        assert validate_spec(spec) is not None

    def test_valid_use_path(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rs", function="run",
            language="rust",
            lang_config={
                "use_path": "std::collections::HashMap",
                "return_type": "i32",
            },
        )
        assert validate_spec(spec) is None

    def test_use_module_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.pl", function="run",
            language="perl",
            lang_config={"use_module": 'POSIX; system("evil")'},
        )
        assert validate_spec(spec) is not None

    def test_import_path_injection(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.go", function="Run",
            language="go",
            lang_config={
                "package": "pkg",
                "import_path": 'os/exec"; import "unsafe',
                "return_type": "int",
            },
        )
        assert validate_spec(spec) is not None

    def test_valid_import_path(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.go", function="Run",
            language="go",
            lang_config={
                "package": "pkg",
                "import_path": "github.com/user/repo/pkg",
                "return_type": "int",
            },
        )
        assert validate_spec(spec) is None

    def test_execute_witness_rejects_bad_spec(self, tmp_path):
        src = tmp_path / "a.rb"
        src.write_text("def system(x); end\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="system",
            language="ruby",
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "spec validation failed" in r.match_detail


# -- execute_witness ----------------------------------------------------------


class TestExecuteWitness:
    def test_validation_failure_returns_error(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="missing.py",
            function="check", module_path="missing",
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "not found" in r.match_detail

    def test_unsupported_language(self, tmp_path):
        src = tmp_path / "main.malbolge"
        src.write_text("(=<`#9]~6ZY327Uv4-QssNJhih", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.malbolge",
            function="main", language="malbolge",
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "unsupported" in r.match_detail

    def test_real_execution_confirms(self, tmp_path):
        mod = tmp_path / "pkg" / "demo.py"
        mod.parent.mkdir(parents=True)
        mod.write_text(textwrap.dedent("""\
            def divide(a, b):
                return a / b
        """), encoding="utf-8")
        (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/demo.py",
            function="divide", module_path="pkg.demo",
            args=[1, 0],
            expected_exception="ZeroDivisionError",
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"

    def test_real_execution_refutes(self, tmp_path):
        mod = tmp_path / "pkg" / "demo.py"
        mod.parent.mkdir(parents=True)
        mod.write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b
        """), encoding="utf-8")
        (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/demo.py",
            function="add", module_path="pkg.demo",
            args=[1, 2],
            expected_return=99,
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "refuted"
        assert "3" in r.actual_return

    def test_language_auto_detected(self, tmp_path):
        mod = tmp_path / "lib" / "calc.py"
        mod.parent.mkdir(parents=True)
        mod.write_text("def double(x): return x * 2\n", encoding="utf-8")
        (tmp_path / "lib" / "__init__.py").write_text("", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/calc.py",
            function="double", module_path="lib.calc",
            args=[5], expected_return=10,
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "python"


# -- execute_witness (C) ------------------------------------------------------


class TestExecuteWitnessC:
    def test_c_compiler_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "bug.c"
        src.write_text("int bug(int x) { return x; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="bug.c", function="bug",
            language="c",
            lang_config={
                "param_types": ["int"], "return_type": "int",
                "arg_expressions": ["42"], "includes": [], "setup_lines": [],
            },
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "compiler not found" in r.match_detail

    def test_c_unsafe_setup_rejected(self, tmp_path):
        src = tmp_path / "exploit.c"
        src.write_text("int exploit(void) { return 0; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="exploit.c", function="exploit",
            language="c",
            lang_config={
                "param_types": [], "return_type": "int",
                "arg_expressions": [],
                "includes": [],
                "setup_lines": ['system("rm -rf /");'],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "unsafe" in r.match_detail


# -- generate_ts_harness -------------------------------------------------------


class TestGenerateTsHarness:
    def test_basic_ts(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/auth.ts", function="validate",
            language="typescript",
            args=["admin"],
            lang_config={"require_path": "./src/auth"},
        )
        harness = generate_ts_harness(spec, tmp_path)
        assert "import * as path" in harness
        assert "./src/auth" in harness
        assert "validate" in harness

    def test_auto_require_path(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/parser.ts", function="parse",
            language="typescript",
            args=[],
            lang_config={},
        )
        harness = generate_ts_harness(spec, tmp_path)
        assert "./lib/parser" in harness


# -- generate_ruby_harness ----------------------------------------------------


class TestGenerateRubyHarness:
    def test_basic_ruby(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="validate",
            language="ruby",
            args=["admin", None],
            lang_config={"require_path": "lib/auth"},
        )
        harness = generate_ruby_harness(spec, tmp_path)
        assert "require 'json'" in harness
        assert '"lib/auth"' in harness
        assert "validate" in harness
        assert "nil" in harness

    def test_auto_require_path(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/parser.rb", function="parse",
            language="ruby",
            args=["test"],
            lang_config={},
        )
        harness = generate_ruby_harness(spec, tmp_path)
        assert "lib/parser" in harness


# -- generate_php_harness -----------------------------------------------------


class TestGeneratePhpHarness:
    def test_basic_php(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/auth.php", function="validate",
            language="php",
            args=["admin", ""],
            lang_config={"require_path": "src/auth.php"},
        )
        harness = generate_php_harness(spec, tmp_path)
        assert "<?php" in harness
        assert "require_once" in harness
        assert "validate" in harness
        assert "json_encode" in harness


# -- generate_rust_harness ----------------------------------------------------


class TestGenerateRustHarness:
    def test_basic_rust(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/lib.rs", function="process",
            language="rust",
            lang_config={
                "arg_expressions": ['"test".to_string()', "0usize"],
                "return_type": "i32",
                "use_path": "",
                "setup_lines": [],
            },
        )
        harness = generate_rust_harness(spec, tmp_path)
        assert "fn main()" in harness
        assert "process" in harness
        assert "let result" in harness

    def test_void_return(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/lib.rs", function="init",
            language="rust",
            lang_config={
                "arg_expressions": [],
                "return_type": "()",
                "use_path": "",
                "setup_lines": [],
            },
        )
        harness = generate_rust_harness(spec, tmp_path)
        assert "init();" in harness
        assert "void" in harness

    def test_single_crate_root_include(self, tmp_path):
        """The harness must splice the target in via include! — rustc
        accepts exactly one crate root, so the executor compiles only the
        harness and copies the target next to it as target_source.rs."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/lib.rs", function="process",
            language="rust",
            lang_config={
                "arg_expressions": ["42"],
                "return_type": "i32",
                "use_path": "",
                "setup_lines": [],
            },
        )
        harness = generate_rust_harness(spec, tmp_path)
        assert 'include!("target_source.rs");' in harness
        # include! must precede fn main so items land at the crate root.
        assert harness.index("include!") < harness.index("fn main()")

    def test_println_template_is_single_string(self, tmp_path):
        """Regression: the JSON println! template contained a stray quote
        that terminated the Rust string literal mid-way, so no generated
        harness ever compiled."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/lib.rs", function="process",
            language="rust",
            lang_config={
                "arg_expressions": ["42"],
                "return_type": "i32",
                "use_path": "",
                "setup_lines": [],
            },
        )
        harness = generate_rust_harness(spec, tmp_path)
        assert (
            'println!("{{\\"status\\":\\"returned\\",'
            '\\"value\\":\\"{:?}\\"}}", result);'
        ) in harness


# -- generate_java_harness ----------------------------------------------------


class TestGenerateJavaHarness:
    def test_static_method(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/AuthUtils.java", function="validate",
            language="java",
            lang_config={
                "class_name": "AuthUtils",
                "imports": ["java.util.HashMap"],
                "arg_expressions": ["null", '"admin"'],
                "return_type": "boolean",
                "is_static": True,
            },
        )
        harness = generate_java_harness(spec, tmp_path)
        assert "import java.util.HashMap" in harness
        assert "AuthUtils.validate" in harness
        assert "DarkWitnessHarness" in harness

    def test_instance_method(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/Parser.java", function="parse",
            language="java",
            lang_config={
                "class_name": "Parser",
                "imports": [],
                "arg_expressions": ['"<script>"'],
                "return_type": "String",
                "is_static": False,
            },
        )
        harness = generate_java_harness(spec, tmp_path)
        assert "new Parser()" in harness
        assert "instance.parse" in harness


# -- execute_witness (JS) -----------------------------------------------------


class TestExecuteWitnessJs:
    def test_js_node_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "auth.js"
        src.write_text("module.exports.check = (x) => x;\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="auth.js", function="check",
            language="javascript",
            args=["test"],
            lang_config={"require_path": "./auth"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "node not found" in r.match_detail


# -- execute_witness (Go) -----------------------------------------------------


class TestExecuteWitnessGo:
    def test_go_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "main.go"
        src.write_text("package main\nfunc main() {}\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.go", function="main",
            language="go",
            lang_config={"package": "main", "arg_expressions": [], "return_type": ""},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "go compiler not found" in r.match_detail


# -- generate_lua_harness ------------------------------------------------------


class TestGenerateLuaHarness:
    def test_basic_lua(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="validate",
            language="lua",
            args=["admin", None],
            lang_config={"require_path": "lib.auth"},
        )
        harness = generate_lua_harness(spec, tmp_path)
        assert "require" in harness
        assert "lib.auth" in harness
        assert "validate" in harness
        assert "pcall" in harness

    def test_auto_require_path(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="scripts/parser.lua", function="parse",
            language="lua",
            args=["test"],
            lang_config={},
        )
        harness = generate_lua_harness(spec, tmp_path)
        assert "scripts.parser" in harness


# -- generate_perl_harness -----------------------------------------------------


class TestGeneratePerlHarness:
    def test_basic_perl(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/Auth.pm", function="validate",
            language="perl",
            args=["admin", None],
            lang_config={"use_module": "Auth"},
        )
        harness = generate_perl_harness(spec, tmp_path)
        assert "use strict" in harness
        assert "require Auth" in harness
        assert "validate" in harness
        assert "JSON::PP" in harness


# -- execute_witness (TypeScript) ----------------------------------------------


class TestExecuteWitnessTs:
    def test_ts_runner_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "auth.ts"
        src.write_text("export function check(x: string) { return x; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="auth.ts", function="check",
            language="typescript",
            args=["test"],
            lang_config={"require_path": "./auth"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "tsx" in r.match_detail or "ts-node" in r.match_detail


# -- execute_witness (Ruby) ---------------------------------------------------


class TestExecuteWitnessRuby:
    def test_ruby_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "auth.rb"
        src.write_text("def check(x); x; end\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="auth.rb", function="check",
            language="ruby",
            args=["test"],
            lang_config={"require_path": "auth"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "ruby not found" in r.match_detail


# -- execute_witness (PHP) ----------------------------------------------------


class TestExecuteWitnessPhp:
    def test_php_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "auth.php"
        src.write_text("<?php function check($x) { return $x; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="auth.php", function="check",
            language="php",
            args=["test"],
            lang_config={"require_path": "auth.php"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "php not found" in r.match_detail


# -- execute_witness (Rust) ---------------------------------------------------


class TestExecuteWitnessRust:
    def test_rustc_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "lib.rs"
        src.write_text("pub fn check(x: i32) -> i32 { x }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib.rs", function="check",
            language="rust",
            lang_config={
                "arg_expressions": ["42"],
                "return_type": "i32",
                "use_path": "",
                "setup_lines": [],
            },
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "rustc not found" in r.match_detail


# -- execute_witness (Java) ---------------------------------------------------


class TestExecuteWitnessJava:
    def test_javac_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "Auth.java"
        src.write_text("public class Auth { static boolean check(String x) { return true; } }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="Auth.java", function="check",
            language="java",
            lang_config={
                "class_name": "Auth",
                "imports": [],
                "arg_expressions": ['"test"'],
                "return_type": "boolean",
                "is_static": True,
            },
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "javac" in r.match_detail


# -- execute_witness (Lua) ----------------------------------------------------


class TestExecuteWitnessLua:
    def test_lua_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "auth.lua"
        src.write_text("local M = {} function M.check(x) return x end return M\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="auth.lua", function="check",
            language="lua",
            args=["test"],
            lang_config={"require_path": "auth"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "lua not found" in r.match_detail


# -- execute_witness (Perl) ---------------------------------------------------


class TestExecuteWitnessPerl:
    def test_perl_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "Auth.pm"
        src.write_text("package Auth; sub check { return 1; } 1;\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="Auth.pm", function="check",
            language="perl",
            args=["test"],
            lang_config={"use_module": "Auth"},
        )
        import shutil
        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "perl not found" in r.match_detail


# -- build_witness_prompt -----------------------------------------------------


class TestBuildWitnessPrompt:
    # build_witness_prompt returns the enveloped (user, system) pair:
    # finding identifiers land in the user message as slots, the
    # hypothesis/detail in untrusted blocks, and the per-language task
    # text in the system prompt.
    def test_includes_finding_details(self):
        user, system = build_witness_prompt(
            file="core/audit/gate.py",
            function="check_bounds",
            hypothesis="off-by-one",
            body="The function does not check upper bound",
        )
        assert "core/audit/gate.py" in user
        assert "check_bounds" in user
        assert "off-by-one" in user
        assert "## Task" in system

    def test_missing_hypothesis(self):
        user, _system = build_witness_prompt("a.py", "f", "", "detail")
        assert "(no hypothesis)" in user

    def test_c_prompt_has_sanitizer(self):
        user, system = build_witness_prompt(
            file="src/buf.c",
            function="copy_buf",
            hypothesis="heap overflow",
            body="No bounds check",
            language="c",
        )
        assert "sanitize" in system.lower() or "ASan" in system
        assert "copy_buf" in user

    def test_go_prompt_has_panic(self):
        user, system = build_witness_prompt(
            file="pkg/auth.go",
            function="Check",
            hypothesis="nil deref",
            body="No nil check",
            language="go",
        )
        assert "panic" in system.lower()
        assert "Check" in user

    def test_js_prompt_has_require(self):
        user, system = build_witness_prompt(
            file="src/auth.js",
            function="validate",
            hypothesis="prototype pollution",
            body="Object.assign without filter",
            language="javascript",
        )
        assert "require" in system.lower()
        assert "validate" in user

    def test_ts_prompt(self):
        user, system = build_witness_prompt(
            file="src/auth.ts", function="validate",
            hypothesis="type confusion", body="Any cast",
            language="typescript",
        )
        assert "TypeScript" in system
        assert "validate" in user

    def test_ruby_prompt(self):
        user, system = build_witness_prompt(
            file="lib/auth.rb", function="check",
            hypothesis="injection", body="No sanitization",
            language="ruby",
        )
        assert "Ruby" in system
        assert "check" in user

    def test_php_prompt(self):
        user, system = build_witness_prompt(
            file="src/auth.php", function="validate",
            hypothesis="sqli", body="No prepared statement",
            language="php",
        )
        assert "PHP" in system
        assert "validate" in user

    def test_rust_prompt(self):
        user, system = build_witness_prompt(
            file="src/lib.rs", function="process",
            hypothesis="buffer overflow", body="Unsafe block",
            language="rust",
        )
        assert "Rust" in system
        assert "process" in user

    def test_java_prompt(self):
        user, system = build_witness_prompt(
            file="src/Auth.java", function="validate",
            hypothesis="null deref", body="No null check",
            language="java",
        )
        assert "Java" in system
        assert "validate" in user

    def test_lua_prompt(self):
        user, system = build_witness_prompt(
            file="lib/auth.lua", function="validate",
            hypothesis="injection", body="No sanitization",
            language="lua",
        )
        assert "Lua" in system
        assert "validate" in user

    def test_perl_prompt(self):
        user, system = build_witness_prompt(
            file="lib/Auth.pm", function="check",
            hypothesis="injection", body="No taint check",
            language="perl",
        )
        assert "Perl" in system
        assert "check" in user


# -- parse_witness_response ---------------------------------------------------


class TestParseWitnessResponse:
    def test_plain_json(self):
        resp = json.dumps({
            "module_path": "core.audit.gate",
            "function": "check",
            "args": [1, 2],
            "kwargs": {},
            "expected_return": True,
            "expected_exception": "",
            "rationale": "test",
        })
        spec = parse_witness_response(resp, "f1", "core/audit/gate.py", "check")
        assert spec is not None
        assert spec.module_path == "core.audit.gate"
        assert spec.args == [1, 2]
        assert spec.expected_return is True
        assert spec.language == "python"

    def test_markdown_fenced(self):
        resp = "```json\n" + json.dumps({
            "module_path": "a.b",
            "function": "f",
            "args": [],
        }) + "\n```"
        spec = parse_witness_response(resp, "f1", "a/b.py", "f")
        assert spec is not None
        assert spec.module_path == "a.b"

    def test_garbage_returns_none(self):
        spec = parse_witness_response("not json", "f1", "a.py", "f")
        assert spec is None

    def test_missing_module_path_returns_none(self):
        resp = json.dumps({"function": "f", "args": []})
        spec = parse_witness_response(resp, "f1", "a.py", "f")
        assert spec is None

    def test_json_with_leading_text(self):
        resp = 'Here is the witness:\n{"module_path": "x.y", "function": "g", "args": [1]}'
        spec = parse_witness_response(resp, "f1", "x/y.py", "g")
        assert spec is not None
        assert spec.function == "g"

    def test_c_response(self):
        resp = json.dumps({
            "function": "overflow",
            "arg_expressions": ["buf", "256"],
            "param_types": ["char *", "int"],
            "return_type": "int",
            "includes": ["string.h"],
            "setup_lines": ['char buf[10] = "AAAA";'],
            "expected_crash": True,
            "expected_sanitizer": "heap-buffer-overflow",
            "rationale": "overflow",
        })
        spec = parse_witness_response(resp, "f1", "src/buf.c", "overflow", language="c")
        assert spec is not None
        assert spec.language == "c"
        assert spec.expected_crash is True
        assert spec.expected_sanitizer == "heap-buffer-overflow"
        assert spec.lang_config["param_types"] == ["char *", "int"]

    def test_go_response(self):
        resp = json.dumps({
            "function": "Check",
            "package": "auth",
            "import_path": "github.com/example/auth",
            "arg_expressions": ["nil"],
            "return_type": "error",
            "expected_return": None,
            "expected_exception": "panic",
            "rationale": "nil deref",
        })
        spec = parse_witness_response(resp, "f1", "pkg/auth.go", "Check", language="go")
        assert spec is not None
        assert spec.language == "go"
        assert spec.expected_exception == "panic"
        assert spec.lang_config["package"] == "auth"

    def test_js_response(self):
        resp = json.dumps({
            "function": "validate",
            "require_path": "./src/auth",
            "args": ["admin", ""],
            "expected_exception": "TypeError",
            "rationale": "empty password",
        })
        spec = parse_witness_response(
            resp, "f1", "src/auth.js", "validate", language="javascript",
        )
        assert spec is not None
        assert spec.language == "javascript"
        assert spec.expected_exception == "TypeError"
        assert spec.lang_config["require_path"] == "./src/auth"

    def test_ts_response(self):
        resp = json.dumps({
            "function": "validate",
            "require_path": "./src/auth",
            "args": ["admin"],
            "expected_exception": "TypeError",
            "rationale": "type confusion",
        })
        spec = parse_witness_response(
            resp, "f1", "src/auth.ts", "validate", language="typescript",
        )
        assert spec is not None
        assert spec.language == "typescript"
        assert spec.lang_config["require_path"] == "./src/auth"

    def test_ruby_response(self):
        resp = json.dumps({
            "function": "check",
            "require_path": "lib/auth",
            "args": [None],
            "expected_exception": "NoMethodError",
            "rationale": "nil deref",
        })
        spec = parse_witness_response(
            resp, "f1", "lib/auth.rb", "check", language="ruby",
        )
        assert spec is not None
        assert spec.language == "ruby"
        assert spec.expected_exception == "NoMethodError"

    def test_php_response(self):
        resp = json.dumps({
            "function": "validate",
            "require_path": "src/auth.php",
            "args": ["' OR 1=1 --"],
            "expected_return": True,
            "rationale": "sqli",
        })
        spec = parse_witness_response(
            resp, "f1", "src/auth.php", "validate", language="php",
        )
        assert spec is not None
        assert spec.language == "php"
        assert spec.expected_return is True

    def test_rust_response(self):
        resp = json.dumps({
            "function": "process",
            "use_path": "target::auth",
            "arg_expressions": ['"test".to_string()'],
            "return_type": "i32",
            "setup_lines": [],
            "expected_crash": True,
            "expected_sanitizer": "",
            "rationale": "overflow",
        })
        spec = parse_witness_response(
            resp, "f1", "src/lib.rs", "process", language="rust",
        )
        assert spec is not None
        assert spec.language == "rust"
        assert spec.expected_crash is True
        assert spec.lang_config["use_path"] == "target::auth"

    def test_java_response(self):
        resp = json.dumps({
            "function": "validate",
            "class_name": "AuthUtils",
            "imports": ["java.util.HashMap"],
            "arg_expressions": ["null"],
            "return_type": "boolean",
            "is_static": True,
            "expected_exception": "NullPointerException",
            "rationale": "null deref",
        })
        spec = parse_witness_response(
            resp, "f1", "src/AuthUtils.java", "validate", language="java",
        )
        assert spec is not None
        assert spec.language == "java"
        assert spec.expected_exception == "NullPointerException"
        assert spec.lang_config["class_name"] == "AuthUtils"
        assert spec.lang_config["is_static"] is True

    def test_lua_response(self):
        resp = json.dumps({
            "function": "validate",
            "require_path": "lib.auth",
            "args": [None],
            "expected_exception": "attempt to index a nil value",
            "rationale": "nil deref",
        })
        spec = parse_witness_response(
            resp, "f1", "lib/auth.lua", "validate", language="lua",
        )
        assert spec is not None
        assert spec.language == "lua"
        assert spec.lang_config["require_path"] == "lib.auth"

    def test_perl_response(self):
        resp = json.dumps({
            "function": "check",
            "use_module": "Auth",
            "args": [None],
            "expected_exception": "die",
            "rationale": "undef deref",
        })
        spec = parse_witness_response(
            resp, "f1", "lib/Auth.pm", "check", language="perl",
        )
        assert spec is not None
        assert spec.language == "perl"
        assert spec.lang_config["use_module"] == "Auth"
        assert spec.expected_exception == "die"


# -- DarkWitnessSpec.to_dict / DarkVerifyResult.to_dict -----------------------


class TestToDict:
    def test_spec_round_trip_keys(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", args=[1], expected_return=42,
        )
        d = spec.to_dict()
        assert d["finding_key"] == "f1"
        assert d["args"] == [1]
        assert d["expected_return"] == 42
        assert d["language"] == ""

    def test_result_round_trip_keys(self):
        r = DarkVerifyResult(
            finding_key="f1", verdict="confirmed",
            actual_return="42", match_detail="matches",
        )
        d = r.to_dict()
        assert d["verdict"] == "confirmed"
        assert d["oracle_reliability"] == "decisive"

    def test_spec_with_lang_config(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/buf.c", function="overflow",
            language="c",
            expected_crash=True,
            lang_config={"param_types": ["int"], "return_type": "int"},
        )
        d = spec.to_dict()
        assert d["language"] == "c"
        assert d["expected_crash"] is True
        assert d["lang_config"]["param_types"] == ["int"]


# ============================================================================
# Real execution tests per language — skip when runtime unavailable
# ============================================================================


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("cc"), reason="C compiler not available")
class TestRealExecutionC:
    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "math_util.c"
        src.write_text("int double_it(int x) { return x * 2; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="math_util.c", function="double_it",
            language="c",
            expected_return="84",
            lang_config={
                "param_types": ["int"], "return_type": "int",
                "arg_expressions": ["42"], "includes": [], "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "c"

    def test_refutes_wrong_prediction(self, tmp_path):
        src = tmp_path / "add.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="add.c", function="add",
            language="c",
            expected_return="999",
            lang_config={
                "param_types": ["int", "int"], "return_type": "int",
                "arg_expressions": ["3", "4"], "includes": [], "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "refuted"
        assert "7" in r.actual_return


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("go"), reason="Go not available")
class TestRealExecutionGo:
    def test_confirms_panic(self, tmp_path):
        src = tmp_path / "main.go"
        src.write_text(textwrap.dedent("""\
            package main

            func IndexPanic(xs []int) int {
                return xs[0]
            }
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.go", function="IndexPanic",
            language="go",
            expected_exception="panic",
            lang_config={
                "package": "main",
                "arg_expressions": ["nil"],
                "return_type": "int",
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "go"

    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "main.go"
        src.write_text(textwrap.dedent("""\
            package main

            func Add(a, b int) int {
                return a + b
            }
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.go", function="Add",
            language="go",
            expected_return="7",
            lang_config={
                "package": "main",
                "arg_expressions": ["3", "4"],
                "return_type": "int",
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
class TestRealExecutionRust:
    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "lib.rs"
        src.write_text(
            "pub fn double_it(x: i32) -> i32 { x * 2 }\n", encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib.rs", function="double_it",
            language="rust",
            expected_return="84",
            lang_config={
                "arg_expressions": ["42"], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "rust"

    def test_refutes_wrong_prediction(self, tmp_path):
        src = tmp_path / "add.rs"
        src.write_text(
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n", encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="add.rs", function="add",
            language="rust",
            expected_return="999",
            lang_config={
                "arg_expressions": ["3", "4"], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "refuted"
        assert "7" in r.actual_return

    def test_confirms_panic_as_crash(self, tmp_path):
        """-C panic=abort turns a panic into a fatal signal so the shared
        signal classifier confirms it (unwind would exit 101 = normal
        exit). WHICH signal is host-dependent: normally SIGABRT, but the
        witness runs as pid 1 of the sandbox's pid namespace, where the
        default SIGABRT action is ignored and glibc's abort() escalates
        to a trap — observed as SIGSEGV — on mount-ns hosts. The pin is
        that the panic surfaces as a crash SIGNAL, not a clean exit."""
        src = tmp_path / "oob.rs"
        src.write_text(
            "pub fn idx(v: &[i32]) -> i32 { v[10] }\n", encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="oob.rs", function="idx",
            language="rust",
            expected_crash=True,
            lang_config={
                "arg_expressions": ["&[1, 2]"], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.actual_exception.startswith("signal: SIG")

    def test_target_with_own_main(self, tmp_path):
        """A bin-crate target's fn main is renamed before the include!
        splice so it cannot collide with the harness main."""
        src = tmp_path / "main.rs"
        src.write_text(
            'fn main() { println!("app"); }\n'
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
            encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.rs", function="add",
            language="rust",
            expected_return="7",
            lang_config={
                "arg_expressions": ["3", "4"], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not available")
class TestRealExecutionJs:
    def test_confirms_exception(self, tmp_path):
        src = tmp_path / "parser.js"
        src.write_text(textwrap.dedent("""\
            function parseJSON(s) {
                return JSON.parse(s);
            }
            module.exports = { parseJSON };
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="parser.js", function="parseJSON",
            language="javascript",
            args=["not valid json"],
            expected_exception="SyntaxError",
            lang_config={"require_path": "./parser"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "javascript"

    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "math.js"
        src.write_text(textwrap.dedent("""\
            function triple(x) { return x * 3; }
            module.exports = { triple };
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="math.js", function="triple",
            language="javascript",
            args=[5],
            expected_return="15",
            lang_config={"require_path": "./math"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"

    def test_refutes_wrong_exception(self, tmp_path):
        src = tmp_path / "safe.js"
        src.write_text(textwrap.dedent("""\
            function safe(x) { return x + 1; }
            module.exports = { safe };
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="safe.js", function="safe",
            language="javascript",
            args=[10],
            expected_exception="TypeError",
            lang_config={"require_path": "./safe"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "refuted"


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("ruby"), reason="Ruby not available")
class TestRealExecutionRuby:
    def test_confirms_exception(self, tmp_path):
        src = tmp_path / "math.rb"
        src.write_text(textwrap.dedent("""\
            def divide(a, b)
              a / b
            end
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="math.rb", function="divide",
            language="ruby",
            args=[1, 0],
            expected_exception="ZeroDivisionError",
            lang_config={"require_path": "math"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "ruby"

    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "greet.rb"
        src.write_text(textwrap.dedent("""\
            def greet(name)
              "hello #{name}"
            end
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="greet.rb", function="greet",
            language="ruby",
            args=["world"],
            expected_return='hello world',
            lang_config={"require_path": "greet"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("perl"), reason="Perl not available")
class TestRealExecutionPerl:
    def test_confirms_return_value(self, tmp_path):
        src = tmp_path / "MathUtil.pm"
        src.write_text(textwrap.dedent("""\
            package MathUtil;
            use strict;
            use warnings;
            use Exporter 'import';
            our @EXPORT = ('add_numbers');

            sub add_numbers {
                my ($a, $b) = @_;
                return $a + $b;
            }
            1;
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="MathUtil.pm", function="add_numbers",
            language="perl",
            args=[10, 20],
            expected_return="30",
            lang_config={"use_module": "MathUtil"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "perl"

    def test_confirms_exception(self, tmp_path):
        src = tmp_path / "Strict.pm"
        src.write_text(textwrap.dedent("""\
            package Strict;
            use strict;
            use warnings;
            use Exporter 'import';
            our @EXPORT = ('fail_hard');

            sub fail_hard {
                die "intentional failure";
            }
            1;
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="Strict.pm", function="fail_hard",
            language="perl",
            args=[],
            expected_exception="die",
            lang_config={"use_module": "Strict"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"


@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("javac"), reason="Java not available")
class TestRealExecutionJava:
    def test_confirms_static_method(self, tmp_path):
        src = tmp_path / "MathUtil.java"
        src.write_text(textwrap.dedent("""\
            public class MathUtil {
                public static int square(int x) {
                    return x * x;
                }
            }
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="MathUtil.java", function="square",
            language="java",
            expected_return="49",
            lang_config={
                "class_name": "MathUtil",
                "imports": [],
                "arg_expressions": ["7"],
                "return_type": "int",
                "is_static": True,
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert r.language == "java"

    def test_confirms_exception(self, tmp_path):
        src = tmp_path / "Divider.java"
        src.write_text(textwrap.dedent("""\
            public class Divider {
                public static int divide(int a, int b) {
                    return a / b;
                }
            }
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="Divider.java", function="divide",
            language="java",
            expected_exception="ArithmeticException",
            lang_config={
                "class_name": "Divider",
                "imports": [],
                "arg_expressions": ["1", "0"],
                "return_type": "int",
                "is_static": True,
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"


# -- _run_dark_verification (orchestrator integration) -----------------------


class TestRunDarkVerification:
    """Test the orchestrator's dark verification pass."""

    def _make_outcome(self, file, function, status="dark", hypothesis=""):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file, function=function, status=status,
            body="suspected bug", hypothesis=hypothesis,
        )

    def _make_result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        for o in outcomes:
            if o.status == "dark":
                r.dormant += 1
            elif o.status == "finding":
                r.findings += 1
            elif o.status == "clean":
                r.clean += 1
        return r

    def test_no_llm_client_is_noop(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("a.py", "check")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=None)
        assert result.outcomes[0].status == "dark"

    def test_no_dark_outcomes_is_noop(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("a.py", "check", status="clean")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=lambda s, u: "{}")
        assert result.outcomes[0].status == "clean"

    def test_confirmed_witness_upgrades_to_finding(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "math_util.py"
        src.write_text(textwrap.dedent("""\
            def divide(a, b):
                return a / b
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "math_util.py", "divide",
            hypothesis="division by zero",
        )
        result = self._make_result([outcome])

        llm_response = json.dumps({
            "module_path": "math_util",
            "function": "divide",
            "args": [1, 0],
            "expected_exception": "ZeroDivisionError",
            "rationale": "dividing by zero",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.findings == 1
        assert result.dormant == 0

    def test_refuted_witness_downgrades_to_clean(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "math_util.py"
        src.write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "math_util.py", "add",
            hypothesis="integer overflow",
        )
        result = self._make_result([outcome])

        llm_response = json.dumps({
            "module_path": "math_util",
            "function": "add",
            "args": [1, 2],
            "expected_exception": "OverflowError",
            "rationale": "overflow on large inputs",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].status == "clean"
        assert result.clean == 1
        assert result.dormant == 0

    def test_refuted_witness_never_demotes_tool_backed_finding(self, tmp_path):
        """Tool-backed floor: a refuted witness (one LLM-guessed input)
        caps a verification-grade finding at suspicious — it never
        erases an SMT/Coccinelle/Semgrep receipt to clean."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "calc.py"
        src.write_text(textwrap.dedent("""\
            def alloc_size(n, elem_size):
                return n + elem_size
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "calc.py", "alloc_size", status="finding",
            hypothesis="integer overflow in size calculation",
        )
        outcome.evidence_tool = "smt:check-overflow"
        outcome.review_result = {"cwe_class": "CWE-190"}
        result = self._make_result([outcome])

        llm_response = json.dumps({
            "module_path": "calc",
            "function": "alloc_size",
            "args": [1, 2],
            "expected_exception": "OverflowError",
            "rationale": "overflow on large inputs",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].status == "suspicious"
        assert "smt:check-overflow" in result.outcomes[0].evidence_tool
        assert "dark_verify:refuted" in result.outcomes[0].evidence_tool
        assert result.findings == 0
        assert result.suspicious == 1
        assert result.clean == 0

    def test_refuted_witness_demotes_llm_claimed_finding(self, tmp_path):
        """llm-claimed stamps are not verification-grade — the refute
        demotes to clean as before."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "calc2.py"
        src.write_text(textwrap.dedent("""\
            def scale(n):
                return n * 2
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "calc2.py", "scale", status="finding",
            hypothesis="integer overflow",
        )
        outcome.evidence_tool = "llm-claimed:smt"
        outcome.review_result = {"cwe_class": "CWE-190"}
        result = self._make_result([outcome])

        llm_response = json.dumps({
            "module_path": "calc2",
            "function": "scale",
            "args": [2],
            "expected_exception": "OverflowError",
            "rationale": "overflow on large inputs",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].status == "clean"
        assert result.outcomes[0].evidence_tool == "dark_verify:refuted"
        assert result.findings == 0
        assert result.clean == 1

    def test_clean_outcome_in_expanded_cwe_not_eligible(self, tmp_path):
        """The expanded CWE families carry a status filter: a clean
        CWE-190 outcome spends no witness call and stays clean."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "calc3.py"
        src.write_text("def f(n):\n    return n\n", encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "calc3.py", "f", status="clean",
            hypothesis="integer overflow",
        )
        outcome.review_result = {"cwe_class": "CWE-190"}
        result = self._make_result([outcome])

        calls = []

        def _llm(s, u):
            calls.append(1)
            return "{}"

        _run_dark_verification(result, config, llm_client=_llm)
        assert calls == []
        assert result.outcomes[0].status == "clean"

    def test_unsupported_language_skipped(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("README.md", "check")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=lambda s, u: "{}")
        assert result.outcomes[0].status == "dark"

    def test_unparseable_llm_response_stays_dark(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "util.py"
        src.write_text("def check(): pass\n", encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("util.py", "check")
        result = self._make_result([outcome])
        _run_dark_verification(
            result, config, llm_client=lambda s, u: "not json at all",
        )
        assert result.outcomes[0].status == "dark"

    def test_persists_results_json(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "math_util.py"
        src.write_text("def divide(a, b): return a / b\n", encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "math_util.py", "divide",
            hypothesis="division by zero",
        )
        result = self._make_result([outcome])

        llm_response = json.dumps({
            "module_path": "math_util",
            "function": "divide",
            "args": [1, 0],
            "expected_exception": "ZeroDivisionError",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)

        results_path = tmp_path / "dark-verify-results.json"
        assert results_path.exists()
        records = json.loads(results_path.read_text(encoding="utf-8"))
        assert len(records) == 1
        assert records[0]["status"] == "finding"
        assert records[0]["evidence_tool"] == "dark_verify:confirmed"

    def test_cwe_dispatch_eligibility(self, tmp_path):
        """A non-dark outcome with an auth CWE (dark_verify: True in
        dispatch) is eligible for dark verification."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "auth.py"
        src.write_text(textwrap.dedent("""\
            def check_login(user, pw):
                return user == "admin"
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "auth.py", "check_login", status="suspicious",
            hypothesis="authentication bypass",
        )
        outcome.review_result = {"cwe_class": "CWE-287"}
        result = self._make_result([outcome])
        result.suspicious = 1

        llm_response = json.dumps({
            "module_path": "auth",
            "function": "check_login",
            "args": ["admin", "wrong"],
            "expected_return": True,
            "rationale": "password not checked",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.findings == 1
        assert result.suspicious == 0

    def test_cwe190_eligible(self, tmp_path):
        """CWE-190 (integer overflow) is dark-verify eligible."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "calc.py"
        src.write_text(textwrap.dedent("""\
            def alloc_size(n, elem_size):
                return (n * elem_size) & 0xFFFFFFFF
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "calc.py", "alloc_size", status="suspicious",
            hypothesis="integer overflow in 32-bit size calculation",
        )
        outcome.review_result = {"cwe_class": "CWE-190"}
        result = self._make_result([outcome])
        result.suspicious = 1

        llm_response = json.dumps({
            "module_path": "calc",
            "function": "alloc_size",
            "args": [2**30, 8],
            "expected_return": 0,
            "rationale": "2^30 * 8 = 2^33 wraps to 0 in uint32",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.outcomes[0].status == "finding"

    def test_cwe134_eligible(self, tmp_path):
        """CWE-134 (format string) is dark-verify eligible."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "log.py"
        src.write_text(textwrap.dedent("""\
            def log_msg(fmt, *args):
                return fmt % args
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "log.py", "log_msg", status="suspicious",
            hypothesis="format string vulnerability",
        )
        outcome.review_result = {"cwe_class": "CWE-134"}
        result = self._make_result([outcome])
        result.suspicious = 1

        llm_response = json.dumps({
            "module_path": "log",
            "function": "log_msg",
            "args": ["%s%s", "a"],
            "expected_exception": "TypeError",
            "rationale": "insufficient args for format",
        })

        _run_dark_verification(result, config, llm_client=lambda s, u: llm_response)
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.outcomes[0].status == "finding"

    def test_cwe416_eligible(self, tmp_path):
        """CWE-416 (use-after-free) is dark-verify eligible."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "cache.py"
        src.write_text(textwrap.dedent("""\
            def fetch_and_free(items, idx):
                result = items[idx]
                items.clear()
                return len(result)
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "cache.py", "fetch_and_free", status="suspicious",
            hypothesis="dangling reference after clear",
        )
        outcome.review_result = {"cwe_class": "CWE-416"}
        result = self._make_result([outcome])
        result.suspicious = 1

        llm_response = json.dumps({
            "module_path": "cache",
            "function": "fetch_and_free",
            "args": [["hello", "world"], 0],
            "expected_return": 5,
            "rationale": "result ref survives clear",
        })

        _run_dark_verification(
            result, config, llm_client=lambda s, u: llm_response,
        )
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.outcomes[0].status == "finding"

    def test_cwe457_eligible(self, tmp_path):
        """CWE-457 (uninitialised variable) is dark-verify eligible."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        src = tmp_path / "initmod.py"
        src.write_text(textwrap.dedent("""\
            def process(flag):
                if flag:
                    value = 42
                return value
        """), encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "initmod.py", "process", status="suspicious",
            hypothesis="value used before assignment when flag is False",
        )
        outcome.review_result = {"cwe_class": "CWE-457"}
        result = self._make_result([outcome])
        result.suspicious = 1

        llm_response = json.dumps({
            "module_path": "initmod",
            "function": "process",
            "args": [False],
            "expected_exception": "UnboundLocalError",
            "rationale": "value never assigned when flag is falsy",
        })

        _run_dark_verification(
            result, config, llm_client=lambda s, u: llm_response,
        )
        assert result.outcomes[0].evidence_tool == "dark_verify:confirmed"
        assert result.outcomes[0].status == "finding"

    def test_non_dark_verify_cwe_skipped(self, tmp_path):
        """A suspicious outcome with a non-dark-verify CWE is not eligible."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome(
            "buf.c", "copy_data", status="suspicious",
        )
        outcome.review_result = {"cwe_class": "CWE-120"}
        result = self._make_result([outcome])
        result.suspicious = 1
        _run_dark_verification(result, config, llm_client=lambda s, u: "{}")
        assert result.outcomes[0].status == "suspicious"


# ============================================================================
# Compile/run sandbox parity — compiles route through core.sandbox and the
# whole module fails closed when the sandbox is unavailable
# ============================================================================


class _SandboxSpy:
    """Stand-in for core.sandbox.context.run — records every invocation
    (cmd, kwargs) and plays back canned CompletedProcess results."""

    def __init__(self, results):
        self.calls = []
        self._results = list(results)

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), dict(kwargs)))
        return self._results.pop(0)


def _completed(stdout="", returncode=0):
    import subprocess
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _forbid_bare_subprocess(monkeypatch):
    """Any subprocess.run reached from the executor module is a sandbox
    bypass — fail the test loudly."""
    from core.audit.dark_verify import _execute as ex

    def _boom(*args, **kwargs):
        raise AssertionError(
            "subprocess.run reached — target-derived code must only "
            "execute through core.sandbox"
        )

    monkeypatch.setattr(ex.subprocess, "run", _boom)


class TestCompileSandboxParity:
    """Compile steps execute target-derived code too (javac annotation
    processors, #embed/.incbin/include_str! reads) — pin them to the same
    sandbox entry point the run steps use."""

    def test_c_compile_routed_through_sandbox(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "add.c").write_text(
            "int add(int a, int b) { return a + b; }\n", encoding="utf-8",
        )
        spy = _SandboxSpy([
            _completed(),  # compile
            _completed(stdout=json.dumps({"status": "returned", "value": "7"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="add.c", function="add",
            language="c", expected_return="7",
            lang_config={
                "param_types": ["int", "int"], "return_type": "int",
                "arg_expressions": ["3", "4"], "includes": [], "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert len(spy.calls) == 2
        cmd, kwargs = spy.calls[0]
        assert cmd[0] == "cc"
        assert "-fsanitize=address,undefined" in cmd
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(tmp_path)
        assert "compile" in kwargs["caller_label"]

    def test_go_compile_routed_through_sandbox(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "main.go").write_text(
            "package main\n\nfunc Add(a, b int) int { return a + b }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        spy = _SandboxSpy([
            _completed(),  # go build
            _completed(stdout=json.dumps({"status": "returned", "value": "7"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.go", function="Add",
            language="go", expected_return="7",
            lang_config={
                "package": "main", "arg_expressions": ["3", "4"],
                "return_type": "int",
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        cmd, kwargs = spy.calls[0]
        assert cmd[:2] == ["/usr/bin/go", "build"]
        assert kwargs["block_network"] is True
        # go build gets a caller env (GOPATH/GOCACHE redirected into the
        # work area) — the sandbox must strip DANGEROUS_ENV_VARS from it.
        assert "GOPATH" in kwargs["env"]
        assert "GOCACHE" in kwargs["env"]
        assert kwargs["strict_env"] is True

    def test_rust_compile_routed_through_sandbox(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "lib.rs").write_text(
            "pub fn double_it(x: i32) -> i32 { x * 2 }\n", encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        spy = _SandboxSpy([
            _completed(),  # rustc
            _completed(stdout=json.dumps({"status": "returned", "value": "84"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib.rs", function="double_it",
            language="rust", expected_return="84",
            lang_config={
                "arg_expressions": ["42"], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        cmd, kwargs = spy.calls[0]
        assert cmd[0] == "/usr/bin/rustc"
        assert kwargs["block_network"] is True
        assert "compile" in kwargs["caller_label"]
        # Single crate root: rustc rejects multiple input files, so the
        # harness is the ONLY .rs on the command line — the target source
        # is spliced in via include!("target_source.rs").
        rs_inputs = [a for a in cmd if a.endswith(".rs")]
        assert len(rs_inputs) == 1
        assert rs_inputs[0].endswith("harness.rs")
        # Panics must surface as crash signals, not exit code 101.
        assert "panic=abort" in cmd

    def test_javac_sandboxed_with_proc_none(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "MathUtil.java").write_text(
            "public class MathUtil {\n"
            "    public static int square(int x) { return x * x; }\n"
            "}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        spy = _SandboxSpy([
            _completed(),  # javac
            _completed(stdout=json.dumps({"status": "returned", "value": "49"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="MathUtil.java", function="square",
            language="java", expected_return="49",
            lang_config={
                "class_name": "MathUtil", "imports": [],
                "arg_expressions": ["7"], "return_type": "int",
                "is_static": True,
            },
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "confirmed"
        assert len(spy.calls) == 2
        cmd, kwargs = spy.calls[0]
        assert cmd[0] == "/usr/bin/javac"
        # Classpath annotation processors must never execute at compile
        # time, even inside the sandbox.
        assert "-proc:none" in cmd
        assert kwargs["block_network"] is True
        assert "compile" in kwargs["caller_label"]
        run_cmd, _run_kwargs = spy.calls[1]
        assert run_cmd[0] == "/usr/bin/java"


class TestSandboxFailClosed:
    """No core.sandbox → error verdict, never a bare-subprocess fallback."""

    def test_import_helper_returns_none_when_sandbox_missing(self, monkeypatch):
        import builtins

        from core.audit.dark_verify import _execute as ex
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name.startswith("core.sandbox"):
                raise ImportError("core.sandbox not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        assert ex._import_sandbox_run() is None

    def _refusal_asserts(self, result):
        assert result.verdict == "error"
        assert "sandbox unavailable" in result.match_detail
        assert "refusing to execute" in result.match_detail

    def test_script_witness_refuses(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "calc.py").write_text(
            "def double(x): return x * 2\n", encoding="utf-8",
        )
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="calc.py", function="double",
            module_path="calc", args=[5], expected_return=10,
        )
        r = execute_witness(spec, tmp_path)
        self._refusal_asserts(r)
        assert r.language == "python"

    def test_c_compile_refuses(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "add.c").write_text(
            "int add(int a, int b) { return a + b; }\n", encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="add.c", function="add",
            language="c",
            lang_config={
                "param_types": ["int", "int"], "return_type": "int",
                "arg_expressions": ["3", "4"], "includes": [], "setup_lines": [],
            },
        )
        self._refusal_asserts(execute_witness(spec, tmp_path))

    def test_go_compile_refuses(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "main.go").write_text(
            "package main\n\nfunc Add(a, b int) int { return a + b }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="main.go", function="Add",
            language="go",
            lang_config={
                "package": "main", "arg_expressions": ["3", "4"],
                "return_type": "int",
            },
        )
        self._refusal_asserts(execute_witness(spec, tmp_path))

    def test_rust_compile_refuses(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "lib.rs").write_text(
            "pub fn f() {}\n", encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib.rs", function="f",
            language="rust",
            lang_config={
                "arg_expressions": [], "return_type": "i32",
                "use_path": "", "setup_lines": [],
            },
        )
        self._refusal_asserts(execute_witness(spec, tmp_path))

    def test_java_refuses(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex
        (tmp_path / "A.java").write_text(
            "public class A { public static int f() { return 1; } }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="A.java", function="f",
            language="java",
            lang_config={
                "class_name": "A", "imports": [], "arg_expressions": [],
                "return_type": "int", "is_static": True,
            },
        )
        self._refusal_asserts(execute_witness(spec, tmp_path))

    def test_run_native_binary_refuses(self, tmp_path, monkeypatch):
        from pathlib import Path

        from core.audit.dark_verify import _execute as ex
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: None)
        _forbid_bare_subprocess(monkeypatch)
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
        )
        r = ex._run_native_binary(
            spec, Path("/nonexistent/harness_bin"), tmp_path, 5, "c",
        )
        self._refusal_asserts(r)


# -- validate_spec arg_expression allowlist -----------------------------------


class TestArgExpressionAllowlist:
    """arg_expressions must fit the literal grammar — constants, bare/dotted
    names, literal containers, +/-/* arithmetic, suffixed numerics, and the
    zero-arg method-on-literal shape. The old substring blocklist was
    bypassable via string concatenation."""

    def _spec(self, exprs, language="c", file="a.c"):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="parse",
            language=language,
            lang_config={"arg_expressions": exprs, "return_type": "int"},
        )

    @pytest.mark.parametrize("expr", [
        "42",                       # int
        "-1",                       # negative int
        "3.14",                     # float
        '"admin"',                  # string
        '"<script>"',               # string with markup
        '"a;b"',                    # semicolon INSIDE a string literal is data
        "'a'",                      # C/Rust char literal parses as a string
        "buf",                      # bare identifier (C variable from setup)
        "nil",                      # Go
        "null",                     # Java
        "NULL",                     # C
        "None",                     # Python
        "True",                     # bool
        "(1, 2)",                   # tuple
        "[1, 2]",                   # list
        "{1, 2}",                   # set / C initializer braces
        '{"k": 1}',                 # dict
        'b"A" * 100',               # BinOp over literals (buffer patterns)
        '"a" + "b"',                # literal concatenation
        "0usize",                   # Rust suffixed numeric
        "100L",                     # Java/C suffixed numeric
        "1.5f",                     # C float suffix
        "-1i64",                    # negative suffixed numeric
        '"test".to_string()',       # Rust: zero-arg method on a literal
        "Integer.MAX_VALUE",        # Java dotted constant
        "&[1, 2]",                  # Rust borrow of a slice literal
        "&mut buf",                 # Rust mutable borrow of an identifier
        '&"abc"',                   # Rust borrow of a string literal
    ])
    def test_literal_grammar_accepted(self, expr):
        assert validate_spec(self._spec([expr])) is None

    @pytest.mark.parametrize("expr", [
        '__import__("o" + "s")',                # concatenation bypass of old blocklist
        "getattr(x, 'y')",                      # general call
        'open("/etc/passwd")',                  # general call
        '0); system("rm -rf /")',               # statement breakout (parse fails)
        "`whoami`",                             # backtick (parse fails)
        'Runtime.getRuntime().exec("evil")',    # chained method calls
        '"".join(x)',                           # method on literal WITH args
        '"x".to_string(1)',                     # method on literal WITH args
        "().__class__",                         # dunder attribute access
        "1\n2",                                 # newline
        "42 # comment",                         # comment past the parser
        "lambda: 1",                            # lambda
        "[i for i in (1, 2)]",                  # comprehension
        "x[0]",                                 # subscript
        "a if b else c",                        # conditional expression
        "(x := 1)",                             # named expression
        'f"{x}"',                               # f-string
        '&open("/etc/passwd")',                 # borrow prefix must not launder calls
    ])
    def test_non_literal_rejected(self, expr):
        err = validate_spec(self._spec([expr]))
        assert err is not None
        assert "arg_expression" in err


# -- restricted reads ---------------------------------------------------------
#
# On Landlock-only hosts (no mount namespace) the sandbox's default is
# restrict_reads=False, so untrusted witness/target code could read $HOME
# credentials and echo them into match_detail — which is persisted to
# dark-verify-results.json. Every execution AND compile site in
# core.audit.dark_verify._execute must therefore pass restrict_reads=True.


def _witness_spec(**overrides) -> DarkWitnessSpec:
    base = dict(
        finding_key="src/a.py:f",
        file="src/a.py",
        function="f",
        language="python",
        module_path="a",
    )
    base.update(overrides)
    return DarkWitnessSpec(**base)


class TestRunScriptWitnessRestrictsReads:
    def test_sandbox_run_receives_restrict_reads_true(self, monkeypatch, tmp_path):
        fake = _SandboxSpy([_completed(stdout=json.dumps(
            {"status": "returned", "value": "1"}))])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: fake)

        result = _run_script_witness(
            _witness_spec(), "print('x')", suffix=".py",
            cmd_prefix=[sys.executable],
            target_root=tmp_path, timeout_s=5,
            language="python",
        )

        assert result.verdict != "error"
        assert len(fake.calls) == 1
        _, kwargs = fake.calls[0]
        assert kwargs["restrict_reads"] is True
        assert kwargs["block_network"] is True


class TestRunNativeBinaryRestrictsReads:
    def test_sandbox_run_receives_restrict_reads_true(self, monkeypatch, tmp_path):
        fake = _SandboxSpy([_completed(stdout=json.dumps(
            {"status": "returned", "value": "1"}))])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: fake)
        binary = tmp_path / "harness_bin"
        binary.write_bytes(b"\x7fELF")

        result = _run_native_binary(
            _witness_spec(language="c", file="src/a.c"), binary, tmp_path, 5, "c",
        )

        assert result.verdict != "error"
        assert len(fake.calls) == 1
        _, kwargs = fake.calls[0]
        assert kwargs["restrict_reads"] is True
        assert kwargs["block_network"] is True


class TestSandboxedCompileRestrictsReads:
    def test_compile_receives_restrict_reads_true(self, tmp_path):
        fake = _SandboxSpy([_completed()])
        _sandboxed_compile(
            fake, ["cc", "-o", "x", "x.c"],
            target_root=tmp_path, work_dir=tmp_path,
            caller_label="test-compile",
        )

        assert len(fake.calls) == 1
        _, kwargs = fake.calls[0]
        assert kwargs["restrict_reads"] is True
        assert kwargs["block_network"] is True
        # work_dir stays readable through tool_paths.
        assert str(tmp_path) in kwargs["tool_paths"]


class TestNoCallSiteOmitsRestrictReads:
    """Structural check: no sandbox call site in the module omits
    restrict_reads."""

    def test_every_sandbox_run_call_passes_restrict_reads_true(self):
        source = inspect.getsource(ex)
        tree = ast.parse(source)
        call_sites = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "sandbox_run"
        ]
        # _sandboxed_compile's inner call, the script witness, the
        # native run, and the Java run step.
        assert len(call_sites) >= 4
        for call in call_sites:
            kwargs = {kw.arg: kw.value for kw in call.keywords}
            assert "restrict_reads" in kwargs, (
                f"sandbox_run call at line {call.lineno} omits restrict_reads"
            )
            value = kwargs["restrict_reads"]
            assert isinstance(value, ast.Constant) and value.value is True, (
                f"sandbox_run call at line {call.lineno} must pass "
                f"restrict_reads=True"
            )


class TestToolchainReadPaths:
    def test_empty_binary_yields_no_paths(self):
        assert _toolchain_read_paths(None) == []
        assert _toolchain_read_paths("") == []

    def test_python_interpreter_delegates_to_runtime_helper(self):
        from core.sandbox.python_paths import python_runtime_tool_paths
        assert _toolchain_read_paths(sys.executable) == (
            python_runtime_tool_paths()
        )

    def test_never_grants_home_or_root(self, tmp_path, monkeypatch):
        home = tmp_path / "home" / "user"
        bin_dir = home / "bin"
        bin_dir.mkdir(parents=True)
        tool = bin_dir / "sometool"
        tool.write_text("#!/bin/sh\n")
        monkeypatch.setenv("HOME", str(home))

        paths = _toolchain_read_paths(str(tool))
        assert str(home) not in paths
        assert "/" not in paths
        # The narrow bin dir itself is acceptable; $HOME is not.
        for p in paths:
            assert p == str(bin_dir)

    def test_system_prefix_binaries_need_no_extra_grant(self):
        # /bin, /usr are already in the restricted read allowlist.
        assert _toolchain_read_paths("/bin/sh") == []

    def test_user_local_toolchain_root_granted(self, tmp_path):
        root = tmp_path / "toolchains" / "x"
        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True)
        tool = bin_dir / "toolc"
        tool.write_text("#!/bin/sh\n")

        paths = _toolchain_read_paths(str(tool))
        assert str(bin_dir) in paths
        assert str(root) in paths


class TestSourcePathContainment:
    def test_traversal_file_is_rejected(self, tmp_path):
        outside = tmp_path / "secret.py"
        outside.write_text("def f():\n    return 1\n")
        repo = tmp_path / "repo"
        repo.mkdir()

        result = execute_witness(
            _witness_spec(file="../secret.py", finding_key="../secret.py:f"),
            repo,
        )
        assert result.verdict == "error"
        assert "escapes target root" in result.match_detail

    def test_in_tree_missing_file_still_reports_not_found(self, tmp_path):
        result = execute_witness(_witness_spec(file="src/missing.py"), tmp_path)
        assert result.verdict == "error"
        assert "not found" in result.match_detail


class TestValidateSpecLanguageFallback:
    def test_dangerous_builtin_caught_with_autodetected_language(self):
        spec = _witness_spec(language="", function="eval")
        err = validate_spec(spec)
        assert err is not None
        assert "dangerous builtin" in err

    def test_explicit_language_still_caught(self):
        spec = _witness_spec(language="python", function="eval")
        err = validate_spec(spec)
        assert err is not None
        assert "dangerous builtin" in err
