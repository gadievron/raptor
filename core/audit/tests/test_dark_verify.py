"""Tests for core.audit.dark_verify — witness-execution verification."""

from __future__ import annotations

import json
import shutil
import textwrap

import pytest

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

    def test_unexpected_exception_confirms(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a",
        )
        stdout = json.dumps({
            "status": "exception", "type": "ZeroDivisionError",
            "message": "division by zero",
        })
        r = _classify_output(spec, stdout, "python")
        assert r.verdict == "confirmed"

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
    def test_includes_finding_details(self):
        prompt = build_witness_prompt(
            file="core/audit/gate.py",
            function="check_bounds",
            hypothesis="off-by-one",
            body="The function does not check upper bound",
        )
        assert "core/audit/gate.py" in prompt
        assert "check_bounds" in prompt
        assert "off-by-one" in prompt

    def test_missing_hypothesis(self):
        prompt = build_witness_prompt("a.py", "f", "", "detail")
        assert "(no hypothesis)" in prompt

    def test_c_prompt_has_sanitizer(self):
        prompt = build_witness_prompt(
            file="src/buf.c",
            function="copy_buf",
            hypothesis="heap overflow",
            body="No bounds check",
            language="c",
        )
        assert "sanitize" in prompt.lower() or "ASan" in prompt
        assert "copy_buf" in prompt

    def test_go_prompt_has_panic(self):
        prompt = build_witness_prompt(
            file="pkg/auth.go",
            function="Check",
            hypothesis="nil deref",
            body="No nil check",
            language="go",
        )
        assert "panic" in prompt.lower()
        assert "Check" in prompt

    def test_js_prompt_has_require(self):
        prompt = build_witness_prompt(
            file="src/auth.js",
            function="validate",
            hypothesis="prototype pollution",
            body="Object.assign without filter",
            language="javascript",
        )
        assert "require" in prompt.lower()
        assert "validate" in prompt

    def test_ts_prompt(self):
        prompt = build_witness_prompt(
            file="src/auth.ts", function="validate",
            hypothesis="type confusion", body="Any cast",
            language="typescript",
        )
        assert "TypeScript" in prompt
        assert "validate" in prompt

    def test_ruby_prompt(self):
        prompt = build_witness_prompt(
            file="lib/auth.rb", function="check",
            hypothesis="injection", body="No sanitization",
            language="ruby",
        )
        assert "Ruby" in prompt
        assert "check" in prompt

    def test_php_prompt(self):
        prompt = build_witness_prompt(
            file="src/auth.php", function="validate",
            hypothesis="sqli", body="No prepared statement",
            language="php",
        )
        assert "PHP" in prompt
        assert "validate" in prompt

    def test_rust_prompt(self):
        prompt = build_witness_prompt(
            file="src/lib.rs", function="process",
            hypothesis="buffer overflow", body="Unsafe block",
            language="rust",
        )
        assert "Rust" in prompt
        assert "process" in prompt

    def test_java_prompt(self):
        prompt = build_witness_prompt(
            file="src/Auth.java", function="validate",
            hypothesis="null deref", body="No null check",
            language="java",
        )
        assert "Java" in prompt
        assert "validate" in prompt

    def test_lua_prompt(self):
        prompt = build_witness_prompt(
            file="lib/auth.lua", function="validate",
            hypothesis="injection", body="No sanitization",
            language="lua",
        )
        assert "Lua" in prompt
        assert "validate" in prompt

    def test_perl_prompt(self):
        prompt = build_witness_prompt(
            file="lib/Auth.pm", function="check",
            hypothesis="injection", body="No taint check",
            language="perl",
        )
        assert "Perl" in prompt
        assert "check" in prompt


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
            OrchestratorConfig, _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("a.py", "check")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=None)
        assert result.outcomes[0].status == "dark"

    def test_no_dark_outcomes_is_noop(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig, _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("a.py", "check", status="clean")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=lambda s, u: "{}")
        assert result.outcomes[0].status == "clean"

    def test_confirmed_witness_upgrades_to_finding(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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

    def test_unsupported_language_skipped(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig, _run_dark_verification,
        )
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcome = self._make_outcome("README.md", "check")
        result = self._make_result([outcome])
        _run_dark_verification(result, config, llm_client=lambda s, u: "{}")
        assert result.outcomes[0].status == "dark"

    def test_unparseable_llm_response_stays_dark(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
            OrchestratorConfig, _run_dark_verification,
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
