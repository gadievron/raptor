"""Tests for core.audit.dark_verify — witness-execution verification."""

from __future__ import annotations

import ast
import inspect
import json
import os
import shutil
import sys
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest

from core.audit.dark_verify import _execute as ex
from core.audit.dark_verify._execute import (
    _run_native_binary,
    _run_script_witness,
    _sandbox_exec_path,
    _sandboxed_compile,
    _toolchain_read_paths,
)
from core.audit.dark_verify import _harness as hy
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

    def test_script_asserts_loaded_file(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/mod.py",
            function="check", module_path="pkg.mod",
        )
        script = generate_witness_script(spec, tmp_path)
        assert "binding_error" in script
        assert "__file__" in script
        assert str(tmp_path.resolve()) + "/pkg/mod.py" in script


class TestWitnessScriptRuntimeBinding:
    """The script's post-load ``__file__`` assertion is a best-effort
    belt behind the static resolution engine: it reports binding_error
    (never a verdict) for mis-binds where no plant code forges the
    interpreter state — an executing plant can spoof ``__file__``, so
    plants are the static engine's job to refuse pre-execution."""

    def _run(self, script):
        import subprocess
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def _tree(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        return tmp_path

    def _spec(self):
        return DarkWitnessSpec(
            finding_key="f1", file="pkg/mod.py",
            function="check", module_path="pkg.mod",
            expected_return="7",
        )

    def test_clean_load_still_returns(self, tmp_path):
        root = self._tree(tmp_path)
        script = generate_witness_script(
            self._spec(), root, witness_token="ab12")
        data = self._run(script)
        assert data["status"] == "returned"
        assert data["token"] == "ab12"

    def test_shadowed_load_reports_binding_error(self, tmp_path):
        # A package-directory plant the loader binds ahead of the
        # finding's module (the shape the static walk refuses; here it
        # exercises the runtime belt directly).
        root = self._tree(tmp_path)
        (root / "pkg" / "mod").mkdir()
        (root / "pkg" / "mod" / "__init__.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        script = generate_witness_script(
            self._spec(), root, witness_token="ab12")
        data = self._run(script)
        assert data["status"] == "binding_error"
        assert "__init__.py" in data["message"]

    def test_sys_modules_hijack_reports_binding_error(self, tmp_path):
        # Planted package code replacing the module in sys.modules at
        # import time: the from-import succeeds against the impostor,
        # but its __file__ is not the finding's file.
        root = self._tree(tmp_path)
        (root / "pkg" / "__init__.py").write_text(
            "import sys, types\n"
            "_m = types.ModuleType('pkg.mod')\n"
            "_m.check = lambda: 7\n"
            "_m.__file__ = __file__\n"
            "sys.modules['pkg.mod'] = _m\n", encoding="utf-8")
        script = generate_witness_script(
            self._spec(), root, witness_token="ab12")
        data = self._run(script)
        assert data["status"] == "binding_error"


class TestClassifyBindingError:
    def _spec(self, **kw):
        return DarkWitnessSpec(
            finding_key="f1", file="pkg/mod.py", function="check",
            language="python", module_path="pkg.mod", **kw,
        )

    def test_binding_error_is_error_never_verdict(self):
        out = json.dumps({
            "status": "binding_error",
            "message": "loaded '/t/pkg/mod/__init__.py', "
                       "expected '/t/pkg/mod.py'",
        })
        r = _classify_output(self._spec(expected_return="7"), out, "python")
        assert r.verdict == "error"
        assert "binding failed" in r.match_detail
        assert r.verdict not in ("confirmed", "refuted")

    def test_binding_error_requires_token_like_any_status(self):
        out = json.dumps({"status": "binding_error", "message": "x"})
        r = _classify_output(
            self._spec(), out, "python", expected_token="ab12")
        assert r.verdict == "inconclusive"


class TestPerlHarnessRuntimeBinding:
    """%INC maps the bareword require's key to the path the loader
    ACTUALLY bound — the harness asserts it is the finding's file, so
    a load served by any other @INC entry reports binding_error."""

    def _spec(self):
        return DarkWitnessSpec(
            finding_key="f1", file="lib/Auth.pm", function="check",
            language="perl", expected_return="1",
            lang_config={"use_module": "lib::Auth"},
        )

    def test_harness_asserts_inc_binding(self, tmp_path):
        harness = hy.generate_perl_harness(
            self._spec(), tmp_path, witness_token="ab12")
        assert "binding_error" in harness
        assert "$INC{'lib/Auth.pm'}" in harness
        assert str(tmp_path.resolve()) + "/lib/Auth.pm" in harness

    def _run_perl(self, harness, tmp_path, env_extra=None):
        import os
        import subprocess
        perl = shutil.which("perl")
        script = tmp_path / "witness.pl"
        script.write_text(harness, encoding="utf-8")
        env = dict(os.environ)
        env.update(env_extra or {})
        proc = subprocess.run(
            [perl, str(script)], capture_output=True, text=True,
            timeout=30, env=env,
        )
        return json.loads(proc.stdout.strip().splitlines()[-1])

    @pytest.mark.skipif(not shutil.which("perl"), reason="Perl not available")
    def test_target_load_passes_binding(self, tmp_path):
        target = tmp_path / "target"
        (target / "lib").mkdir(parents=True)
        (target / "lib" / "Auth.pm").write_text(
            "sub check { return 1; }\n1;\n", encoding="utf-8")
        harness = hy.generate_perl_harness(
            self._spec(), target, witness_token="ab12")
        data = self._run_perl(harness, tmp_path)
        assert data["status"] == "returned"
        assert data["token"] == "ab12"

    @pytest.mark.skipif(not shutil.which("perl"), reason="Perl not available")
    def test_foreign_inc_load_reports_binding_error(self, tmp_path):
        # The module resolves through a DIFFERENT @INC entry (here
        # PERL5LIB; in production any entry after the target root) —
        # whatever loaded is not the finding's file.
        target = tmp_path / "target"
        target.mkdir()
        other = tmp_path / "other"
        (other / "lib").mkdir(parents=True)
        (other / "lib" / "Auth.pm").write_text(
            "sub check { return 1; }\n1;\n", encoding="utf-8")
        harness = hy.generate_perl_harness(
            self._spec(), target, witness_token="ab12")
        data = self._run_perl(
            harness, tmp_path, env_extra={"PERL5LIB": str(other)})
        assert data["status"] == "binding_error"
        assert "expected" in data["message"]


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

    def test_char_ptr_return_printed_as_pointer(self, tmp_path):
        # %s would make the HARNESS dereference the returned buffer
        # after the pre-call sentinel — a function legitimately
        # returning a non-NUL-terminated buffer then overreads inside
        # harness code, and the post-sentinel sanitizer report would
        # read as a confirmed bug in the target.
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/str.c", function="dup_prefix",
            language="c",
            lang_config={
                "param_types": ["char *", "int"],
                "return_type": "char *",
                "arg_expressions": ["buf", "4"],
                "includes": [],
                "setup_lines": ['char buf[10] = "AAAA";'],
            },
        )
        harness = generate_c_harness(spec, tmp_path)
        assert "%s" not in harness
        assert "%p" in harness


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
        # Exact file path with extension: a stripped stem would let a
        # repo-planted extensionless `lib/parser` shadow the module.
        assert "./lib/parser.js" in harness


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

    def test_lua_error_message_substring_confirms(self):
        # Lua's pcall carries no exception class — the harness reports
        # a fixed type token ("error") and the prompt contract defines
        # expected_exception as an error-MESSAGE substring.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.lua", function="f",
            language="lua",
            expected_exception="attempt to index a nil value",
        )
        stdout = json.dumps({
            "status": "exception", "type": "error",
            "message": "a.lua:3: attempt to index a nil value (local 'x')",
        })
        r = _classify_output(spec, stdout, "lua")
        assert r.verdict == "confirmed"

    def test_perl_die_message_substring_confirms(self):
        # Perl's die is untyped — the harness reports type "die" and
        # the prompt contract defines expected_exception as an
        # error-MESSAGE substring.
        spec = DarkWitnessSpec(
            finding_key="f1", file="A.pm", function="f",
            language="perl",
            expected_exception="division by zero",
        )
        stdout = json.dumps({
            "status": "exception", "type": "die",
            "message": "Illegal division by zero at A.pm line 4.",
        })
        r = _classify_output(spec, stdout, "perl")
        assert r.verdict == "confirmed"

    def test_lua_error_message_mismatch_not_confirmed(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.lua", function="f",
            language="lua",
            expected_exception="attempt to index a nil value",
        )
        stdout = json.dumps({
            "status": "exception", "type": "error",
            "message": "a.lua:3: bad argument #1 to 'f'",
        })
        r = _classify_output(spec, stdout, "lua")
        assert r.verdict == "refuted"

    def test_typed_language_keeps_exact_type_match(self):
        # Python's prompt contract promises an exception CLASS name —
        # a message merely mentioning the class must not confirm.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="f",
            module_path="a", expected_exception="ValueError",
        )
        stdout = json.dumps({
            "status": "exception", "type": "TypeError",
            "message": "expected ValueError here",
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

    def test_char_ptr_return_value_check_is_inconclusive(self):
        # char* results print as %p pointer identity, so a predicted
        # string value can never be compared against the output — the
        # mismatch is insufficiency of evidence, not a refutation.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_return="hello",
            lang_config={"return_type": "char *"},
        )
        stdout = json.dumps({"status": "returned", "value": "0x5591ab0"})
        r = _classify_output(spec, stdout, "c")
        assert r.verdict == "inconclusive"

    @pytest.mark.parametrize("return_type", [
        "const char *", "unsigned char *", "void *", "int *",
        "struct foo *", "char **",
    ])
    def test_any_pointer_return_value_check_is_inconclusive(
        self, return_type,
    ):
        # The harness prints EVERY pointer as %p pointer identity —
        # the guard must match the formatter, or a correct prediction
        # (e.g. "NULL" vs glibc's "(nil)") on any non-char* pointer
        # return mints a wrong authoritative refutation.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_return="NULL",
            lang_config={"return_type": return_type},
        )
        stdout = json.dumps({"status": "returned", "value": "(nil)"})
        r = _classify_output(spec, stdout, "c")
        assert r.verdict == "inconclusive", return_type

    def test_int_return_value_check_still_compares(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_return="7",
            lang_config={"return_type": "int"},
        )
        stdout = json.dumps({"status": "returned", "value": "7"})
        r = _classify_output(spec, stdout, "c")
        assert r.verdict == "confirmed"

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

    def test_sanitizerless_fallback_clean_exit_is_inconclusive(self):
        # The Rust executor's fallback build drops -Z sanitizer=address
        # (stable rustc).  A clean exit there proves nothing — the
        # predicted memory-safety crash may simply not manifest without
        # ASan — so silent sanitizer loss must not keep refutation
        # authority.
        spec = _native_spec(expected_crash=True)
        r = ex._classify_native_output(
            spec, _native_proc(stdout="{}"), None, "rust",
            sanitizers_active=False,
        )
        assert r.verdict == "inconclusive"
        assert "no sanitizers" in r.match_detail

    def test_sanitizerless_fallback_real_crash_still_confirms(self):
        # Control: a real crash signal stands on its own — losing ASan
        # only removes refutation authority, never confirmation.
        spec = _native_spec(expected_crash=True)
        info = {"signal": "SIGSEGV"}
        r = ex._classify_native_output(
            spec, _native_proc(returncode=-11), info, "rust",
            sanitizers_active=False,
        )
        assert r.verdict == "confirmed"

    def test_sanitizerless_fallback_json_return_is_inconclusive(self):
        # The shared JSON classifier's crash-expectation refutation is
        # gated the same way.
        spec = _native_spec(expected_sanitizer="heap-buffer-overflow")
        stdout = '{"status": "returned", "value": "0"}'
        r = ex._classify_native_output(
            spec, _native_proc(stdout=stdout), None, "rust",
            sanitizers_active=False,
        )
        assert r.verdict == "inconclusive"
        # Control: the instrumented build keeps the refutation.
        r2 = ex._classify_native_output(
            spec, _native_proc(stdout=stdout), None, "rust",
        )
        assert r2.verdict == "refuted"


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

    def test_trailing_newline_rejected(self):
        """`$` matches before a trailing newline; the validation
        allowlists must anchor with \\Z so a name/path carrying a
        trailing newline never reaches harness generation."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.py", function="check\n",
            language="python",
        )
        err = validate_spec(spec)
        assert err is not None
        assert "invalid function name" in err

        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="check",
            language="ruby",
            lang_config={"require_path": "lib/auth\n"},
        )
        err = validate_spec(spec)
        assert err is not None
        assert "invalid require_path" in err

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

    def test_valid_import_path(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module github.com/user/repo\n", encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/a.go", function="Run",
            language="go",
            lang_config={
                "package": "pkg",
                "import_path": "github.com/user/repo/pkg",
                "return_type": "int",
            },
        )
        assert validate_spec(spec, tmp_path) is None

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
    @pytest.fixture()
    def real_execution_sandbox(self):
        """Real execution needs an achievable containment tier — the
        executors fail closed to verdict="error" without one, which
        must read as skip, not failure. Same probe as the sandboxed-
        compile write-grant tests."""
        if ex._import_sandbox_run() is None:
            pytest.skip("core.sandbox unavailable")
        try:
            from core.sandbox import check_landlock_available
            from core.sandbox._spawn import mount_ns_available
        except ImportError:
            pytest.skip("core.sandbox unavailable")
        if not (check_landlock_available() or mount_ns_available()):
            pytest.skip("no sandbox containment tier on this host")

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

    def test_real_execution_confirms(self, tmp_path, real_execution_sandbox):
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

    def test_real_execution_refutes(self, tmp_path, real_execution_sandbox):
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

    def test_language_auto_detected(self, tmp_path, real_execution_sandbox):
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
        assert "declaration grammar" in r.match_detail


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
        assert "./lib/parser.ts" in harness


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
        assert "'lib/auth'" in harness
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

    def test_loaded_features_binding_assert_present(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="validate",
            language="ruby", lang_config={"require_path": "lib/auth"},
        )
        harness = generate_ruby_harness(spec, tmp_path)
        assert "$LOADED_FEATURES" in harness
        assert "binding_error" in harness
        assert str(tmp_path.resolve()) + "/lib/auth.rb" in harness
        # The assert runs after the require (features are recorded at
        # load) and before the target function is invoked.
        assert harness.index("$LOADED_FEATURES") > harness.index("require ")
        assert harness.index("binding_error") < harness.index("validate(")

    @pytest.mark.skipif(not shutil.which("ruby"), reason="Ruby not available")
    def test_live_target_load_passes_binding(self, tmp_path):
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "auth.rb").write_text(
            "def validate(x)\n  1\nend\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="validate",
            language="ruby", args=["x"],
            lang_config={"require_path": "lib/auth"},
        )
        harness = generate_ruby_harness(spec, tmp_path, witness_token="ab12")
        out = _run_stdout([shutil.which("ruby"), "-e", harness])
        data = json.loads(out.strip().splitlines()[-1])
        assert data["status"] == "returned"

    @pytest.mark.skipif(not shutil.which("ruby"), reason="Ruby not available")
    def test_live_foreign_load_reports_binding_error(self, tmp_path):
        # The feature resolves through a LATER load-path entry (the
        # target-root slot is empty): whatever loaded is not the
        # finding's file.
        target = tmp_path / "target"
        target.mkdir()
        other = tmp_path / "other"
        (other / "lib").mkdir(parents=True)
        (other / "lib" / "auth.rb").write_text(
            "def validate(x)\n  1\nend\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="validate",
            language="ruby", args=["x"],
            lang_config={"require_path": "lib/auth"},
        )
        harness = generate_ruby_harness(spec, target, witness_token="ab12")
        import subprocess
        proc = subprocess.run(
            [shutil.which("ruby"), "-I", str(other), "-e", harness],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        assert data["status"] == "binding_error"


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
            lang_config={"require_path": "./auth.js"},
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

    def test_package_path_renders_engine_templates_in_order(self, tmp_path):
        # The harness search order IS the engine's candidate order —
        # both render from _LUA_PATH_TEMPLATES, asserted here against
        # the generated text.
        from core.audit.dark_verify._resolve import _LUA_PATH_TEMPLATES
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="validate",
            language="lua", lang_config={"require_path": "lib.auth"},
        )
        harness = generate_lua_harness(spec, tmp_path)
        path_line = harness.splitlines()[0]
        positions = [path_line.index("/" + t + ";")
                     for t in _LUA_PATH_TEMPLATES]
        assert positions == sorted(positions)
        assert path_line.rstrip().endswith(".. package.path")

    def test_searchpath_binding_assert_present(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="validate",
            language="lua", lang_config={"require_path": "lib.auth"},
        )
        harness = generate_lua_harness(spec, tmp_path)
        assert "package.searchpath" in harness
        assert "binding_error" in harness
        assert str(tmp_path.resolve()) + "/lib/auth.lua" in harness
        # The assert must run BEFORE require executes any target code.
        assert harness.index("package.searchpath") < harness.index(
            "pcall(require")

    @pytest.mark.skipif(
        not (shutil.which("lua") or shutil.which("lua5.4")
             or shutil.which("lua5.3") or shutil.which("luajit")),
        reason="Lua not available")
    def test_live_shadowed_init_reports_binding_error(self, tmp_path):
        # Runtime belt: the plantable sibling occupies the earlier
        # ?.lua slot, so searchpath lands on the plant, not the
        # finding's init.lua.
        lua = shutil.which("lua") or shutil.which("lua5.4") \
            or shutil.which("lua5.3") or shutil.which("luajit")
        (tmp_path / "lib" / "auth").mkdir(parents=True)
        (tmp_path / "lib" / "auth" / "init.lua").write_text(
            "return { validate = function() return 1 end }\n",
            encoding="utf-8")
        (tmp_path / "lib" / "auth.lua").write_text(
            "return { validate = function() return 99 end }\n",
            encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth/init.lua",
            function="validate", language="lua",
            lang_config={"require_path": "lib.auth"},
        )
        harness = generate_lua_harness(spec, tmp_path, witness_token="ab12")
        script = tmp_path / "witness.lua"
        script.write_text(harness, encoding="utf-8")
        out = _run_stdout([lua, str(script)])
        data = json.loads(out.strip().splitlines()[-1])
        # Lua 5.1 without package.searchpath skips the runtime belt;
        # the static engine still refuses this spec pre-execution.
        assert data["status"] in ("binding_error", "returned")
        if data["status"] == "returned":
            import subprocess
            has_searchpath = subprocess.run(
                [lua, "-e", "os.exit(package.searchpath and 1 or 0)"],
                check=False).returncode
            assert has_searchpath == 0

    def test_json_encode_escapes_backslash_and_control_chars(self, tmp_path):
        """A message containing backslash-quote or a raw newline must
        survive json_encode as parseable single-line JSON — malformed
        output degrades the verdict to inconclusive (target-influenced
        verdict suppression)."""
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="validate",
            language="lua",
            args=["x"],
            lang_config={"require_path": "lib.auth"},
        )
        harness = generate_lua_harness(spec, tmp_path)
        # Backslash must be escaped BEFORE the quote: quote-first would
        # let backslash-quote re-open the string. Control bytes must be
        # spelt \uXXXX, never emitted raw.
        bs_pos = harness.index("gsub('\\\\', '\\\\\\\\')")
        quote_pos = harness.index("gsub('\"', '\\\\\"')")
        assert bs_pos < quote_pos
        assert "'\\\\u%04X'" in harness
        lua = shutil.which("lua") or shutil.which("lua5.4") \
            or shutil.which("lua5.3") or shutil.which("luajit")
        if lua:
            prologue = harness.split("if package.searchpath")[0]
            hostile = 'boom \\" quote\nnewline\ttab'
            snippet = prologue + (
                'io.write(json_encode({status="exception", token=_tok,'
                ' type="error", message=' + hy._lua_quote(hostile) + "}))"
            )
            out = _run_stdout([lua, "-e", snippet])
            assert "\n" not in out
            assert json.loads(out)["message"] == hostile


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
            lang_config={"require_path": "./auth.ts"},
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

    def test_ruby_perl_prompts_request_bare_identifiers(self):
        """validate_spec's identifier grammar rejects qualified names
        ("Class.method", "MyModule::check") with verdict="error" — the
        prompts must not invite spellings that can never execute."""
        for language, file in (("ruby", "lib/auth.rb"), ("perl", "lib/Auth.pm")):
            _user, system = build_witness_prompt(
                file=file, function="check",
                hypothesis="h", body="b", language=language,
            )
            assert "or Class.method" not in system
            assert '"MyModule::check" or just' not in system
            fn_line = next(
                ln for ln in system.splitlines()
                if ln.startswith('- "function"')
            )
            assert "bare" in fn_line

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


# -- _resolve_rustc: rustup-proxy indirection ---------------------------------


class TestResolveRustc:
    """The witness compile invokes the binary _toolchain_read_paths
    grants; a rustup proxy re-execs the real compiler from
    ``$RUSTUP_HOME`` — unreadable under restrict_reads. The resolver
    must see through the proxy via ``--print sysroot``."""

    @staticmethod
    def _fake_proxy(tmp_path, sysroot_reply: str, rc: int = 0):
        proxy_dir = tmp_path / "cargo-bin"
        proxy_dir.mkdir()
        proxy = proxy_dir / "rustc"
        proxy.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--print" ] && [ "$2" = "sysroot" ]; then\n'
            f"  echo '{sysroot_reply}'\n"
            f"  exit {rc}\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        proxy.chmod(0o755)
        return proxy_dir, proxy

    def test_resolves_through_proxy_to_sysroot_binary(
        self, tmp_path, monkeypatch,
    ):
        sysroot = tmp_path / "rustup" / "toolchains" / "dev"
        (sysroot / "bin").mkdir(parents=True)
        real = sysroot / "bin" / "rustc"
        real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        real.chmod(0o755)
        proxy_dir, _ = self._fake_proxy(tmp_path, str(sysroot))
        monkeypatch.setenv("PATH", str(proxy_dir))
        assert ex._resolve_rustc() == str(real)

    def test_resolves_through_chained_proxies(self, tmp_path, monkeypatch):
        """A wrapper shim can dispatch to a rustup-managed rustc: the
        first sysroot probe then yields ANOTHER proxy — its bin/rustc
        resolves outside the sysroot it reports — whose settings read
        the witness sandbox would deny (the Nightly runner shape:
        "could not read settings file ... Permission denied").
        Resolution must keep probing until the candidate lives inside
        its own reported sysroot: the real compiler."""
        real_root = tmp_path / "rustup" / "toolchains" / "dev"
        (real_root / "bin").mkdir(parents=True)
        real = real_root / "bin" / "rustc"
        real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        real.chmod(0o755)

        # Inner proxy (the rustup shim shape): lives outside any
        # toolchain, reports the real toolchain's sysroot.
        inner_dir = tmp_path / "cargo-bin-inner"
        inner_dir.mkdir()
        inner = inner_dir / "rustc"
        inner.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--print" ] && [ "$2" = "sysroot" ]; then\n'
            f"  echo '{real_root}'\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        inner.chmod(0o755)

        # Outer wrapper on PATH: reports a "toolchain" whose rustc is
        # the inner proxy (resolves outside that toolchain).
        outer_root = tmp_path / "site" / "toolchains" / "wrapped"
        (outer_root / "bin").mkdir(parents=True)
        (outer_root / "bin" / "rustc").symlink_to(inner)
        proxy_dir, _ = self._fake_proxy(tmp_path, str(outer_root))
        monkeypatch.setenv("PATH", str(proxy_dir))
        assert ex._resolve_rustc() == str(real)

    def test_self_reporting_proxy_terminates(self, tmp_path, monkeypatch):
        """A proxy chain that never reaches a real compiler (the
        reported sysroot's rustc points back at the proxy) must
        terminate on the no-progress fixed point, not loop."""
        root = tmp_path / "loop" / "toolchains" / "dev"
        (root / "bin").mkdir(parents=True)
        proxy_dir, proxy = self._fake_proxy(tmp_path, str(root))
        (root / "bin" / "rustc").symlink_to(proxy)
        monkeypatch.setenv("PATH", str(proxy_dir))
        assert ex._resolve_rustc() == str(root / "bin" / "rustc")

    def test_keeps_which_result_when_probe_fails(
        self, tmp_path, monkeypatch,
    ):
        proxy_dir, proxy = self._fake_proxy(tmp_path, "", rc=1)
        monkeypatch.setenv("PATH", str(proxy_dir))
        assert ex._resolve_rustc() == str(proxy)

    def test_keeps_which_result_when_sysroot_has_no_rustc(
        self, tmp_path, monkeypatch,
    ):
        # A system rustc prints a sysroot too; when <sysroot>/bin/rustc
        # is not a distinct real file (or missing), the which() result
        # stands.
        proxy_dir, proxy = self._fake_proxy(
            tmp_path, str(tmp_path / "no-such-sysroot"))
        monkeypatch.setenv("PATH", str(proxy_dir))
        assert ex._resolve_rustc() == str(proxy)

    def test_none_when_rustc_absent(self, tmp_path, monkeypatch):
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
        assert ex._resolve_rustc() is None

    def test_sysroot_probe_uses_safe_env(self, tmp_path, monkeypatch):
        """The host-side probe executes the operator's toolchain, but it
        must still run under the sanitised allowlist env like every
        other subprocess in the module."""
        proxy_dir, proxy = self._fake_proxy(tmp_path, "", rc=1)
        monkeypatch.setenv("PATH", str(proxy_dir))
        monkeypatch.setenv("LD_PRELOAD", "/nonexistent/evil.so")
        seen: dict[str, object] = {}
        real_run = ex.subprocess.run

        def spy_run(cmd, **kwargs):
            seen["env"] = kwargs.get("env")
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(ex.subprocess, "run", spy_run)
        assert ex._resolve_rustc() == str(proxy)
        env = seen["env"]
        assert env is not None
        assert "LD_PRELOAD" not in env


# ============================================================================
# Real execution tests per language — skip when runtime unavailable
# ============================================================================


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "linux",
                    reason="Linux sandbox write-grant semantics")
class TestSandboxedCompileWriteGrants:
    """The compile work_dir rides the sandbox's writable channel.

    Regression tests for the dark-verify compile EROFS breakage: the
    witness work_dir lives under host /tmp (the exec-workdir session
    family), and ``tool_paths`` is a READ-ONLY grant — under
    mount-namespace isolation it becomes a read-only bind, so a
    compiler writing through it fails with "Read-only file system".
    That write historically snuck through only because the read-only
    remount of a /tmp-resident bind failed EPERM (it would have
    cleared the host mount's locked nosuid/nodev flags) and fell back
    to Landlock, whose baseline allows /tmp — a hole since closed.
    ``_sandboxed_compile`` therefore passes work_dir as ``output``.

    Three properties pin the intended posture (uses /bin/sh as the
    "compiler" so no toolchain is needed):
      1. the designated work_dir IS writable in-sandbox even though it
         is /tmp-resident, and the write is visible on the host;
      2. an ungranted host-/tmp path stays unwritable (private-tmpfs /
         private-scratch isolation is not reopened);
      3. the read-only target bind stays read-only.
    """

    @pytest.fixture()
    def sandbox_run(self):
        run = ex._import_sandbox_run()
        if run is None:
            pytest.skip("core.sandbox unavailable")
        from core.sandbox import check_landlock_available
        from core.sandbox._spawn import mount_ns_available
        if not (check_landlock_available() or mount_ns_available()):
            pytest.skip("no sandbox write enforcement on this host")
        return run

    @pytest.fixture()
    def dirs(self, tmp_path):
        from core.run.workdir import exec_workdir
        work_dir = Path(tempfile.mkdtemp(
            prefix="raptor_dark_test_", dir=exec_workdir()))
        target = tmp_path / "target"
        target.mkdir()
        (target / "src.c").write_text("int x;\n", encoding="utf-8")
        yield work_dir, target
        shutil.rmtree(work_dir, ignore_errors=True)

    def test_work_dir_writable_in_sandbox(self, sandbox_run, dirs):
        work_dir, target = dirs
        artifact = work_dir / "artifact"
        comp = _sandboxed_compile(
            sandbox_run,
            ["/bin/sh", "-c", f"echo compiled > {artifact}"],
            target_root=target, work_dir=work_dir,
            caller_label="test-dark-verify-write-grant",
        )
        assert comp.returncode == 0, comp.stderr
        # The write must land on the HOST side of the grant — the run
        # step consumes the compiled artifact after the sandbox exits.
        assert artifact.read_text(encoding="utf-8").strip() == "compiled"

    def test_ungranted_tmp_path_not_writable(self, sandbox_run, dirs):
        work_dir, target = dirs
        other = Path(tempfile.mkdtemp(prefix="raptor_dark_test_other_",
                                      dir="/tmp"))
        try:
            comp = _sandboxed_compile(
                sandbox_run,
                ["/bin/sh", "-c", f"echo pwn > {other}/pwn"],
                target_root=target, work_dir=work_dir,
                caller_label="test-dark-verify-tmp-deny",
            )
            assert comp.returncode != 0
            assert not (other / "pwn").exists()
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_target_root_stays_read_only(self, sandbox_run, dirs):
        work_dir, target = dirs
        comp = _sandboxed_compile(
            sandbox_run,
            ["/bin/sh", "-c", f"echo pwn > {target}/pwn"],
            target_root=target, work_dir=work_dir,
            caller_label="test-dark-verify-target-ro",
        )
        assert comp.returncode != 0
        assert not (target / "pwn").exists()


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

    def test_confirms_through_rustup_proxy_layout(self, tmp_path, monkeypatch):
        """rustup-managed hosts reach rustc through a proxy that reads
        $RUSTUP_HOME settings and re-execs the toolchain compiler —
        both outside the sandbox's granted read roots, so invoking the
        proxy inside the witness sandbox fails every compile. The
        executor must resolve the real compiler via the sysroot probe
        (_resolve_rustc) before entering the sandbox."""
        rustup_home = tmp_path / "rustup"
        tc_bin = rustup_home / "toolchains" / "dev" / "bin"
        tc_bin.mkdir(parents=True)
        real = tc_bin / "rustc"
        real.symlink_to(shutil.which("rustc"))
        (rustup_home / "settings.toml").write_text(
            'default_toolchain = "dev"\n', encoding="utf-8")
        proxy_dir = tmp_path / "cargo" / "bin"
        proxy_dir.mkdir(parents=True)
        proxy = proxy_dir / "rustc"
        proxy.write_text(
            "#!/bin/sh\n"
            f"cat '{rustup_home}/settings.toml' >/dev/null 2>&1 || exit 3\n"
            'if [ "$1" = "--print" ] && [ "$2" = "sysroot" ]; then\n'
            f"  echo '{tc_bin.parent}'\n"
            "  exit 0\n"
            "fi\n"
            f"exec '{real}' \"$@\"\n",
            encoding="utf-8",
        )
        proxy.chmod(0o755)
        import os as _os
        monkeypatch.setenv(
            "PATH", f"{proxy_dir}:{_os.environ.get('PATH', '')}")

        target = tmp_path / "target"
        target.mkdir()
        (target / "lib.rs").write_text(
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
        r = execute_witness(spec, target)
        assert r.verdict == "confirmed", r.match_detail

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
            lang_config={"require_path": "./parser.js"},
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
            lang_config={"require_path": "./math.js"},
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
            lang_config={"require_path": "./safe.js"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "refuted"

    def test_planted_extensionless_shadow_never_executes(self, tmp_path):
        # Node's LOAD_AS_FILE tries the extensionless path first: a
        # repo-planted file named `math` (no extension, loaded as CJS)
        # shadows `math.js` under a stem require. The stem spelling is
        # rejected before anything executes, and the derived default
        # (exact file path with extension) loads the finding's file,
        # not the plant.
        (tmp_path / "math.js").write_text(textwrap.dedent("""\
            function triple(x) { return x * 3; }
            module.exports = { triple };
        """), encoding="utf-8")
        (tmp_path / "math").write_text(
            "module.exports = { triple: (x) => 999 };\n", encoding="utf-8",
        )
        stem_spec = DarkWitnessSpec(
            finding_key="f1", file="math.js", function="triple",
            language="javascript", args=[5], expected_return="15",
            lang_config={"require_path": "./math"},
        )
        r = execute_witness(stem_spec, tmp_path)
        assert r.verdict == "error"
        assert "not bound to the finding's file" in r.match_detail

        default_spec = DarkWitnessSpec(
            finding_key="f1", file="math.js", function="triple",
            language="javascript", args=[5], expected_return="15",
            lang_config={},
        )
        r2 = execute_witness(default_spec, tmp_path)
        assert r2.verdict == "confirmed", r2.match_detail

    def test_confirms_through_symlinked_shim_layout(
        self, tmp_path, monkeypatch,
    ):
        """Version-manager shim dirs symlink the interpreter from a
        directory the sandbox never mounts (same stranded-argv[0] class
        as the rustup proxy layout: the literal which() path is
        invisible inside the mount namespace while its resolved target
        is). The executor must invoke the resolved binary."""
        node_bin = shutil.which("node")
        if os.path.basename(os.path.realpath(node_bin)) != "node":
            pytest.skip("node resolves to a renamed binary on this host")
        shim_dir = tmp_path / "shims"
        shim_dir.mkdir()
        (shim_dir / "node").symlink_to(node_bin)
        monkeypatch.setenv(
            "PATH", f"{shim_dir}:{os.environ.get('PATH', '')}")

        target = tmp_path / "target"
        target.mkdir()
        (target / "math.js").write_text(textwrap.dedent("""\
            function triple(x) { return x * 3; }
            module.exports = { triple };
        """), encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file="math.js", function="triple",
            language="javascript",
            args=[5],
            expected_return="15",
            lang_config={"require_path": "./math.js"},
        )
        r = execute_witness(spec, target)
        assert r.verdict == "confirmed", r.match_detail


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
            # Per the Perl prompt contract this is an error-MESSAGE
            # substring, not a type token.
            expected_exception="intentional failure",
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


def _unwrap_capped(cmd):
    """Executors wrap commands in the bounded-capture redirect
    (/bin/sh -c 'exec "$@" > cap 2> cap' argv0 cmd...) — return the
    inner command for assertions."""
    assert cmd[:2] == ["/bin/sh", "-c"], cmd
    assert 'exec "$@"' in cmd[2]
    return cmd[4:]


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
            _completed(stdout=json.dumps({"status": "returned", "token": "feedface", "value": "7"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")
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
        cmd = _unwrap_capped(cmd)
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
            _completed(stdout=json.dumps({"status": "returned", "token": "feedface", "value": "7"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")
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
        cmd = _unwrap_capped(cmd)
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
            _completed(stdout=json.dumps({"status": "returned", "token": "feedface", "value": "84"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")
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
        cmd = _unwrap_capped(cmd)
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
            _completed(stdout=json.dumps({"status": "returned", "token": "feedface", "value": "49"})),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")
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
        cmd = _unwrap_capped(cmd)
        assert cmd[0] == "/usr/bin/javac"
        # Classpath annotation processors must never execute at compile
        # time, even inside the sandbox.
        assert "-proc:none" in cmd
        assert kwargs["block_network"] is True
        assert "compile" in kwargs["caller_label"]
        run_cmd, _run_kwargs = spy.calls[1]
        run_cmd = _unwrap_capped(run_cmd)
        assert run_cmd[0] == "/usr/bin/java"


class TestAuditEvidencePersistence:
    """Under the sandbox CLI --audit flag, the tracer writes evidence
    into the call's audit target dir. Witness steps pass a throwaway
    scratch dir as output= — evidence there is destroyed on sweep — so
    the run's persistent output dir must travel as audit_run_dir= on
    EVERY witness step (compile and run)."""

    def _c_spec(self):
        return DarkWitnessSpec(
            finding_key="f1", file="add.c", function="add",
            language="c", expected_return="7",
            lang_config={
                "param_types": ["int", "int"], "return_type": "int",
                "arg_expressions": ["3", "4"], "includes": [],
                "setup_lines": [],
            },
        )

    def _target(self, base):
        base.mkdir(parents=True, exist_ok=True)
        (base / "add.c").write_text(
            "int add(int a, int b) { return a + b; }\n", encoding="utf-8",
        )
        return base

    def test_witness_steps_route_audit_evidence_to_run_dir(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.dark_verify import _execute as ex

        target = self._target(tmp_path / "src")
        run_dir = tmp_path / "run-out"
        run_dir.mkdir()
        spy = _SandboxSpy([
            _completed(),  # compile
            _completed(stdout=json.dumps(
                {"status": "returned", "token": "feedface", "value": "7"},
            )),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")

        r = execute_witness(self._c_spec(), target, audit_run_dir=run_dir)
        assert r.verdict == "confirmed"
        assert len(spy.calls) == 2
        for _cmd, kwargs in spy.calls:
            assert kwargs.get("audit_run_dir") == str(run_dir)
            # The persistent evidence dir is NOT the swept scratch.
            assert kwargs["audit_run_dir"] != kwargs.get("output")

    def test_missing_run_dir_does_not_cost_the_verdict(
        self, tmp_path, monkeypatch,
    ):
        # The sandbox raises ValueError for a nonexistent
        # audit_run_dir — a lost audit trail must degrade to the old
        # scratch-dir behaviour, never to an error verdict.
        from core.audit.dark_verify import _execute as ex

        target = self._target(tmp_path)
        spy = _SandboxSpy([
            _completed(),
            _completed(stdout=json.dumps(
                {"status": "returned", "token": "feedface", "value": "7"},
            )),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")

        r = execute_witness(
            self._c_spec(), target, audit_run_dir=tmp_path / "gone",
        )
        assert r.verdict == "confirmed"
        for _cmd, kwargs in spy.calls:
            assert "audit_run_dir" not in kwargs

    def test_unwritable_run_dir_does_not_cost_the_verdict(
        self, tmp_path, monkeypatch,
    ):
        # The sandbox's audit-target validation also rejects an
        # existing-but-unwritable dir with ValueError — same
        # degradation contract as a missing one.
        import os as os_mod

        from core.audit.dark_verify import _execute as ex

        target = self._target(tmp_path)
        run_dir = tmp_path / "run-out"
        run_dir.mkdir()
        run_dir.chmod(0o500)
        try:
            if os_mod.access(run_dir, os_mod.W_OK):
                pytest.skip("privileged user: chmod cannot revoke write")
            spy = _SandboxSpy([
                _completed(),
                _completed(stdout=json.dumps(
                    {"status": "returned", "token": "feedface",
                     "value": "7"},
                )),
            ])
            monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
            monkeypatch.setattr(
                ex.secrets, "token_hex", lambda n=8: "feedface",
            )

            r = execute_witness(
                self._c_spec(), target, audit_run_dir=run_dir,
            )
            assert r.verdict == "confirmed"
            for _cmd, kwargs in spy.calls:
                assert "audit_run_dir" not in kwargs
        finally:
            run_dir.chmod(0o700)

    def test_ambient_dir_reset_after_dispatch(self, tmp_path, monkeypatch):
        from core.audit.dark_verify import _execute as ex

        target = self._target(tmp_path)
        run_dir = tmp_path / "run-out"
        run_dir.mkdir()
        spy = _SandboxSpy([
            _completed(),
            _completed(stdout=json.dumps(
                {"status": "returned", "token": "feedface", "value": "7"},
            )),
        ])
        monkeypatch.setattr(ex, "_import_sandbox_run", lambda: spy)
        monkeypatch.setattr(ex.secrets, "token_hex", lambda n=8: "feedface")

        execute_witness(self._c_spec(), target, audit_run_dir=run_dir)
        assert ex._AUDIT_RUN_DIR.get() is None


class TestBoundedCapture:
    """Witness stdout/stderr reach the parent CAPPED, never as an
    unbounded in-memory pipe accumulation."""

    @staticmethod
    def _passthrough_sandbox(cmd, **kwargs):
        import subprocess as sp
        return sp.run(cmd, check=False)  # noqa: S603 — test-local echo of the sandbox shape

    def test_huge_stdout_is_capped_parent_side(self, tmp_path):
        from core.audit.dark_verify import _execute as ex

        proc = ex._sandbox_run_capped(
            self._passthrough_sandbox,
            [sys.executable, "-c", "print('x' * 1000000)"],
            cap_dir=tmp_path,
        )
        assert proc.returncode == 0
        assert proc.stdout.startswith("xxx")
        assert len(proc.stdout) <= 2 * ex._CAPTURE_CAP_BYTES + len(
            ex._TRUNCATION_MARKER,
        ), "parent-side stdout must be capped"

    def test_stderr_keeps_head_and_tail(self, tmp_path):
        from core.audit.dark_verify import _execute as ex

        code = (
            "import sys; sys.stderr.write('HEAD-MARKER\\n');"
            "sys.stderr.write('y' * 1000000);"
            "sys.stderr.write('\\nERROR: AddressSanitizer: "
            "heap-buffer-overflow tail\\n')"
        )
        proc = ex._sandbox_run_capped(
            self._passthrough_sandbox,
            [sys.executable, "-c", code],
            cap_dir=tmp_path,
        )
        assert "HEAD-MARKER" in proc.stderr, "sentinel head must survive"
        assert "AddressSanitizer" in proc.stderr, "report tail must survive"
        assert len(proc.stderr) <= 2 * ex._CAPTURE_CAP_BYTES + len(
            ex._TRUNCATION_MARKER,
        )
        # stderr-derived classification re-merged for the witness
        # outcome adapter.
        info = getattr(proc, "sandbox_info", None) or {}
        assert info.get("sanitizer") == "asan"

    def test_exit_code_passes_through_exec(self, tmp_path):
        from core.audit.dark_verify import _execute as ex

        proc = ex._sandbox_run_capped(
            self._passthrough_sandbox,
            [sys.executable, "-c", "raise SystemExit(7)"],
            cap_dir=tmp_path,
        )
        assert proc.returncode == 7

    def test_stub_runner_inline_capture_untouched(self, tmp_path):
        from core.audit.dark_verify import _execute as ex

        canned = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"status": "ok"}', stderr="",
        )
        proc = ex._sandbox_run_capped(
            lambda cmd, **kw: canned, ["true"], cap_dir=tmp_path,
        )
        assert proc.stdout == '{"status": "ok"}'


class TestAnchoredCapture:
    """Marker-anchored stderr retention + truncation classification.

    Positional head/tail capture alone let attacker-controlled stderr
    padding evict the harness sentinel and the sanitizer report from
    the window classification sees — flipping genuine crashes to
    inconclusive (suppression direction) from stderr content alone.
    The FULL stream is now scanned for the sentinel (token-bearing)
    and the sanitizer-family marker, and a truncated stream missing
    the markers a verdict hangs on classifies as ``error`` (re-run
    with a larger cap), never a silent inconclusive/clean."""

    _TOKEN = "feedface"

    @staticmethod
    def _passthrough_sandbox(cmd, **kwargs):
        import subprocess as sp
        return sp.run(cmd, check=False)  # noqa: S603 — test-local echo of the sandbox shape

    def _classify(self, tmp_path, code, spec):
        anchors = (
            (ex._CALL_MARKER_PREFIX + self._TOKEN).encode(),
            ex._SANITIZER_ANCHOR,
        )
        proc = ex._sandbox_run_capped(
            self._passthrough_sandbox,
            [sys.executable, "-c", code],
            cap_dir=tmp_path,
            stderr_anchors=anchors,
        )
        return ex._classify_native_output(
            spec, proc, getattr(proc, "sandbox_info", None), "c",
            expected_token=self._TOKEN,
        )

    def test_padding_cannot_evict_sentinel_or_report(self, tmp_path):
        """>64KiB of target-printed padding before the sentinel and
        around the ASan report pushed both into the evicted middle
        window — a genuine crash read inconclusive."""
        sentinel = ex._CALL_MARKER_PREFIX + self._TOKEN
        code = (
            "import sys, os\n"
            "w = sys.stderr.write\n"
            "w('P' * 200000)\n"
            f"w('\\n{sentinel}\\n')\n"
            "w('Q' * 200000)\n"
            "w('\\nERROR: AddressSanitizer: heap-buffer-overflow "
            "on address 0x0000\\n')\n"
            "w('R' * 200000)\n"
            "sys.stderr.flush()\n"
            "os.abort()\n"
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_sanitizer="heap-buffer-overflow",
        )
        r = self._classify(tmp_path, code, spec)
        assert r.verdict == "confirmed", r.match_detail

    def test_truncation_without_sentinel_is_error(self, tmp_path):
        """Truncated stream, sentinel nowhere in it: its absence
        proves nothing — must be ``error``, not a silent
        inconclusive."""
        code = (
            "import sys, os\n"
            "sys.stderr.write('P' * 300000)\n"
            "sys.stderr.flush()\n"
            "os.abort()\n"
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_crash=True,
        )
        r = self._classify(tmp_path, code, spec)
        assert r.verdict == "error", r.match_detail
        assert "re-run" in r.match_detail

    def test_truncated_stream_missing_predicted_sanitizer_is_error(self):
        """Predicted sanitizer + truncated stream with no sanitizer
        text anywhere: the report may sit in the dropped bytes —
        ``error``, never a bare EXIT_SIGNAL inconclusive."""
        stderr = (
            "head" + ex._TRUNCATION_MARKER
            + ex._CALL_MARKER_PREFIX + self._TOKEN + "\ntail"
        )
        proc = subprocess.CompletedProcess(
            args=[], returncode=-6, stdout="", stderr=stderr,
        )
        proc.stderr_truncated = True
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_sanitizer="heap-buffer-overflow",
        )
        r = ex._classify_native_output(
            spec, proc,
            {"signal": "SIGABRT", "signal_num": 6, "crashed": True},
            "c", expected_token=self._TOKEN,
        )
        assert r.verdict == "error", r.match_detail

    def test_untruncated_missing_sentinel_stays_inconclusive(self):
        """No truncation → the sentinel's absence is real evidence of
        a setup-phase failure; the existing inconclusive stands."""
        proc = subprocess.CompletedProcess(
            args=[], returncode=-11, stdout="", stderr="short noise\n",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="f", language="c",
            expected_crash=True,
        )
        r = ex._classify_native_output(
            spec, proc,
            {"signal": "SIGSEGV", "signal_num": 11, "crashed": True},
            "c", expected_token=self._TOKEN,
        )
        assert r.verdict == "inconclusive"
        assert "sentinel absent" in r.match_detail

    def test_anchor_windows_bounded_under_marker_spam(self, tmp_path):
        """A stream spamming the sanitizer marker cannot balloon the
        retained text: only first/last hit windows are kept."""
        stream = tmp_path / "err"
        with open(stream, "wb") as f:
            for _ in range(20000):
                f.write(b"AddressSanitizer spam line\n")
        text, truncated = ex._read_capped(
            stream, keep_tail=True, anchors=(ex._SANITIZER_ANCHOR,),
        )
        assert truncated
        budget = (
            2 * ex._CAPTURE_CAP_BYTES
            + 4 * ex._ANCHOR_HITS_KEPT
            * (ex._ANCHOR_PRE_CONTEXT + ex._ANCHOR_POST_CONTEXT)
            + 64 * len(ex._TRUNCATION_MARKER)
        )
        assert len(text) <= budget

    def test_anchored_windows_survive_in_stream_order(self, tmp_path):
        stream = tmp_path / "err"
        sentinel = ex._CALL_MARKER_PREFIX + self._TOKEN
        with open(stream, "wb") as f:
            f.write(b"P" * 200000)
            f.write(b"\n" + sentinel.encode() + b"\n")
            f.write(b"Q" * 200000)
            f.write(b"\nERROR: AddressSanitizer: heap-buffer-overflow\n")
            f.write(b"R" * 200000)
        text, truncated = ex._read_capped(
            stream, keep_tail=True,
            anchors=(sentinel.encode(), ex._SANITIZER_ANCHOR),
        )
        assert truncated
        at_sentinel = text.find(sentinel)
        at_report = text.find("ERROR: AddressSanitizer")
        assert at_sentinel >= 0 and at_report >= 0
        assert at_sentinel < at_report, "stream order must be preserved"


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
            and node.func.id == "_sandbox_run_capped"
        ]
        # _sandboxed_compile's inner call, the script witness, the
        # native run, and the Java run step — all via the bounded-
        # capture wrapper.
        assert len(call_sites) >= 4
        for call in call_sites:
            kwargs = {kw.arg: kw.value for kw in call.keywords}
            assert "restrict_reads" in kwargs, (
                f"_sandbox_run_capped call at line {call.lineno} omits "
                f"restrict_reads"
            )
            value = kwargs["restrict_reads"]
            assert isinstance(value, ast.Constant) and value.value is True, (
                f"_sandbox_run_capped call at line {call.lineno} must "
                f"pass restrict_reads=True"
            )
        # The only raw sandbox_run invocation is the wrapper's own
        # pass-through (isolation kwargs arrive via **kwargs there).
        raw_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "sandbox_run"
        ]
        assert len(raw_calls) == 1, (
            "executor sandbox calls must route through the bounded-"
            "capture wrapper"
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

    def test_never_grants_cargo_home(self, tmp_path, monkeypatch):
        # The rustup proxy fallback resolves rustc to
        # <cargo-home>/bin/rustc; a parent-dir grant there would expose
        # the registry credential store to target-derived code (compile
        # steps honour include_str! and witness stdout is persisted).
        home = tmp_path / "home" / "user"
        cargo = home / ".cargo"
        bin_dir = cargo / "bin"
        bin_dir.mkdir(parents=True)
        tool = bin_dir / "rustc"
        tool.write_text("#!/bin/sh\n")
        (cargo / "credentials.toml").write_text("[registry]\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("CARGO_HOME", raising=False)

        paths = _toolchain_read_paths(str(tool))
        assert str(bin_dir) in paths
        assert str(cargo) not in paths

    def test_never_grants_credential_bearing_parent(
        self, tmp_path, monkeypatch,
    ):
        # A relocated cargo home is recognised by the credential file
        # it directly holds, not only by its default location.
        root = tmp_path / "toolhome"
        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True)
        tool = bin_dir / "rustc"
        tool.write_text("#!/bin/sh\n")
        (root / "credentials").write_text('token = "x"\n')
        monkeypatch.delenv("CARGO_HOME", raising=False)

        paths = _toolchain_read_paths(str(tool))
        assert str(bin_dir) in paths
        assert str(root) not in paths

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


class TestSandboxExecPath:
    """The mount-ns backend resolves argv[0] literally inside the new
    rootfs — a which()-resolved symlink outside every mounted root is
    ENOENT there even when its target is mounted. `_sandbox_exec_path`
    swaps in the resolved target ONLY when the literal path is
    uncovered, the target is already covered (system prefix or an
    explicit grant), and the basename is unchanged. It never adds a
    grant."""

    @staticmethod
    def _system_env() -> str:
        env_bin = shutil.which("env")
        assert env_bin and any(
            env_bin.startswith(p) for p in ex._SYSTEM_TOOLCHAIN_PREFIXES)
        if os.path.basename(os.path.realpath(env_bin)) != "env":
            pytest.skip(
                "multi-call env binary; basename-changing rewrite is "
                "refused by design")
        return env_bin

    def test_rewrites_out_of_tree_symlink_to_system_target(self, tmp_path):
        env_bin = self._system_env()
        shim = tmp_path / "shims" / "env"
        shim.parent.mkdir()
        shim.symlink_to(env_bin)
        assert _sandbox_exec_path(str(shim), []) == os.path.realpath(env_bin)

    def test_rewrites_multi_hop_chain_to_system_target(self, tmp_path):
        # rustup-style: toolchain bin/ symlinks a system compiler that
        # is itself a symlink (/usr/bin/X -> ../lib/.../X). Every hop
        # collapses to the final real file under the system prefix.
        env_bin = self._system_env()
        hop = tmp_path / "hop" / "env"
        hop.parent.mkdir()
        hop.symlink_to(env_bin)
        shim = tmp_path / "shims" / "env"
        shim.parent.mkdir()
        shim.symlink_to(hop)
        assert _sandbox_exec_path(str(shim), []) == os.path.realpath(env_bin)

    def test_rewrites_symlink_into_granted_root(self, tmp_path):
        # Version-manager shape: a shim dir symlinks the real install;
        # _toolchain_read_paths grants the RESOLVED bin dir + parent,
        # so the target is covered while the shim dir is not.
        real_bin = tmp_path / "real" / "bin"
        real_bin.mkdir(parents=True)
        real = real_bin / "node"
        real.write_text("#!/bin/sh\n")
        shim = tmp_path / "shims" / "node"
        shim.parent.mkdir()
        shim.symlink_to(real)
        granted = [str(real_bin), str(real_bin.parent)]
        assert _sandbox_exec_path(str(shim), granted) == str(real)

    def test_keeps_literal_system_path(self):
        # A system-prefix literal is always visible in-sandbox; it is
        # never rewritten — even when it resolves elsewhere (merged-usr
        # /bin/sh, argv[0]-dispatching proxies under /usr).
        assert _sandbox_exec_path("/bin/sh", []) == "/bin/sh"

    def test_keeps_covered_literal_symlink(self, tmp_path):
        # A symlink inside a granted root is visible in-sandbox as-is;
        # keep the literal path (argv[0] semantics preserved).
        env_bin = shutil.which("env")
        assert env_bin
        shim_dir = tmp_path / "shims"
        shim_dir.mkdir()
        shim = shim_dir / "env"
        shim.symlink_to(env_bin)
        assert _sandbox_exec_path(str(shim), [str(shim_dir)]) == str(shim)

    def test_hostile_chain_outside_grants_unchanged(self, tmp_path):
        # Unit form: a chain ending outside system prefixes AND every
        # grant is returned unchanged — no rewrite ever points at an
        # uncovered file. (Real call sites derive `granted` from the
        # resolved target; the call-site-shaped pins follow.)
        evil = tmp_path / "elsewhere" / "tool"
        evil.parent.mkdir()
        evil.write_text("#!/bin/sh\n")
        shim = tmp_path / "shims" / "tool"
        shim.parent.mkdir()
        shim.symlink_to(evil)
        assert _sandbox_exec_path(str(shim), []) == str(shim)

    def test_home_resident_target_unchanged_with_call_site_grants(
        self, tmp_path, monkeypatch,
    ):
        # Call-site shape: `granted` comes from _toolchain_read_paths,
        # which refuses $HOME itself and its ancestors. A chain ending
        # directly in $HOME therefore earns no grant and is never
        # rewritten — the grant derivation, not this helper, is the
        # refusing authority.
        home = tmp_path / "home" / "user"
        home.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        target = home / "node"
        target.write_text("#!/bin/sh\n")
        shim = tmp_path / "shims" / "node"
        shim.parent.mkdir()
        shim.symlink_to(target)
        granted = _toolchain_read_paths(str(shim))
        assert granted == []
        assert _sandbox_exec_path(str(shim), granted) == str(shim)

    def test_call_site_grants_cover_version_manager_target(
        self, tmp_path, monkeypatch,
    ):
        # Call-site shape, positive direction: the grant derivation
        # approves an ordinary user-local install root (version manager
        # under a $HOME subdirectory), so the rewrite proceeds — to the
        # same file the operator's PATH already designated, under
        # grants identical to the pre-rewrite ones. The property pinned
        # here is "no new grants", not "user-local chains are blocked".
        home = tmp_path / "home" / "user"
        install_bin = home / ".mgr" / "versions" / "v1" / "bin"
        install_bin.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        real = install_bin / "node"
        real.write_text("#!/bin/sh\n")
        shim = tmp_path / "shims" / "node"
        shim.parent.mkdir()
        shim.symlink_to(real)
        granted = _toolchain_read_paths(str(shim))
        assert str(install_bin) in granted
        assert _sandbox_exec_path(str(shim), granted) == str(real)

    def test_no_rewrite_on_basename_change(self, tmp_path):
        # busybox-applet shape: /shims/gzip -> multi-call binary. The
        # target dispatches on argv[0]; invoking it under the resolved
        # name would run the wrong tool.
        env_bin = shutil.which("env")
        assert env_bin
        shim = tmp_path / "shims" / "gzip"
        shim.parent.mkdir()
        shim.symlink_to(env_bin)
        assert _sandbox_exec_path(str(shim), []) == str(shim)

    def test_keeps_running_interpreter_symlink(self, tmp_path):
        # venv shape: python derives sys.prefix from the literal
        # symlink location, and python_runtime_tool_paths grants it.
        shim = tmp_path / "venv-bin" / "python"
        shim.parent.mkdir()
        shim.symlink_to(sys.executable)
        assert _sandbox_exec_path(str(shim), []) == str(shim)

    def test_relative_and_empty_unchanged(self):
        assert _sandbox_exec_path("", []) == ""
        assert _sandbox_exec_path("node", []) == "node"


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
# -- return-value comparison ----------------------------------------------------


class TestReturnValueComparison:
    """Return comparison is exact except for cross-language boolean/nil
    spellings — a blanket case-fold flipped refuted to confirmed for any
    case-differing string pair."""

    def _returned(self, value):
        return json.dumps({"status": "returned", "value": value})

    def _spec(self, expected, file="a.go", language="go"):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="F",
            language=language, expected_return=expected,
        )

    def test_case_differing_strings_refute(self):
        r = _classify_output(
            self._spec("Admin"), self._returned("admin"), "go")
        assert r.verdict == "refuted"

    def test_case_differing_quoted_strings_refute(self):
        r = _classify_output(
            self._spec("admin"), self._returned('"ADMIN"'), "ruby")
        assert r.verdict == "refuted"

    def test_exact_string_confirms(self):
        r = _classify_output(
            self._spec("admin"), self._returned("admin"), "go")
        assert r.verdict == "confirmed"

    @pytest.mark.parametrize("expected,actual", [
        ("True", "true"),    # Python-style prediction vs Go %v
        ("False", "false"),
        ("Nil", "nil"),
        ("Null", "null"),
        ("None", "none"),
    ])
    def test_boolean_spellings_fold_case(self, expected, actual):
        r = _classify_output(
            self._spec(expected), self._returned(actual), "go")
        assert r.verdict == "confirmed"

    def test_different_boolean_words_still_refute(self):
        r = _classify_output(
            self._spec("None"), self._returned("nil"), "go")
        assert r.verdict == "refuted"

    def test_python_repr_comparison_is_case_sensitive(self):
        r = _classify_output(
            self._spec("abc", file="a.py", language="python"),
            self._returned("'ABC'"), "python")
        assert r.verdict == "refuted"


# -- execute_witness source-path containment -----------------------------------


class TestExecuteWitnessSourcePathContainment:
    """spec.file joins the target root and is later read UNSANDBOXED by
    the Go/Rust executors — absolute values, traversal and repo-planted
    symlinks pointing out of the tree must be rejected up front."""

    def _spec(self, file, language=""):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language=language,
        )

    def test_absolute_path_rejected(self, tmp_path):
        r = execute_witness(self._spec("/etc/hostname", "ruby"), tmp_path)
        assert r.verdict == "error"
        assert "escapes target root" in r.match_detail

    def test_traversal_rejected(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        secret = tmp_path / "secret.rb"
        secret.write_text("def check; end\n", encoding="utf-8")
        r = execute_witness(self._spec("../secret.rb"), root)
        assert r.verdict == "error"
        assert "escapes target root" in r.match_detail

    def test_symlink_escape_rejected(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        secret = tmp_path / "secret.rb"
        secret.write_text("def check; end\n", encoding="utf-8")
        (root / "link.rb").symlink_to(secret)
        r = execute_witness(self._spec("link.rb"), root)
        assert r.verdict == "error"
        assert "escapes target root" in r.match_detail

    def test_in_root_symlink_not_rejected(self, tmp_path):
        real = tmp_path / "real.rb"
        real.write_text("def check; end\n", encoding="utf-8")
        (tmp_path / "link.rb").symlink_to(real)
        r = execute_witness(self._spec("link.rb"), tmp_path)
        assert "escapes target root" not in r.match_detail

    def test_missing_file_still_reported_as_not_found(self, tmp_path):
        r = execute_witness(self._spec("nope.rb"), tmp_path)
        assert r.verdict == "error"
        assert "not found" in r.match_detail


# -- validate_spec load-path fields --------------------------------------------


class TestValidateSpecLoadPaths:
    """require_path / use_path / use_module / import_path feed module
    resolution rooted at the target tree — absolute values, '..' and
    (with a target_root) symlinked escapes must all be rejected."""

    def _spec(self, lang_config, language="ruby", file="a.rb"):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language=language, lang_config=lang_config,
        )

    @pytest.mark.parametrize("field,language,file,value", [
        ("require_path", "ruby", "a.rb", "../../etc/evil"),
        ("require_path", "javascript", "a.js", "./../evil"),
        ("use_path", "rust", "a.rs", "lib/../../evil"),
        ("use_module", "perl", "A.pm", "Foo::..::Bar"),
        ("import_path", "go", "a.go", "pkg/../../evil"),
    ])
    def test_traversal_rejected(self, field, language, file, value):
        err = validate_spec(self._spec({field: value}, language, file))
        assert err is not None
        assert field in err

    @pytest.mark.parametrize("field,language,file", [
        ("require_path", "ruby", "a.rb"),
        ("import_path", "go", "a.go"),
    ])
    def test_absolute_rejected(self, field, language, file):
        err = validate_spec(
            self._spec({field: "/etc/passwd"}, language, file))
        assert err is not None
        assert field in err

    @pytest.mark.parametrize("hostile", [
        "#{`touch /tmp/x`}",        # Ruby interpolation
        "$injected",                # PHP interpolation
        "lib'; system('x'); '",     # quote breakout
        "a b",                      # whitespace
        "x\ny",                     # newline
    ])
    def test_require_path_charset_rejected(self, hostile):
        err = validate_spec(self._spec({"require_path": hostile}))
        assert err is not None
        assert "require_path" in err

    @pytest.mark.parametrize("field,language,file,value", [
        ("require_path", "ruby", "lib/auth.rb", "lib/auth"),
        ("require_path", "javascript", "parser.js", "./parser.js"),
        ("require_path", "lua", "lib/auth.lua", "lib.auth"),
        ("use_path", "rust", "a.rs", "std::collections::HashMap"),
        ("use_module", "perl", "MathUtil.pm", "MathUtil"),
        # Go import paths are exercised in TestGoImportBinding — the
        # binding needs a readable go.mod, which this fixture lacks.
    ])
    def test_legitimate_values_pass(self, field, language, file, value):
        assert validate_spec(self._spec({field: value}, language, file)) is None

    def test_require_path_symlink_escape_rejected(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        root = tmp_path / "root"
        root.mkdir()
        (root / "esc").symlink_to(outside)
        spec = self._spec({"require_path": "esc/mod"}, file="esc/mod.rb")
        assert validate_spec(spec) is None  # lexically clean
        err = validate_spec(spec, root)
        assert err is not None
        assert "escapes target root" in err

    def test_confined_require_path_passes_with_root(self, tmp_path):
        spec = self._spec({"require_path": "lib/auth"}, file="lib/auth.rb")
        assert validate_spec(spec, tmp_path) is None

    def test_execute_witness_rejects_traversal_require_path(self, tmp_path):
        src = tmp_path / "a.rb"
        src.write_text("def check; end\n", encoding="utf-8")
        spec = self._spec({"require_path": "../../evil"})
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert "spec validation failed" in r.match_detail


class TestModuleBindingToFindingFile:
    """The module reference must resolve to the finding's FILE: a
    witness pointed at a lookalike in-tree module exporting a
    same-named function would execute the wrong code and mint
    confirmed/refuted for the original finding."""

    @staticmethod
    def _spec(field, value, language, file):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language=language, lang_config={field: value},
        )

    @pytest.mark.parametrize("field,language,file,wrong", [
        ("require_path", "javascript", "src/auth.js", "./src/lookalike"),
        ("require_path", "typescript", "src/auth.ts", "./src/lookalike"),
        # Stem spelling: Node's LOAD_AS_FILE tries the EXTENSIONLESS
        # path first, so a repo-planted file named `src/auth` (loaded
        # as CJS) shadows `src/auth.js` — and under the TS loaders a
        # planted `src/auth.js` shadows `src/auth.ts` (`.js` resolves
        # before `.ts`). Only the exact file path binds.
        ("require_path", "javascript", "src/auth.js", "./src/auth"),
        ("require_path", "typescript", "src/auth.ts", "./src/auth"),
        # Directory/index spelling: directory resolution consults a
        # repo-plantable package.json "main" BEFORE index files.
        ("require_path", "javascript", "src/auth/index.js", "./src/auth"),
        ("require_path", "ruby", "lib/auth.rb", "lib/lookalike"),
        ("require_path", "php", "src/auth.php", "src/lookalike.php"),
        ("require_path", "lua", "lib/auth.lua", "lib.lookalike"),
        # Dotted DIRNAME: require "a.b.c" resolves to a/b/c.lua (every
        # dot maps to a separator), NOT the finding's a.b/c.lua — the
        # spelling-direction check accepted this plantable lookalike.
        ("require_path", "lua", "a.b/c.lua", "a.b.c"),
        # Dotted FILENAME stem: same resolution ambiguity.
        ("require_path", "lua", "lib/auth.spec.lua", "lib.auth.spec"),
        ("use_module", "perl", "lib/Auth.pm", "lib::Lookalike"),
    ])
    def test_wrong_module_rejected(self, field, language, file, wrong):
        err = validate_spec(self._spec(field, wrong, language, file))
        assert err is not None
        assert "not bound to the finding's file" in err

    def test_lua_dotted_stem_has_no_derived_default(self):
        # With no override the harness derives the dotted spelling
        # from the stem — for a dotted-dirname file that inherits the
        # SAME ambiguity (a.b/c.lua -> "a.b.c" -> a/b/c.lua), so the
        # spec is rejected before anything executes.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.b/c.lua", function="check",
            language="lua", lang_config={},
        )
        err = validate_spec(spec)
        assert err is not None
        assert "no unambiguous" in err

    def test_lua_clean_stem_keeps_derived_default(self):
        # Both directions: a dot-free stem stays on the derived
        # default with no override, exactly as before.
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="check",
            language="lua", lang_config={},
        )
        assert validate_spec(spec) is None

    @pytest.mark.parametrize("field,language,file,value", [
        ("require_path", "javascript", "src/auth.js", "./src/auth.js"),
        ("require_path", "javascript", "src/auth/index.js",
         "./src/auth/index.js"),
        ("require_path", "typescript", "src/auth.ts", "./src/auth.ts"),
        ("require_path", "ruby", "lib/auth.rb", "lib/auth"),
        ("require_path", "ruby", "lib/auth.rb", "lib/auth.rb"),
        ("require_path", "php", "src/auth.php", "src/auth.php"),
        ("require_path", "lua", "lib/auth.lua", "lib.auth"),
        # Dot-spelled directory module: require "lib.auth.init" maps to
        # lib/auth/init.lua through the ?.lua template — deterministic.
        ("require_path", "lua", "lib/auth/init.lua", "lib.auth.init"),
        ("use_module", "perl", "lib/Auth.pm", "lib::Auth"),
    ])
    def test_bound_module_accepted(self, field, language, file, value):
        assert validate_spec(self._spec(field, value, language, file)) is None

    def test_lua_init_directory_spelling_needs_vacant_sibling(
            self, tmp_path):
        # The harness's ?.lua template is tried BEFORE ?/init.lua, so
        # require "lib.auth" binds lib/auth/init.lua only when the
        # plantable sibling slot lib/auth.lua is verified vacant —
        # occupied means the loader picks the plant, no tree means the
        # slot cannot be verified at all.
        spec = self._spec(
            "require_path", "lib.auth", "lua", "lib/auth/init.lua")
        err = validate_spec(spec)
        assert err is not None
        assert "without the target tree" in err

        (tmp_path / "lib" / "auth").mkdir(parents=True)
        (tmp_path / "lib" / "auth" / "init.lua").write_text(
            "return { check = function() return 1 end }\n",
            encoding="utf-8")
        assert validate_spec(spec, tmp_path) is None

        (tmp_path / "lib" / "auth.lua").write_text(
            "return { check = function() return 99 end }\n",
            encoding="utf-8")
        err = validate_spec(spec, tmp_path)
        assert err is not None
        assert "shadow slot occupied" in err

    def test_empty_override_uses_derived_default(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="check",
            language="ruby", lang_config={},
        )
        assert validate_spec(spec) is None

    def test_wrong_module_witness_errors_not_verdicts(self, tmp_path):
        src = tmp_path / "lib"
        src.mkdir()
        (src / "auth.rb").write_text("def check; end\n", encoding="utf-8")
        (src / "lookalike.rb").write_text(
            "def check; true; end\n", encoding="utf-8",
        )
        spec = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="check",
            language="ruby", lang_config={"require_path": "lib/lookalike"},
        )
        r = execute_witness(spec, tmp_path)
        assert r.verdict == "error"
        assert r.verdict not in ("confirmed", "refuted")


class TestGoImportBinding:
    """Go resolves an import path by stripping the go.mod module
    prefix and mapping the remainder to a directory — the binding
    must hold in that RESOLUTION direction. The old suffix check
    accepted module-prefixed lookalikes and left root-package imports
    completely unchecked."""

    @staticmethod
    def _spec(file: str, ip: str):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="Check",
            language="go",
            lang_config={"package": "auth", "import_path": ip},
        )

    @staticmethod
    def _root(tmp_path, module_line="module example.com/m"):
        (tmp_path / "go.mod").write_text(
            f"{module_line}\n\ngo 1.21\n", encoding="utf-8",
        )
        return tmp_path

    def test_resolved_import_accepted(self, tmp_path):
        root = self._root(tmp_path)
        spec = self._spec("pkg/auth/a.go", "example.com/m/pkg/auth")
        assert validate_spec(spec, root) is None

    def test_module_prefixed_lookalike_rejected(self, tmp_path):
        # "example.com/m/x/a/b" ends with "/a/b" (the old suffix check
        # passed it) but Go resolves it to directory x/a/b — a
        # plantable lookalike package.
        root = self._root(tmp_path)
        spec = self._spec("a/b/f.go", "example.com/m/x/a/b")
        err = validate_spec(spec, root)
        assert err is not None
        assert "not bound to the finding's file" in err

    def test_bare_directory_spelling_rejected(self, tmp_path):
        # "pkg/auth" without the module prefix names a DIFFERENT
        # module under Go resolution.
        root = self._root(tmp_path)
        spec = self._spec("pkg/auth/a.go", "pkg/auth")
        err = validate_spec(spec, root)
        assert err is not None
        assert "not bound to the finding's file" in err

    def test_root_package_bound_to_module_path(self, tmp_path):
        # Root-package findings were previously not checked at all —
        # any package in the repo could be named.
        root = self._root(tmp_path)
        assert validate_spec(
            self._spec("a.go", "example.com/m"), root,
        ) is None
        err = validate_spec(
            self._spec("a.go", "example.com/m/pkg/evil"), root,
        )
        assert err is not None
        assert "not bound to the finding's file" in err

    def test_unreadable_go_mod_refuses(self, tmp_path):
        # No go.mod = no resolution to verify: refuse, never execute
        # (mirrors the dotted-Lua-stem refusal).
        spec = self._spec("pkg/auth/a.go", "example.com/m/pkg/auth")
        err = validate_spec(spec, tmp_path)
        assert err is not None
        assert "go.mod" in err

    def test_quoted_and_commented_module_lines_parse(self, tmp_path):
        root = self._root(
            tmp_path, 'module "example.com/m"  // legacy quoted form',
        )
        assert validate_spec(
            self._spec("pkg/auth/a.go", "example.com/m/pkg/auth"), root,
        ) is None

    def test_empty_import_path_stays_unchecked(self, tmp_path):
        # No import_path: the harness imports nothing (package-main
        # findings compile the target source directly).
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.go", function="Check",
            language="go", lang_config={},
        )
        assert validate_spec(spec, tmp_path) is None

    @pytest.mark.parametrize("alias", [
        'x"\n\nfunc init() { println("forged") }\nvar _ = "',
        "a b",
        "x;",
        "x\ny",
        "3x",
    ])
    def test_import_alias_injection_rejected(self, tmp_path, alias):
        # import_alias is pasted raw into the harness import block and
        # call prefix — anything beyond a single identifier is Go code
        # injection with verdict-forging reach.
        root = self._root(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/auth/a.go", function="Check",
            language="go",
            lang_config={
                "package": "auth",
                "import_path": "example.com/m/pkg/auth",
                "import_alias": alias,
            },
        )
        err = validate_spec(spec, root)
        assert err is not None
        assert "import_alias" in err

    def test_import_alias_identifier_accepted(self, tmp_path):
        root = self._root(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="f1", file="pkg/auth/a.go", function="Check",
            language="go",
            lang_config={
                "package": "auth",
                "import_path": "example.com/m/pkg/auth",
                "import_alias": "target",
            },
        )
        assert validate_spec(spec, root) is None


# -- resolution-direction engine: registry closure + shadow batteries ---------


class TestLaneBindingClosure:
    """Every supported language answers the module-binding question
    through the resolution engine — a lane outside the registry, or a
    registered lane validate_spec does not route through it, would
    re-open the per-lane drift the engine exists to close."""

    def test_registry_covers_every_supported_language(self):
        from core.audit.dark_verify import _resolve
        from core.audit.dark_verify._types import _SUPPORTED_LANGS
        assert set(_resolve._LANE_BINDINGS) == set(_SUPPORTED_LANGS)

    def test_every_lane_declares_a_binding_mode(self):
        from core.audit.dark_verify import _resolve
        for lang, lane in _resolve._LANE_BINDINGS.items():
            assert lane.mode in ("resolver", "structural"), lang
            if lane.mode == "resolver":
                assert lane.resolver is not None, lang
            else:
                # Structural lanes must NAME the mechanism that binds
                # the load without a loader search.
                assert lane.rationale, lang

    def test_unregistered_language_is_refused(self):
        from core.audit.dark_verify._resolve import binding_error
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.zig", function="check",
            language="zig",
        )
        err = binding_error(spec, "zig", None)
        assert err is not None and "no module-binding lane" in err

    def test_validate_spec_routes_through_the_engine(self, monkeypatch):
        # validate_spec must surface the engine's verdict for every
        # language — a lane that skips the engine call would fall back
        # to nothing at all.
        from core.audit.dark_verify import _execute
        from core.audit.dark_verify._types import _SUPPORTED_LANGS
        seen = []

        def sentinel(spec, lang, target_root=None):
            seen.append(lang)
            return f"engine sentinel for {lang}"

        monkeypatch.setattr(_execute, "binding_error", sentinel)
        by_lang = {
            "python": "a.py", "c": "a.c", "cpp": "a.cpp", "go": "a.go",
            "javascript": "a.js", "typescript": "a.ts", "ruby": "a.rb",
            "php": "a.php", "rust": "a.rs", "java": "A.java",
            "lua": "a.lua", "perl": "A.pm",
        }
        assert set(by_lang) == set(_SUPPORTED_LANGS)
        for lang, file in by_lang.items():
            spec = DarkWitnessSpec(
                finding_key="f1", file=file, function="check",
                language=lang,
            )
            err = _execute.validate_spec(spec)
            assert err == f"engine sentinel for {lang}", lang
        assert set(seen) == set(_SUPPORTED_LANGS)

    # One plantable-lookalike reference per resolver lane: the engine
    # must refuse each one, whatever the lane.  Module-level so the
    # coverage-totality test below derives its lane set from the SAME
    # rows the battery runs — a lane added here is exercised, a
    # resolver lane missing here fails the totality test.
    _LOOKALIKE_ROWS = [
        ("python", "src/auth.py", {}, "src.lookalike"),
        ("javascript", "src/auth.js", {"require_path": "./src/auth"}, ""),
        ("typescript", "src/auth.ts", {"require_path": "./src/auth"}, ""),
        ("ruby", "lib/auth.rb", {"require_path": "lib/lookalike"}, ""),
        ("php", "src/auth.php", {"require_path": "src/lookalike.php"}, ""),
        ("lua", "lib/auth.lua", {"require_path": "lib.lookalike"}, ""),
        ("perl", "lib/Auth.pm", {"use_module": "lib::Lookalike"}, ""),
        ("go", "pkg/a/f.go",
         {"package": "a", "import_path": "example.com/m/pkg/b"}, ""),
        ("java", "src/Auth.java",
         {"class_name": "Auth", "imports": ["com.evil.Auth"]}, ""),
    ]

    @pytest.mark.parametrize("lang,file,lang_config,module_path",
                             _LOOKALIKE_ROWS)
    def test_resolver_lanes_refuse_lookalikes(
            self, tmp_path, lang, file, lang_config, module_path):
        from core.audit.dark_verify._resolve import (
            _LANE_BINDINGS, binding_error,
        )
        assert _LANE_BINDINGS[lang].mode == "resolver"
        src = tmp_path / file
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("// finding\n", encoding="utf-8")
        if lang == "go":
            (tmp_path / "go.mod").write_text(
                "module example.com/m\n", encoding="utf-8")
        spec = DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language=lang, module_path=module_path,
            lang_config=lang_config,
        )
        assert binding_error(spec, lang, tmp_path) is not None

    def test_resolver_lane_coverage_is_total(self):
        # The lookalike battery above must cover every resolver lane;
        # a new resolver lane without a battery row fails here.  The
        # battery set is DERIVED from the parametrize rows, never
        # hand-duplicated — a lane listed here but absent from the
        # rows cannot pass vacuously.
        from core.audit.dark_verify._resolve import _LANE_BINDINGS
        battery = {row[0] for row in self._LOOKALIKE_ROWS}
        resolver_lanes = {
            lang for lang, lane in _LANE_BINDINGS.items()
            if lane.mode == "resolver"
        }
        assert battery == resolver_lanes

    def test_generator_derivations_are_engine_derivations(self):
        # The engine validates exactly the reference the generators
        # feed the loader — both sides call the same derivation
        # helper, asserted here against the rendered harness text.
        from core.audit.dark_verify import _resolve
        ruby = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.rb", function="check",
            language="ruby",
        )
        assert (_resolve.derive_ruby_require_path(ruby)
                in hy.generate_ruby_harness(ruby, Path("/t")))
        lua = DarkWitnessSpec(
            finding_key="f1", file="lib/auth.lua", function="check",
            language="lua",
        )
        assert (_resolve.derive_lua_require_path(lua)
                in hy.generate_lua_harness(lua, Path("/t")))
        perl = DarkWitnessSpec(
            finding_key="f1", file="lib/Auth.pm", function="check",
            language="perl",
        )
        assert (_resolve.derive_perl_use_module(perl)
                in hy.generate_perl_harness(perl, Path("/t")))
        js = DarkWitnessSpec(
            finding_key="f1", file="src/auth.js", function="check",
            language="javascript",
        )
        assert (json.dumps(_resolve.derive_js_require_path(js))
                in hy.generate_js_harness(js, Path("/t")))


class TestPythonPackageShadowBinding:
    """CPython resolves a regular PACKAGE before a same-named module:
    a repo-planted ``src/auth/__init__.py`` directory shadows the
    finding's ``src/auth.py``, so ``from src.auth import f`` executes
    the plant and mints a verdict for code that never ran."""

    def _spec(self, file="src/auth.py", module_path="src.auth"):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language="python", module_path=module_path,
        )

    def _tree(self, tmp_path, *, shadow):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth.py").write_text(
            "def check():\n    return 1\n", encoding="utf-8")
        if shadow:
            (tmp_path / "src" / "auth").mkdir()
            (tmp_path / "src" / "auth" / "__init__.py").write_text(
                "def check():\n    return 99\n", encoding="utf-8")
        return tmp_path

    def test_clean_tree_accepted(self, tmp_path):
        root = self._tree(tmp_path, shadow=False)
        assert validate_import_path(self._spec(), root) is None
        assert validate_spec(self._spec(), root) is None

    def test_package_shadow_refused(self, tmp_path):
        root = self._tree(tmp_path, shadow=True)
        err = validate_import_path(self._spec(), root)
        assert err is not None and "shadow" in err
        err = validate_spec(self._spec(), root)
        assert err is not None and "shadow" in err

    def test_shadowed_witness_errors_not_verdicts(self, tmp_path):
        root = self._tree(tmp_path, shadow=True)
        spec = DarkWitnessSpec(
            finding_key="f1", file="src/auth.py", function="check",
            language="python", module_path="src.auth",
            expected_return="99",
        )
        r = execute_witness(spec, root)
        assert r.verdict == "error"
        assert r.verdict not in ("confirmed", "refuted")

    def test_package_finding_outranks_module_plant(self, tmp_path):
        # A directory with an __init__ binds before any same-named
        # module file — a planted module file cannot shadow an
        # __init__.py finding (only an extension __init__ in the same
        # directory can, covered below).
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth").mkdir()
        (tmp_path / "src" / "auth" / "__init__.py").write_text(
            "def check():\n    return 1\n", encoding="utf-8")
        (tmp_path / "src" / "auth.py").write_text(
            "def check():\n    return 99\n", encoding="utf-8")
        spec = self._spec(file="src/auth/__init__.py",
                          module_path="src.auth")
        assert validate_import_path(spec, tmp_path) is None

    def test_shadow_check_requires_tree(self):
        # Without a target tree the shadow slot cannot be verified
        # vacant — fail closed, never assume.
        err = validate_spec(self._spec())
        assert err is not None and "without the target tree" in err


class TestPythonNamespaceParentShadowBinding:
    """CPython defers a PEP 420 namespace portion below every module
    and extension hit at the same level: for a finding ``pkg/mod.py``
    whose ``pkg/`` has no ``__init__.py``, a repo-planted ``pkg.py``
    binds the ``pkg`` name FIRST — its import-time code owns
    ``sys.modules['pkg.mod']`` before the finding's file is ever
    considered.  Intermediate components carry hijack direction at
    every namespace level."""

    def _spec(self, file="pkg/mod.py", module_path="pkg.mod", **kw):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language="python", module_path=module_path, **kw,
        )

    def _tree(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        return tmp_path

    def test_namespace_layout_accepted_when_vacant(self, tmp_path):
        root = self._tree(tmp_path)
        assert validate_spec(self._spec(), root) is None

    def test_namespace_parent_module_plant_refused(self, tmp_path):
        root = self._tree(tmp_path)
        (root / "pkg.py").write_text("# plant\n", encoding="utf-8")
        err = validate_spec(self._spec(), root)
        assert err is not None and "pkg.py" in err

    def test_deep_namespace_ancestor_plant_refused(self, tmp_path):
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a" / "b" / "mod.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        (tmp_path / "a" / "b.py").write_text("# plant\n", encoding="utf-8")
        err = validate_spec(
            self._spec(file="a/b/mod.py", module_path="a.b.mod"), tmp_path)
        assert err is not None and "a/b.py" in err

    def test_regular_package_parent_ignores_module_plant(self, tmp_path):
        # A regular package (own __init__.py) binds before a same-named
        # module file — the parent-level plant carries no hijack
        # direction there.
        root = self._tree(tmp_path)
        (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (root / "pkg.py").write_text("# plant\n", encoding="utf-8")
        assert validate_spec(self._spec(), root) is None

    def test_plain_sibling_dir_is_not_a_shadow(self, tmp_path):
        # The reverse layout: a bare directory named like the finding's
        # module is a namespace portion and LOSES to the module file —
        # must stay accepted.
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        (tmp_path / "src" / "auth").mkdir()
        (tmp_path / "src" / "auth" / ".keep").write_text("", encoding="utf-8")
        assert validate_spec(
            self._spec(file="src/auth.py", module_path="src.auth"),
            tmp_path) is None

    def test_hijacking_plant_errors_not_verdicts(self, tmp_path):
        # End to end: a plant that installs an impostor
        # sys.modules['pkg.mod'] with a FORGED __file__ would satisfy
        # both the from-import and the runtime __file__ belt — the
        # static gate must refuse it before anything executes.
        root = self._tree(tmp_path)
        (root / "pkg.py").write_text(
            "import sys, types, os.path\n"
            "_m = types.ModuleType('pkg.mod')\n"
            "_m.check = lambda: 7\n"
            "_m.__file__ = os.path.join("
            "os.path.dirname(__file__), 'pkg', 'mod.py')\n"
            "sys.modules['pkg.mod'] = _m\n", encoding="utf-8")
        r = execute_witness(self._spec(expected_return="7"), root)
        assert r.verdict == "error"
        assert r.verdict not in ("confirmed", "refuted")


class TestPythonExtensionSuffixShadowBinding:
    """CPython's FileFinder tries EXTENSION suffixes before ``.py``
    for the same name, and any ``__init__`` artifact makes a directory
    a regular package regardless of suffix — so a repo-planted
    ``pkg/mod.so`` (or ``pkg/mod/__init__.so``) binds ahead of the
    finding's ``pkg/mod.py``."""

    def _spec(self, file="pkg/mod.py", module_path="pkg.mod", **kw):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language="python", module_path=module_path, **kw,
        )

    def _tree(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "pkg" / "mod.py").write_text(
            "def check():\n    return 7\n", encoding="utf-8")
        return tmp_path

    def test_clean_tree_accepted(self, tmp_path):
        root = self._tree(tmp_path)
        assert validate_spec(self._spec(), root) is None

    @pytest.mark.parametrize("plant", [
        "pkg/mod.so",
        "pkg/mod.cpython-314-x86_64-linux-gnu.so",
        "pkg/mod.pyd",
        "pkg/mod/__init__.so",
        "pkg/mod/__init__.pyc",
    ])
    def test_extension_plant_refused(self, tmp_path, plant):
        root = self._tree(tmp_path)
        p = root / plant
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x7fELF-plant")
        err = validate_spec(self._spec(), root)
        assert err is not None and "shadow" in err

    def test_bytecode_ranks_after_source(self, tmp_path):
        # Sourceless bytecode for the SAME name is a later slot than
        # the finding's .py — not a shadow.
        root = self._tree(tmp_path)
        (root / "pkg" / "mod.pyc").write_bytes(b"\x00\x00\x00\x00")
        assert validate_spec(self._spec(), root) is None

    def test_package_finding_extension_init_plant_refused(self, tmp_path):
        # An __init__.py finding is outranked by an extension init in
        # its own directory.
        root = self._tree(tmp_path)
        (root / "pkg" / "__init__.so").write_bytes(b"\x7fELF-plant")
        err = validate_spec(
            self._spec(file="pkg/__init__.py", module_path="pkg"), root)
        assert err is not None and "shadow" in err

    def test_regular_package_ancestor_extension_init_refused(self, tmp_path):
        # Even a regular-package ancestor keeps one plantable slot: an
        # extension __init__ outranks its source __init__.
        root = self._tree(tmp_path)
        (root / "pkg" / "__init__.so").write_bytes(b"\x7fELF-plant")
        err = validate_spec(self._spec(), root)
        assert err is not None and "shadow" in err

    def test_extension_plant_errors_not_verdicts(self, tmp_path):
        # End to end: a valid planted extension module loads AS
        # pkg.mod with in-process control of __file__ — the static
        # gate must refuse before the interpreter ever sees it.
        root = self._tree(tmp_path)
        (root / "pkg" / "mod.so").write_bytes(b"\x7fELF-plant")
        r = execute_witness(self._spec(expected_return="7"), root)
        assert r.verdict == "error"
        assert r.verdict not in ("confirmed", "refuted")


class TestNativeSuffixOrderingOtherLanes:
    """The extension-suffix shadow class, checked across the other
    resolver lanes: Ruby resolves ``.rb`` across the load path before
    native suffixes, Lua's package.path searcher runs before the
    C-library searcher, and Node's suffix ladder only starts after the
    exact-path hit — so a planted native artifact never outranks the
    accepted reference, and these lanes stay accept."""

    @pytest.mark.parametrize("lang,file,lang_config,plant", [
        ("ruby", "lib/auth.rb", {"require_path": "lib/auth"},
         "lib/auth.so"),
        ("lua", "lib/auth.lua", {"require_path": "lib.auth"},
         "lib/auth.so"),
        ("javascript", "src/auth.js", {"require_path": "./src/auth.js"},
         "src/auth.node"),
        ("javascript", "src/auth.js", {"require_path": "./src/auth.js"},
         "src/auth.json"),
    ])
    def test_native_plant_does_not_shadow(
            self, tmp_path, lang, file, lang_config, plant):
        from core.audit.dark_verify._resolve import binding_error
        src = tmp_path / file
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("-- finding\n", encoding="utf-8")
        (tmp_path / plant).write_bytes(b"\x7fELF-plant")
        spec = DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language=lang, lang_config=lang_config,
        )
        assert binding_error(spec, lang, tmp_path) is None


class TestPerlBarewordResolution:
    """``require Bareword`` maps ``::`` to ``/`` and appends ``.pm``
    ONLY — no bareword spelling can ever load a ``.pl`` finding; the
    loader would bind a same-stem ``.pm`` plant instead."""

    def _spec(self, file, use_module=""):
        lc = {"use_module": use_module} if use_module else {}
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language="perl", lang_config=lc,
        )

    def test_pl_finding_refused_on_derived_default(self):
        err = validate_spec(self._spec("lib/auth.pl"))
        assert err is not None
        assert "declining to verify" in err

    def test_pl_finding_refused_on_explicit_module(self):
        err = validate_spec(self._spec("lib/auth.pl", "lib::auth"))
        assert err is not None
        assert "declining to verify" in err

    def test_pl_lookalike_pm_never_reached(self, tmp_path):
        # The exact plant shape: same-stem .pm next to the .pl finding.
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "auth.pl").write_text(
            "sub check { return 1; }\n1;\n", encoding="utf-8")
        (tmp_path / "lib" / "auth.pm").write_text(
            "sub check { return 99; }\n1;\n", encoding="utf-8")
        r = execute_witness(self._spec("lib/auth.pl"), tmp_path)
        assert r.verdict == "error"
        assert r.verdict not in ("confirmed", "refuted")

    def test_pm_finding_still_accepted(self):
        assert validate_spec(self._spec("lib/Auth.pm", "lib::Auth")) is None
        assert validate_spec(self._spec("lib/Auth.pm")) is None


class TestJavaImportBinding:
    """The harness's class reference resolves through javac's
    simple-name rules: a single-type import whose terminal name is the
    finding's class stem re-binds every reference to whatever class it
    names on the whole-tree compile classpath — the import must be the
    finding's own package-qualified name, derived from the file's
    package declaration, or the spec is refused."""

    def _spec(self, file="src/Auth.java", imports=(), class_name="Auth"):
        return DarkWitnessSpec(
            finding_key="f1", file=file, function="check",
            language="java",
            lang_config={
                "class_name": class_name,
                "imports": list(imports),
                "arg_expressions": [],
            },
        )

    def _tree(self, tmp_path, package="com.example"):
        src = tmp_path / "src" / "Auth.java"
        src.parent.mkdir(parents=True, exist_ok=True)
        decl = f"package {package};\n" if package else ""
        src.write_text(
            decl + "public class Auth {\n"
            "    public static int check() { return 1; }\n"
            "}\n", encoding="utf-8")
        return tmp_path

    def test_lookalike_import_refused(self, tmp_path):
        root = self._tree(tmp_path)
        err = validate_spec(
            self._spec(imports=["com.evil.Auth"]), root)
        assert err is not None and "not bound" in err

    def test_own_package_import_accepted(self, tmp_path):
        root = self._tree(tmp_path)
        assert validate_spec(
            self._spec(imports=["com.example.Auth"]), root) is None

    def test_packaged_class_requires_its_import(self, tmp_path):
        # Without the single-type import the harness's reference can
        # only resolve through an on-demand import — a channel a
        # planted package on the whole-tree classpath can serve.
        root = self._tree(tmp_path)
        err = validate_spec(self._spec(imports=[]), root)
        assert err is not None and "single-type import" in err

    def test_default_package_rejects_stem_imports(self, tmp_path):
        # The default package cannot be imported (JLS 7.5.1) — a stem
        # import can only name a lookalike.
        root = self._tree(tmp_path, package="")
        err = validate_spec(
            self._spec(imports=["com.evil.Auth"]), root)
        assert err is not None and "default package" in err

    def test_default_package_plain_spec_accepted(self, tmp_path):
        root = self._tree(tmp_path, package="")
        assert validate_spec(
            self._spec(imports=["java.util.HashMap"]), root) is None

    def test_static_stem_import_refused(self, tmp_path):
        # `import static com.evil.Util.Auth` binds a member (or nested
        # type) named like the stem — never the finding's class.
        root = self._tree(tmp_path)
        err = validate_spec(
            self._spec(imports=["com.example.Auth",
                                "static com.evil.Util.Auth"]), root)
        assert err is not None and "not bound" in err

    def test_on_demand_imports_stay_allowed(self, tmp_path):
        # On-demand imports are shadowed by both single-type imports
        # and same-package types (JLS 6.4.1) — they cannot re-bind the
        # stem once the single-type discipline holds.
        root = self._tree(tmp_path)
        assert validate_spec(
            self._spec(imports=["com.example.Auth", "java.util.*"]),
            root) is None

    def test_comment_wrapped_package_decl_parses(self, tmp_path):
        src = tmp_path / "src" / "Auth.java"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(
            "/* copyright\n * package com.wrong; in prose\n */\n"
            "// package com.also.wrong;\n"
            "package com.example;\n"
            "public class Auth { public static int check()"
            " { return 1; } }\n", encoding="utf-8")
        assert validate_spec(
            self._spec(imports=["com.example.Auth"]), tmp_path) is None
        err = validate_spec(
            self._spec(imports=["com.wrong.Auth"]), tmp_path)
        assert err is not None

    def test_unreadable_finding_file_refused(self, tmp_path):
        # No package declaration to resolve against = decline.
        err = validate_spec(
            self._spec(imports=["com.example.Auth"]), tmp_path)
        assert err is not None and "declining to verify" in err

    def test_stem_import_without_tree_refused(self):
        err = validate_spec(self._spec(imports=["com.evil.Auth"]))
        assert err is not None and "without the target tree" in err

    def test_class_name_binding_still_enforced(self):
        err = validate_spec(self._spec(class_name="SomeOtherClass"))
        assert err is not None and "not bound" in err


# -- scripting-language string args render as data, never code ----------------


_HOSTILE_STRINGS = [
    "#{1+1}",                             # Ruby interpolation
    "@{[system('x')]}",                   # Perl block interpolation
    "$injected",                          # Perl/PHP scalar interpolation
    "{$var}",                             # PHP curly interpolation
    "`id`",                               # backticks
    'double "quotes" inside',
    "single 'quotes' inside",
    "trailing backslash \\",
    "escape-looking \\' \\\\ \\n",
    "hash # and #{nested '\\' mix}",
]


def _sq_roundtrip(literal: str) -> str:
    """Decode a single-quoted literal under Ruby/Perl/PHP semantics.

    In all three languages a single-quoted string recognises exactly two
    escapes (``\\\\`` and ``\\'``) and interpolates nothing. Walking the
    literal with those rules proves it is well-formed pure data: any
    unescaped quote (early termination) or dangling backslash asserts.
    """
    assert literal.startswith("'") and literal.endswith("'"), literal
    body = literal[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            assert i + 1 < len(body), f"dangling backslash: {literal!r}"
            nxt = body[i + 1]
            assert nxt in ("\\", "'"), f"unexpected escape: {literal!r}"
            out.append(nxt)
            i += 2
        else:
            assert ch != "'", f"unescaped quote ends literal early: {literal!r}"
            out.append(ch)
            i += 1
    return "".join(out)


def _run_stdout(argv: list[str]) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


class TestScriptingStringArgsAreData:
    """LLM-supplied string args are pasted into Ruby/Perl/PHP/Lua harness
    source. Rendered double-quoted they are an eval sink (#{...}, @{[...]},
    $var); rendered single-quoted they are pure data. Interpreter round-trips
    run when the interpreter is installed; the quote-closure asserts always
    run."""

    @pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
    def test_single_quote_closure(self, hostile):
        assert _sq_roundtrip(hy._single_quote(hostile)) == hostile

    @pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
    def test_ruby_roundtrips_as_data(self, hostile):
        lit = hy._format_args_scripting([hostile], nil_kw="nil")
        assert _sq_roundtrip(lit) == hostile
        ruby = shutil.which("ruby")
        if ruby:
            assert _run_stdout([ruby, "-e", f"print({lit})"]) == hostile

    @pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
    def test_perl_roundtrips_as_data(self, hostile):
        lit = hy._format_args_scripting([hostile], nil_kw="undef")
        assert _sq_roundtrip(lit) == hostile
        perl = shutil.which("perl")
        if perl:
            assert _run_stdout([perl, "-e", f"print({lit});"]) == hostile

    @pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
    def test_php_roundtrips_as_data(self, hostile):
        lit = hy._format_args_scripting([hostile], nil_kw="null")
        assert _sq_roundtrip(lit) == hostile
        php = shutil.which("php")
        if php:
            assert _run_stdout([php, "-r", f"echo {lit};"]) == hostile

    @pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
    def test_lua_roundtrips_as_data(self, hostile):
        lit = hy._format_args_scripting(
            [hostile], nil_kw="nil", quote=hy._lua_quote,
        )
        assert lit.startswith("'") and lit.endswith("'")
        lua = shutil.which("lua") or shutil.which("lua5.4") \
            or shutil.which("lua5.3") or shutil.which("luajit")
        if lua:
            assert _run_stdout([lua, "-e", f"io.write({lit})"]) == hostile

    def test_lua_control_chars_use_decimal_escapes(self):
        lit = hy._lua_quote("a\nb\tc")
        assert lit == "'a\\010b\\009c'"

    def test_perl_backtick_block_interpolation_stays_data(self, tmp_path):
        """Regression for the live repro: a Perl @{[ `cmd` ]} arg executed
        under the double-quoted rendering. Single-quoted it must print
        verbatim and the command must not run."""
        probe_file = tmp_path / "pwned"
        hostile = f"@{{[ `touch {probe_file}` ]}}"
        lit = hy._format_args_scripting([hostile], nil_kw="undef")
        assert _sq_roundtrip(lit) == hostile
        perl = shutil.which("perl")
        if perl:
            assert _run_stdout([perl, "-e", f"print({lit});"]) == hostile
        assert not probe_file.exists()

    def test_ruby_harness_renders_args_single_quoted(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="check",
            language="ruby",
            args=["#{1+1}"],
            lang_config={"require_path": "a"},
        )
        harness = generate_ruby_harness(spec, tmp_path)
        assert "check('#{1+1}')" in harness
        assert '"#{1+1}"' not in harness

    def test_ruby_harness_require_path_not_interpolable(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.rb", function="check",
            language="ruby",
            lang_config={"require_path": "#{`touch /tmp/x`}"},
        )
        harness = generate_ruby_harness(spec, tmp_path)
        assert 'require "#{' not in harness
        assert "require '#{`touch /tmp/x`}'" in harness

    def test_perl_harness_renders_args_single_quoted(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="A.pm", function="check",
            language="perl",
            args=["@{[system('x')]}"],
            lang_config={"use_module": "A"},
        )
        harness = generate_perl_harness(spec, tmp_path)
        assert "'@{[system(\\'x\\')]}'" in harness
        assert '"@{[system' not in harness

    def test_php_harness_renders_args_single_quoted(self, tmp_path):
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.php", function="check",
            language="php",
            args=["$HOME"],
        )
        harness = generate_php_harness(spec, tmp_path)
        assert "check('$HOME')" in harness
        assert '"$HOME"' not in harness

    def test_nested_containers_render_strings_as_data(self):
        lit = hy._format_args_scripting(
            [["#{1+1}"], {"k": "$v"}], nil_kw="nil",
        )
        assert lit == "['#{1+1}'], {'k' => '$v'}"


# ---------------------------------------------------------------------------
# W1 witness/verdict provenance — forged-oracle regression tests
# ---------------------------------------------------------------------------


class TestForgedWitnessFailsClosed:
    """Adversarial-review PoC vectors (U08-F300 / U07-F7): each of these
    LLM-authored specs empirically minted verdict="confirmed" against a
    provably benign target (``int f(int x){return x+1;}``) before the
    structural validators landed. All four must now fail CLOSED at spec
    validation — no compile, no execution, never a verdict."""

    def _benign_target(self, tmp_path):
        (tmp_path / "lib.c").write_text(
            "int f(int x){ return x+1; }\n", encoding="utf-8")
        return tmp_path

    def test_setup_lines_crash_forgery_rejected(self, tmp_path):
        root = self._benign_target(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="k1", file="lib.c", function="f", language="c",
            expected_crash=True,
            lang_config={
                "param_types": ["int"], "return_type": "int",
                "arg_expressions": ["1"],
                "setup_lines": ["int _k = *(volatile int*)0; (void)_k;"],
            },
        )
        assert validate_spec(spec, root) is not None
        r = execute_witness(spec, root)
        assert r.verdict == "error"
        assert "declaration grammar" in r.match_detail

    def test_param_types_constructor_injection_rejected(self, tmp_path):
        root = self._benign_target(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="k2", file="lib.c", function="f", language="c",
            expected_crash=True,
            lang_config={
                "param_types": [
                    "int); __attribute__((constructor)) static void "
                    "_pwn(void){__builtin_trap();} extern int _decoy(int"
                ],
                "return_type": "int", "arg_expressions": ["1"],
                "setup_lines": [],
            },
        )
        assert validate_spec(spec, root) is not None
        r = execute_witness(spec, root)
        assert r.verdict == "error"
        assert "param_type" in r.match_detail

    def test_forged_asan_stderr_rejected(self, tmp_path):
        root = self._benign_target(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="k3", file="lib.c", function="f", language="c",
            expected_sanitizer="heap-buffer-overflow",
            lang_config={
                "param_types": ["int"], "return_type": "int",
                "arg_expressions": ["1"],
                "setup_lines": [
                    'fprintf(stderr, "==1==ERROR: AddressSanitizer: '
                    'heap-buffer-overflow on address 0x602000000011\\n");',
                    "fflush(0); abort();",
                ],
            },
        )
        assert validate_spec(spec, root) is not None
        r = execute_witness(spec, root)
        assert r.verdict == "error"

    def test_forged_json_sentinel_rejected(self, tmp_path):
        root = self._benign_target(tmp_path)
        spec = DarkWitnessSpec(
            finding_key="k4", file="lib.c", function="f", language="c",
            expected_return="9999",
            lang_config={
                "param_types": ["int"], "return_type": "int",
                "arg_expressions": ["1"],
                "setup_lines": [
                    'printf("{\\"status\\":\\"returned\\",'
                    '\\"value\\":\\"9999\\"}\\n");',
                    "fflush(0); exit(0);",
                ],
            },
        )
        assert validate_spec(spec, root) is not None
        r = execute_witness(spec, root)
        assert r.verdict == "error"

    def test_rust_setup_forgeries_rejected(self):
        for line in (
            "let _ = std::process::abort();",
            "let x = 1; panic!();",
            "let v = vec![std::process::abort()];",
            'eprintln!("==ERROR: AddressSanitizer: x");',
        ):
            spec = DarkWitnessSpec(
                finding_key="k", file="l.rs", function="f", language="rust",
                lang_config={"arg_expressions": [], "setup_lines": [line]},
            )
            assert validate_spec(spec) is not None, line

    def test_rust_constructor_calls_rejected(self):
        # Rust setup lines get the C declaration-only doctrine: NO
        # general calls.  The pre-sentinel soundness argument that once
        # admitted constructor calls was unsound — the run sandbox
        # grants the witness read on its own work dir, where harness.rs
        # and the binary image carry the sentinel token, so any
        # call-capable setup line can read the token, replay the
        # sentinel plus a forged sanitizer report, and panic into a
        # forged "confirmed".  Constructor calls now fail validation
        # (witness dropped — error, never a forged confirmation).
        for line in (
            "let payload = bytes::Bytes::from_static(&[0x40u8]);",
            "let opt = Option::Some(5);",
            'let b = bytes::Bytes::copy_from_slice(b"abc");',
        ):
            spec = DarkWitnessSpec(
                finding_key="k", file="lib.rs", function="next",
                language="rust", expected_crash=True,
                lang_config={
                    "arg_expressions": ["&payload"],
                    "setup_lines": [line],
                },
            )
            assert validate_spec(spec) is not None, line

    def test_rust_sentinel_replay_setup_rejected(self):
        # The reproduced forged-confirmed chain: read the harness
        # source (the work dir is readable — it must be, to exec the
        # binary), replay its sentinel line to stderr, then panic.
        # Every call-bearing spelling of that chain must fail
        # validation.
        for line in (
            'let s = std::fs::read_to_string("harness.rs");',
            "let e = std::io::stderr();",
            'let exe = std::fs::read("/proc/self/exe");',
        ):
            spec = DarkWitnessSpec(
                finding_key="k", file="l.rs", function="f",
                language="rust",
                lang_config={"arg_expressions": [], "setup_lines": [line]},
            )
            assert validate_spec(spec) is not None, line

    def test_rust_call_free_setup_still_passes(self):
        # Control: the call-free grammar (literals, refs, arrays,
        # vec!, zero-arg methods on literals) stays usable.
        spec = DarkWitnessSpec(
            finding_key="k", file="lib.rs", function="next",
            language="rust", expected_crash=True,
            lang_config={
                "arg_expressions": ["&payload"],
                "setup_lines": [
                    "let payload = &[0x40u8];",
                    "let n: usize = 16;",
                    "let v = vec![0u8; 32];",
                    'let s = "x".to_string();',
                    'let t = b"abc".to_vec();',
                ],
            },
        )
        assert validate_spec(spec) is None

    def test_rust_closures_blocks_macros_still_rejected(self):
        for line in (
            'let c = || std::fs::remove_file("x");',
            "let u = unsafe { core::ptr::read(p) };",
            'let f = format!("{}", 1);',
            "let z = 1 < 2;",
        ):
            spec = DarkWitnessSpec(
                finding_key="k", file="l.rs", function="f", language="rust",
                lang_config={"arg_expressions": [], "setup_lines": [line]},
            )
            assert validate_spec(spec) is not None, line

    def test_legit_declarations_still_pass(self):
        c_spec = DarkWitnessSpec(
            finding_key="k", file="lib.c", function="f", language="c",
            expected_crash=True,
            lang_config={
                "param_types": ["char *", "unsigned long"],
                "return_type": "int",
                "arg_expressions": ["buf", "256"],
                "setup_lines": [
                    'char buf[10] = "AAAA";',
                    "int n = 5;",
                    "unsigned long long sz = 0;",
                    "struct foo s2 = {0};",
                    "char *p = NULL;",
                ],
            },
        )
        assert validate_spec(c_spec) is None
        rust_spec = DarkWitnessSpec(
            finding_key="k", file="lib.rs", function="f", language="rust",
            expected_crash=True,
            lang_config={
                "arg_expressions": ["&buf"],
                "setup_lines": [
                    "let mut buf = vec![0u8; 10];",
                    "let x: usize = 3;",
                    'let s = "x".to_string();',
                    "let a = [0u8; 4];",
                    "let r = &[1, 2];",
                ],
            },
        )
        assert validate_spec(rust_spec) is None

    def test_java_import_newline_injection_rejected(self):
        spec = DarkWitnessSpec(
            finding_key="k", file="A.java", function="m", language="java",
            lang_config={
                "class_name": "A",
                "imports": [
                    "java.util.HashMap\nclass Pwn { static { "
                    "Runtime.getRuntime().halt(1); } }",
                ],
                "arg_expressions": [],
            },
        )
        err = validate_spec(spec)
        assert err is not None and "import" in err

    def test_java_class_name_bound_to_finding_file(self):
        spec = DarkWitnessSpec(
            finding_key="k", file="src/AuthUtils.java", function="check",
            language="java",
            lang_config={"class_name": "SomeOtherClass",
                         "arg_expressions": []},
        )
        err = validate_spec(spec)
        assert err is not None and "not bound" in err
        nested = DarkWitnessSpec(
            finding_key="k", file="src/AuthUtils.java", function="check",
            language="java",
            lang_config={"class_name": "AuthUtils.Inner",
                         "arg_expressions": []},
        )
        assert validate_spec(nested) is None

    def test_native_args_fallback_validated_as_expressions(self):
        # No arg_expressions key: generators fall back to raw spec.args,
        # pasted verbatim — must go through the same allowlist.
        spec = DarkWitnessSpec(
            finding_key="k", file="lib.c", function="f", language="c",
            args=['1); system("id"); (0'],
            lang_config={"param_types": ["int"], "return_type": "int"},
        )
        err = validate_spec(spec)
        assert err is not None and "args used as expression" in err


class TestWitnessSubstitutionRejected:
    """U07-F8: parse_witness_response accepted any 'function' the LLM
    returned — a witness could exercise a lookalike and mint a verdict
    for the original finding. Substitution must reject the response."""

    def test_python_substitution_rejected(self):
        resp = json.dumps({
            "module_path": "pkg.mod", "function": "other_func",
            "args": ["x"], "expected_exception": "TypeError",
        })
        spec = parse_witness_response(
            resp, "pkg/mod.py:parse_input", "pkg/mod.py", "parse_input")
        assert spec is None

    def test_c_substitution_rejected(self):
        resp = json.dumps({
            "function": "helper_that_crashes",
            "arg_expressions": ["1"], "param_types": ["int"],
            "return_type": "int", "expected_crash": True,
        })
        spec = parse_witness_response(
            resp, "lib.c:parse_input", "lib.c", "parse_input")
        assert spec is None

    def test_matching_function_accepted(self):
        resp = json.dumps({
            "module_path": "pkg.mod", "function": "parse_input",
            "args": ["x"], "expected_exception": "TypeError",
        })
        spec = parse_witness_response(
            resp, "pkg/mod.py:parse_input", "pkg/mod.py", "parse_input")
        assert spec is not None
        assert spec.function == "parse_input"

    def test_omitted_function_defaults_to_finding(self):
        resp = json.dumps({
            "module_path": "pkg.mod",
            "args": ["x"], "expected_exception": "TypeError",
        })
        spec = parse_witness_response(
            resp, "pkg/mod.py:parse_input", "pkg/mod.py", "parse_input")
        assert spec is not None
        assert spec.function == "parse_input"


class TestHarnessTokenBinding:
    """The harness embeds an in-process token in its own JSON epilogue
    and a pre-call sentinel on stderr; classification requires both, so
    forged status lines and pre-call crashes never mint verdicts."""

    def _spec(self, **kw):
        base = dict(finding_key="k", file="lib.c", function="f",
                    language="c")
        base.update(kw)
        return DarkWitnessSpec(**base)

    def test_json_without_token_is_inconclusive(self):
        spec = self._spec(expected_return="1")
        out = json.dumps({"status": "returned", "value": "1"})
        r = _classify_output(spec, out, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"
        assert "token" in r.match_detail

    def test_json_with_wrong_token_is_inconclusive(self):
        spec = self._spec(expected_return="1")
        out = json.dumps(
            {"status": "returned", "token": "0000", "value": "1"})
        r = _classify_output(spec, out, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"

    def test_json_with_token_confirms(self):
        spec = self._spec(expected_return="1")
        out = json.dumps(
            {"status": "returned", "token": "feedface", "value": "1"})
        r = _classify_output(spec, out, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_no_expected_token_keeps_legacy_behaviour(self):
        spec = self._spec(expected_return="1")
        out = json.dumps({"status": "returned", "value": "1"})
        r = _classify_output(spec, out, "c")
        assert r.verdict == "confirmed"

    def test_crash_without_precall_sentinel_never_confirms(self):
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_crash=True)
        proc = _completed(returncode=-11)
        info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"
        assert "sentinel" in r.match_detail

    def test_crash_with_precall_sentinel_confirms(self):
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_crash=True)
        proc = _completed(returncode=-11)
        proc.stderr = "__raptor_witness_start__:feedface\n"
        info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_sanitizer_only_before_sentinel_never_confirms(self):
        # Setup expressions run pre-sentinel and may write stderr — a
        # forged sanitizer line planted there must not confirm even
        # though the sentinel itself is present.
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=0)
        proc.stderr = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "__raptor_witness_start__:feedface\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: heap-buffer-overflow"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"
        assert "BEFORE the pre-call sentinel" in r.match_detail

    def test_sanitizer_after_sentinel_confirms(self):
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=1)
        proc.stderr = (
            "__raptor_witness_start__:feedface\n"
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: heap-buffer-overflow"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_post_sentinel_decoy_does_not_rename_real_report(self):
        # One wrong-type line printed by the target call before the
        # real report must not flip a genuine, fully-retained crash to
        # inconclusive: type matching is anchored to ALL report lines
        # in the verified post-sentinel window, not to the whole-stream
        # classifier evidence (which is first-match-derived — here it
        # carries only the decoy type).
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=1)
        proc.stderr = (
            "__raptor_witness_start__:feedface\n"
            "ERROR: AddressSanitizer: decoy-type\n"
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on "
            "address 0x602000000011\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: decoy-type"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_pre_sentinel_forged_type_does_not_match(self):
        # The reverse steering direction: a forged expected-type line
        # planted BEFORE the sentinel (setup output) must not satisfy
        # the type match when the real post-sentinel report is a
        # different bug — the verified window is authoritative.
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=1)
        proc.stderr = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "__raptor_witness_start__:feedface\n"
            "==1==ERROR: AddressSanitizer: global-buffer-overflow on "
            "address 0x602000000011\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: heap-buffer-overflow"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"
        assert "does not match" in r.match_detail

    def test_report_spam_does_not_evict_real_report(self):
        # Type extraction from the verified window is uncapped
        # (window size is already bounded by the capture machinery):
        # a fixed cap would let N distinct forged report lines push
        # the genuine report — typically LAST, the sanitizer aborts
        # at the fault — out of the match set.
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=1)
        spam = "".join(
            f"ERROR: AddressSanitizer: forged-{i}\n" for i in range(40)
        )
        proc.stderr = (
            "__raptor_witness_start__:feedface\n"
            + spam
            + "==1==ERROR: AddressSanitizer: heap-buffer-overflow on "
            "address 0x602000000011\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: forged-0"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_bare_mention_window_never_reopens_evidence_fallback(self):
        # A verified window whose only "Sanitizer" text is a bare
        # mention (no report-shaped line) must FAIL the type match —
        # falling back to the whole-stream evidence would hand a
        # pre-sentinel forged report the match back.
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=-6)
        proc.stderr = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "__raptor_witness_start__:feedface\n"
            "note: AddressSanitizer shadow bytes follow\n"
        )
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: heap-buffer-overflow"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"

    def test_multiword_bug_type_matches_in_window(self):
        # TSAN-style multi-word types must stay matchable: window
        # extraction keeps the full report line, not the first token.
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="data race")
        proc = _completed(returncode=1)
        proc.stderr = (
            "__raptor_witness_start__:feedface\n"
            "WARNING: ThreadSanitizer: data race (pid=7)\n"
        )
        info = {"sanitizer": "tsan",
                "evidence": "ThreadSanitizer: data race detected"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "confirmed"

    def test_sanitizer_without_sentinel_never_confirms(self):
        from core.audit.dark_verify._execute import _classify_native_output
        spec = self._spec(expected_sanitizer="heap-buffer-overflow")
        proc = _completed(returncode=1)
        proc.stderr = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        info = {"sanitizer": "asan",
                "evidence": "AddressSanitizer: heap-buffer-overflow"}
        r = _classify_native_output(
            spec, proc, info, "c", expected_token="feedface")
        assert r.verdict == "inconclusive"
        assert "sentinel" in r.match_detail

    def test_harness_templates_embed_token_and_sentinel(self, tmp_path):
        spec = self._spec(
            expected_return="2",
            lang_config={"param_types": ["int"], "return_type": "int",
                         "arg_expressions": ["1"], "setup_lines": []},
        )
        src = generate_c_harness(spec, tmp_path, witness_token="feedface")
        assert '__raptor_witness_start__:feedface' in src
        assert '\\"token\\":\\"feedface\\"' in src

    def test_token_shape_is_enforced(self, tmp_path):
        spec = self._spec(lang_config={"arg_expressions": []})
        with pytest.raises(ValueError):
            generate_c_harness(
                spec, tmp_path, witness_token='x"); attack(("')


# -- setup-line grammar: backtracking budget ----------------------------------


class TestSetupGrammarBacktrackingBudget:
    """The declaration-grammar regexes run on LLM-authored setup
    lines, so a line that merely FAILS to parse must fail in linear
    time. Both historical quadratic witnesses are pinned: an
    unclosed ``[`` before a whitespace run (C array dims), and a
    type annotation with no ``=`` after a whitespace run (Rust
    let-binding). Budgets are CPU time, not wall time."""

    # 200k chars: the pre-fix quadratic engines needed tens of
    # seconds here; the unambiguous grammars need milliseconds.
    _N = 200_000
    _CPU_BUDGET_S = 1.0

    def _assert_cpu_bounded(self, fn):
        import time as _time
        start = _time.process_time()
        fn()
        assert _time.process_time() - start < self._CPU_BUDGET_S

    def test_c_decl_unclosed_bracket_whitespace_is_linear(self):
        line = "a[" + " " * self._N + "("
        self._assert_cpu_bounded(lambda: ex._C_DECL_LHS_RE.match(line))

    def test_rust_let_annotation_whitespace_is_linear(self):
        line = "let x : T" + " " * self._N + "("
        self._assert_cpu_bounded(lambda: ex._RUST_LET_RE.match(line))

    def test_c_array_dim_forms_still_accepted(self):
        for decl in ("char buf[16];", "int m[];", "int m[  ];",
                     "char b [ 12 ] [ 3 ];", "unsigned long long x;",
                     "struct foo *p;"):
            assert ex._c_setup_line_error(decl) is None, decl

    def test_c_rejections_unchanged(self):
        for decl in ("int x(void);", "a[ (;", "char buf[1e];"):
            assert ex._c_setup_line_error(decl) is not None, decl

    def test_rust_annotation_forms_still_accepted(self):
        for line in ("let mut v: Vec<u8> = 5;",
                     "let z: std::vec::Vec< u8 , u8 > = q;",
                     "let y = 5;"):
            assert ex._rust_setup_line_error(line) is None, line

    def test_setup_line_length_cap(self):
        long_line = "int x = " + "1" * ex._MAX_SETUP_LINE_CHARS + ";"
        err = ex._validate_setup([long_line], "c")
        assert err is not None and "exceeds" in err
        ok_line = "char buf[16];"
        assert ex._validate_setup([ok_line], "c") is None


class TestJavaUnicodeEscapeInjection:
    """javac pre-tokenizes backslash-uXXXX escapes everywhere (JLS
    3.3): a quoted arg carrying the escape for a double quote passes
    the Python-literal allowlist yet closes the string in the pasted
    harness — injected statements could print the verdict JSON and
    mint "confirmed" against a benign target."""

    _PAYLOAD = '"\\u0022); Runtime.getRuntime().exec(\\u0022id\\u0022);//"'

    def _spec(self, **lc):
        return DarkWitnessSpec(
            finding_key="f1", file="A.java", function="parse",
            language="java",
            lang_config={"class_name": "A", "return_type": "String", **lc},
        )

    def test_unicode_escape_in_arg_expression_rejected(self):
        err = validate_spec(self._spec(
            arg_expressions=[self._PAYLOAD],
        ))
        assert err is not None
        assert "unicode escape" in err

    def test_unicode_escape_newline_smuggle_rejected(self):
        err = validate_spec(self._spec(
            arg_expressions=['"a\\u000ab"'],
        ))
        assert err is not None
        assert "unicode escape" in err

    def test_unicode_escape_in_fallback_args_rejected(self):
        spec = DarkWitnessSpec(
            finding_key="f1", file="A.java", function="parse",
            language="java",
            lang_config={"class_name": "A", "return_type": "String"},
            args=[self._PAYLOAD],
        )
        err = validate_spec(spec)
        assert err is not None
        assert "unicode escape" in err

    def test_plain_java_args_still_pass(self):
        # Two-direction guard: legitimate literal args stay accepted.
        assert validate_spec(self._spec(
            arg_expressions=['"hello"', "42"],
        )) is None

    def test_c_arg_with_backslash_u_unaffected(self):
        # C does not pre-tokenize unicode escapes outside literals —
        # the rejection is Java-scoped.
        spec = DarkWitnessSpec(
            finding_key="f1", file="a.c", function="parse",
            language="c",
            lang_config={
                "arg_expressions": ['"caf\\u00e9"'],
                "return_type": "int",
            },
        )
        assert validate_spec(spec) is None


class TestJavaReturnValueEncoding:
    """The Java return path pastes a repo-controlled string — the
    target's ``toString()`` — into the token-authenticated verdict
    JSON. Raw concatenation let a crafted return value smuggle
    duplicate keys INSIDE the authenticated epilogue (``json.loads``
    keeps the last duplicate), flipping real refutations into
    attacker-chosen ``exception`` shapes and minting ``confirmed``
    whenever the injected type matched the witness's prediction."""

    # The duplicate-key payload: a toString() return that, pasted raw,
    # closes the value string and appends a forged exception epilogue.
    _INJECTED = (
        'X","status":"exception","type":"AssertionError",'
        '"message":"forged'
    )

    def _spec(self, **kw):
        base = dict(
            finding_key="f1", file="A.java", function="parse",
            language="java", expected_exception="AssertionError",
            lang_config={"class_name": "A", "return_type": "String"},
        )
        base.update(kw)
        return DarkWitnessSpec(**base)

    @staticmethod
    def _java_esc(s: str) -> str:
        # Python model of the template's esc(): per-char dispatch —
        # backslash / quote get their JSON escapes, control chars
        # become \\uXXXX (the Lua lane's json_escape coverage).
        return "".join(
            "\\\\" if c == "\\"
            else '\\"' if c == '"'
            else "\\u%04x" % ord(c) if ord(c) < 0x20
            else c
            for c in s
        )

    def test_return_path_escapes_before_interpolation(self):
        src = generate_java_harness(
            self._spec(), Path("/t"), witness_token="ab" * 16,
        )
        # Both epilogue paths route their repo-controlled text through
        # the template's esc() helper — the value is pure data.
        assert "private static String esc(String s)" in src
        assert 'String.format("\\\\u%04x", (int) c)' in src
        assert "String _val = esc(String.valueOf(result));" in src
        assert "esc(e.getMessage())" in src
        assert '+ _val + ' in src
        assert '+ result + ' not in src

    def test_escaped_epilogue_round_trips_hostile_value(self):
        # Simulate the template's esc() on the injection payload: the
        # emitted line stays ONE parseable object whose value is the
        # payload verbatim, and the classifier reads the normal return
        # as the refutation it is (an exception was predicted).
        line = (
            '{"status":"returned","token":"feedface",'
            '"value":"' + self._java_esc(self._INJECTED) + '"}'
        )
        data = json.loads(line)
        assert data["status"] == "returned"
        assert data["value"] == self._INJECTED
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "refuted"

    def test_multiline_return_value_keeps_its_verdict(self):
        # Loss-direction guard: a LEGITIMATE multi-line toString()
        # (newlines, tabs, CR) must stay one parseable status line —
        # an unescaped control char would degrade a truthful refuted
        # to inconclusive.
        payload = "line one\nline two\r\n\tindented"
        line = (
            '{"status":"returned","token":"feedface",'
            '"value":"' + self._java_esc(payload) + '"}'
        )
        data = json.loads(line)
        assert data["value"] == payload
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "refuted"

    def test_multiline_exception_message_still_confirms(self):
        # Same loss-direction guard on the exception path's _msg.
        msg = "boom:\n  at A.parse(A.java:3)"
        line = (
            '{"status":"exception","token":"feedface",'
            '"type":"AssertionError",'
            '"message":"' + self._java_esc(msg) + '"}'
        )
        data = json.loads(line)
        assert data["message"] == msg
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "confirmed"

    def test_duplicate_key_line_never_confirms(self):
        # Pre-fix repro: the raw-concatenation harness emitted exactly
        # this line for the payload; json.loads kept the LAST duplicate
        # and _classify_json_output minted verdict="confirmed" with
        # "exception type matches prediction" — token authentication
        # passed because the injection rode inside the authenticated
        # epilogue.
        line = (
            '{"status":"returned","token":"feedface","value":"'
            + self._INJECTED + '"}'
        )
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "inconclusive"
        assert "duplicate" in r.match_detail

    def test_clean_exception_line_still_confirms(self):
        # Two-direction guard: the duplicate-key gate must not tax a
        # legitimate epilogue.
        line = json.dumps({
            "status": "exception", "token": "feedface",
            "type": "AssertionError", "message": "boom",
        })
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "confirmed"

    def test_clean_return_line_still_classifies(self):
        line = json.dumps({
            "status": "returned", "token": "feedface", "value": "ok",
        })
        r = _classify_output(
            self._spec(), line, "java", expected_token="feedface",
        )
        assert r.verdict == "refuted"  # exception predicted, returned


class TestLaneValueEncoderClosure:
    """Every registry lane's RETURN-path epilogue must route the
    runtime value through a real encoder (or a typed numeric/%p format
    for C) — never raw interpolation into the verdict JSON. The Java
    lane regressed exactly this way; the table below is the mechanical
    oracle for the all-lanes claim, keyed to ``_SUPPORTED_LANGS`` so a
    new lane cannot land without declaring its encoder here."""

    _TOKEN = "ab" * 16

    @staticmethod
    def _rows():
        troot = Path("/t")

        def spec(file, lang, **kw):
            base = dict(finding_key="f1", file=file, function="check",
                        language=lang)
            base.update(kw)
            return DarkWitnessSpec(**base)

        return {
            "python": (
                generate_witness_script(
                    spec("src/auth.py", "python", module_path="src.auth"),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ['json.dumps({"status": "returned", "token": _tok, '
                 '"value": repr(_result)})'],
            ),
            "c": (
                generate_c_harness(
                    spec("a.c", "c",
                         lang_config={"return_type": "char *"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ['\\"value\\":\\"%p\\"'],
            ),
            "cpp": (
                generate_c_harness(
                    spec("a.cpp", "cpp",
                         lang_config={"return_type": "int"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ['\\"value\\":\\"%d\\"'],
            ),
            "go": (
                generate_go_harness(
                    spec("pkg/a.go", "go",
                         lang_config={"return_type": "string"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["json.Marshal(result{", 'Value:  fmt.Sprintf("%v", v)'],
            ),
            "javascript": (
                generate_js_harness(
                    spec("src/auth.js", "javascript",
                         lang_config={"require_path": "./src/auth"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["JSON.stringify({", "value: String(result)"],
            ),
            "typescript": (
                generate_ts_harness(
                    spec("src/auth.ts", "typescript",
                         lang_config={"require_path": "./src/auth"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["JSON.stringify({", "value: String(result)"],
            ),
            "ruby": (
                generate_ruby_harness(
                    spec("lib/auth.rb", "ruby"),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["JSON.generate({ status: 'returned', token: _tok, "
                 "value: _result.inspect })"],
            ),
            "php": (
                generate_php_harness(
                    spec("src/auth.php", "php"),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["json_encode([", "'value' => var_export($result, true)"],
            ),
            "rust": (
                generate_rust_harness(
                    spec("src/lib.rs", "rust",
                         lang_config={"return_type": "String"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ['\\"value\\":\\"{:?}\\"'],
            ),
            "java": (
                generate_java_harness(
                    spec("A.java", "java",
                         lang_config={"class_name": "A",
                                      "return_type": "String"}),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ['private static String esc(String s)',
                 'String _val = esc(String.valueOf(result));',
                 '+ _val + '],
            ),
            "lua": (
                generate_lua_harness(
                    spec("lib/auth.lua", "lua"),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["local function json_escape(s)",
                 'json_encode({status="returned", token=_tok, '
                 "value=tostring(result)})"],
            ),
            "perl": (
                generate_perl_harness(
                    spec("lib/Auth.pm", "perl"),
                    troot, witness_token=TestLaneValueEncoderClosure._TOKEN),
                ["encode_json({status => 'returned', token => $_tok, "
                 'value => "$result"})'],
            ),
        }

    def test_encoder_table_covers_every_supported_language(self):
        from core.audit.dark_verify._types import _SUPPORTED_LANGS
        assert set(self._rows()) == set(_SUPPORTED_LANGS)

    def test_every_lane_emits_through_its_encoder(self):
        for lang, (src, markers) in self._rows().items():
            for marker in markers:
                assert marker in src, (lang, marker)

    def test_no_lane_concatenates_the_raw_value(self):
        # The Java regression shape: the raw runtime value adjacent to
        # the value field with no encoder in between. String-typed
        # C-family formats would be the same class.
        for lang, (src, _markers) in self._rows().items():
            assert '+ result + ' not in src, lang
            assert '\\"value\\":\\"%s\\"' not in src, lang
