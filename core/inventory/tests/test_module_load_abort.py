"""Tests for :mod:`core.inventory.module_load_abort` (S4).

Covers per-language detection of unconditional top-of-module aborts
plus the conservative-bias negatives (conditional aborts must NOT
fire — false positives silence real findings on loadable files).
"""

from __future__ import annotations

from core.inventory.module_load_abort import (
    ModuleLoadAbort,
    detect_module_load_abort,
)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_python_top_level_raise_import_error_fires():
    src = (
        "import os\n"
        "raise ImportError('this module is disabled')\n"
        "\n"
        "def vulnerable(cmd):\n"
        "    os.system(cmd)\n"
    )
    abort = detect_module_load_abort("python", src)
    assert isinstance(abort, ModuleLoadAbort)
    assert abort.line == 2
    assert abort.summary == "raise ImportError"


def test_python_module_not_found_error_fires():
    src = "raise ModuleNotFoundError('nope')\n"
    abort = detect_module_load_abort("python", src)
    assert abort is not None
    assert abort.summary == "raise ModuleNotFoundError"


def test_python_system_exit_fires():
    src = "raise SystemExit(1)\n"
    abort = detect_module_load_abort("python", src)
    assert abort is not None
    assert abort.summary == "raise SystemExit"


def test_python_conditional_raise_does_not_fire():
    # The canonical false-positive trap: a version-gated raise. The
    # file still imports on the supported branch, so we must NOT flag.
    src = (
        "import sys\n"
        "if sys.version_info < (3, 10):\n"
        "    raise ImportError('needs 3.10+')\n"
        "\n"
        "def handler():\n"
        "    return 1\n"
    )
    assert detect_module_load_abort("python", src) is None


def test_python_raise_inside_try_does_not_fire():
    src = (
        "try:\n"
        "    import fast_impl\n"
        "except Exception:\n"
        "    raise ImportError('fallback unavailable')\n"
    )
    assert detect_module_load_abort("python", src) is None


def test_python_raise_inside_function_does_not_fire():
    # A raise in a function body runs only when the function is
    # called — not at module load. Not an abort.
    src = (
        "def guard():\n"
        "    raise ImportError('only when called')\n"
    )
    assert detect_module_load_abort("python", src) is None


def test_python_non_abort_exception_does_not_fire():
    # ValueError isn't in the abort allow-list — too generic; a
    # module-scope ValueError is unusual and we stay conservative.
    src = "raise ValueError('weird but loadable-ish')\n"
    assert detect_module_load_abort("python", src) is None


def test_python_syntax_error_returns_none():
    assert detect_module_load_abort("python", "def (:\n") is None


def test_python_dotted_exception_name_fires():
    # ``raise exceptions.ImportError(...)`` — attribute form.
    src = "import errors\nraise errors.ImportError('x')\n"
    abort = detect_module_load_abort("python", src)
    assert abort is not None
    assert abort.summary == "raise ImportError"


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def test_js_top_level_throw_fires():
    src = (
        "const x = 1;\n"
        "throw new Error('module disabled');\n"
        "function vuln(p) { eval(p); }\n"
    )
    abort = detect_module_load_abort("javascript", src)
    assert abort is not None
    assert abort.line == 2
    assert abort.summary == "throw new Error"


def test_js_typescript_alias_fires():
    src = "throw new TypeError('disabled');\n"
    abort = detect_module_load_abort("typescript", src)
    assert abort is not None
    assert abort.summary == "throw new TypeError"


def test_js_throw_inside_function_does_not_fire():
    src = (
        "function guard() {\n"
        "  throw new Error('only when called');\n"
        "}\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_throw_inside_if_does_not_fire():
    src = (
        "if (process.env.DISABLED) {\n"
        "  throw new Error('conditionally disabled');\n"
        "}\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_commented_throw_does_not_fire():
    src = (
        "// throw new Error('this is a comment');\n"
        "/* throw new Error('block comment'); */\n"
        "const ok = true;\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_throw_in_fn_with_string_brace_does_not_fire():
    # Adversarial false-positive: a string literal with an unbalanced
    # brace (``const s = "}";``) must NOT corrupt the depth counter and
    # make a throw INSIDE the function read as module-level. Pre-fix
    # this fired and silenced `vuln` (and everything below).
    src = (
        "function f() {\n"
        "  const s = \"}\";\n"
        "  throw new Error('boom');\n"
        "}\n"
        "function vuln(p) { eval(p); }\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_template_literal_braces_do_not_break_detection():
    # A template literal with ``${…}`` braces before a real top-level
    # throw must not desync the walker — the throw still fires.
    src = (
        "const x = `val=${1 + 2}`;\n"
        "throw new Error('dead');\n"
    )
    abort = detect_module_load_abort("javascript", src)
    assert abort is not None
    assert abort.line == 2


def test_js_arrow_function_throw_does_not_fire():
    src = "const f = () => { throw new Error('x'); };\n"
    assert detect_module_load_abort("javascript", src) is None


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_go_init_unconditional_panic_fires():
    src = (
        "package main\n"
        "\n"
        "func init() {\n"
        "    panic(\"this package is disabled\")\n"
        "}\n"
        "\n"
        "func Vuln(cmd string) {\n"
        "}\n"
    )
    abort = detect_module_load_abort("go", src)
    assert abort is not None
    assert abort.summary == "func init() { panic(...) }"


def test_go_init_conditional_panic_does_not_fire():
    # panic gated by a config check — not unconditional.
    src = (
        "package main\n"
        "\n"
        "func init() {\n"
        "    if cfg == nil {\n"
        "        panic(\"missing config\")\n"
        "    }\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_no_init_does_not_fire():
    src = (
        "package main\n"
        "func helper() { panic(\"runtime only\") }\n"
    )
    assert detect_module_load_abort("go", src) is None


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def test_rust_compile_error_fires():
    src = (
        "compile_error!(\"this module is disabled\");\n"
        "pub fn vuln() {}\n"
    )
    abort = detect_module_load_abort("rust", src)
    assert abort is not None
    assert abort.summary == "compile_error!(...)"


def test_rust_cfg_gated_compile_error_does_not_fire():
    # Build-config-gated compile_error is conditional on features;
    # out of scope for static analysis (conservative no-fire).
    src = "#[cfg(not(feature = \"x\"))] compile_error!(\"need x\");\n"
    assert detect_module_load_abort("rust", src) is None


# ---------------------------------------------------------------------------
# PHP — file-scope die / exit / throw new aborts include/require.
# ---------------------------------------------------------------------------


def test_php_top_level_die_fires():
    r = detect_module_load_abort("php", "<?php\ndie('disabled');\nfunction f(){}\n")
    assert r is not None and r.line == 2 and r.summary == "die"


def test_php_top_level_throw_new_fires():
    r = detect_module_load_abort(
        "php", "<?php\nthrow new \\App\\DisabledException();\nclass C{}\n")
    assert r is not None and r.summary == "throw new DisabledException"


def test_php_exit_after_function_fires():
    # The function binds, then an unconditional exit aborts the rest.
    r = detect_module_load_abort("php", "<?php\nfunction g(){}\nexit;\n")
    assert r is not None and r.line == 3


def test_php_die_inside_function_does_not_fire():
    assert detect_module_load_abort("php", "<?php\nfunction f(){ die('x'); }\n") is None


def test_php_throw_inside_method_does_not_fire():
    assert detect_module_load_abort(
        "php", "<?php\nclass C{ function m(){ throw new E(); } }\n") is None


def test_php_conditional_die_does_not_fire():
    # ``if ($x) die();`` — the die follows ``)`` so it is not statement-initial.
    assert detect_module_load_abort("php", "<?php\nif ($x) die('x');\n") is None


def test_php_die_in_string_does_not_fire():
    assert detect_module_load_abort("php", "<?php\n$s = 'die()';\nfunction f(){}\n") is None


def test_php_exit_method_call_does_not_fire():
    # ``$o->exit()`` is a method call, not the language construct.
    assert detect_module_load_abort("php", "<?php\n$o->exit();\nfunction f(){}\n") is None


# ---------------------------------------------------------------------------
# Ruby — column-0 unconditional raise / abort / exit / fail aborts require.
# ---------------------------------------------------------------------------


def test_ruby_top_level_raise_fires():
    r = detect_module_load_abort("ruby", "raise 'disabled'\nclass C\n  def m; end\nend\n")
    assert r is not None and r.line == 1 and r.summary == "raise"


def test_ruby_abort_after_oneliner_def_fires():
    # A one-liner ``def`` before the abort must not leave nesting stuck at 1.
    r = detect_module_load_abort("ruby", "def early; 1; end\nabort 'no'\ndef late; end\n")
    assert r is not None and r.line == 2 and r.summary == "abort"


def test_ruby_raise_inside_def_does_not_fire():
    assert detect_module_load_abort("ruby", "def f\n  raise 'x'\nend\n") is None


def test_ruby_raise_inside_class_method_does_not_fire():
    assert detect_module_load_abort(
        "ruby", "class C\n  def m\n    raise 'x'\n  end\nend\n") is None


def test_ruby_conditional_raise_modifier_does_not_fire():
    assert detect_module_load_abort("ruby", "raise 'x' if broken?\n") is None


def test_ruby_raise_inside_if_block_does_not_fire():
    assert detect_module_load_abort("ruby", "if cond\n  raise 'x'\nend\n") is None


def test_ruby_bare_raise_does_not_fire():
    # Bare ``raise`` (re-raise) has no argument — not a module-abort signal.
    assert detect_module_load_abort("ruby", "raise\n") is None


# ---------------------------------------------------------------------------
# Cross-cutting
# ---------------------------------------------------------------------------


def test_empty_content_returns_none():
    assert detect_module_load_abort("python", "") is None


def test_unwired_language_returns_none():
    # Java has a call-graph extractor but no abort detector (no top-level
    # execution model) — must degrade gracefully (no signal, not a crash).
    assert detect_module_load_abort(
        "java", "class X { static { throw new RuntimeException(); } }\n") is None


def test_clean_python_file_returns_none():
    src = (
        "import os\n"
        "def handler(cmd):\n"
        "    return os.system(cmd)\n"
    )
    assert detect_module_load_abort("python", src) is None


# ---------------------------------------------------------------------------
# Builder wiring + resolver accessor — the field must land on the
# inventory file record and the public ``module_aborts_on_load``
# accessor must surface it for downstream consumers.
# ---------------------------------------------------------------------------


def test_builder_records_abort_field(tmp_path):
    import tempfile
    from core.inventory.builder import build_inventory
    from core.inventory.reachability import module_aborts_on_load

    (tmp_path / "disabled.py").write_text(
        "raise ImportError('disabled')\n"
        "def vuln(cmd):\n"
        "    import os; os.system(cmd)\n"
    )
    (tmp_path / "ok.py").write_text(
        "def handler(x):\n"
        "    return x\n"
    )
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(tmp_path), td)

    # The aborting file carries the field; the clean file does not.
    by_path = {f["path"]: f for f in inv["files"]}
    assert "module_aborts_on_load" in by_path["disabled.py"]
    assert by_path["disabled.py"]["module_aborts_on_load"]["line"] == 1
    assert "module_aborts_on_load" not in by_path["ok.py"]

    # Accessor surfaces the record for the aborting file, None else.
    abort = module_aborts_on_load(inv, "disabled.py")
    assert abort is not None
    assert abort["summary"] == "raise ImportError"
    assert module_aborts_on_load(inv, "ok.py") is None
    assert module_aborts_on_load(inv, "nonexistent.py") is None
