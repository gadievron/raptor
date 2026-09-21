"""Tests for :mod:`core.inventory.module_load_abort` (S4).

Covers per-language detection of unconditional top-of-module aborts
plus the conservative-bias negatives (conditional aborts must NOT
fire — false positives silence real findings on loadable files).
"""

from __future__ import annotations

import textwrap

import pytest

from core.inventory.module_load_abort import (
    ModuleLoadAbort,
    _go_panic_is_unconditional,
    detect_module_load_abort,
)


def _requires_lexical_grammar(language: str) -> None:
    """Positive-detection tests need the tokenizer-grade blanker's
    grammar; without it the detector fails closed (no abort), which
    the degradation tests pin separately."""
    from core.inventory import lexical_view

    if lexical_view._language_for(language) is None:
        pytest.skip(f"{language} tree-sitter grammar not installed")



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
    _requires_lexical_grammar("javascript")
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
    _requires_lexical_grammar("typescript")
    src = "throw new TypeError('disabled');\n"
    abort = detect_module_load_abort("typescript", src)
    assert abort is not None
    assert abort.summary == "throw new TypeError"


@pytest.mark.parametrize("language", ["typescript", "tsx"])
def test_ts_template_literal_type_throw_does_not_fire(language):
    # Type-level template literal: its text is erased at compile time,
    # but the node sits at depth 0 like a value template. Hostile (or
    # merely string-typed) literal content must not mint a whole-file
    # abort on a clean-parsing, live TypeScript file.
    _requires_lexical_grammar(language)
    src = (
        "type T = `\n"
        'x;throw new Error("q");\n'
        "`;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort(language, src) is None


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
    _requires_lexical_grammar("javascript")
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
# Go — comments and strings must not fabricate an abort. A panic, init
# header, or brace inside a comment or string literal must never
# produce the whole-file abort gate (which would suppress every
# finding in a loadable file).
# ---------------------------------------------------------------------------


def test_go_commented_panic_not_detected():
    src = (
        "package p\n"
        "\n"
        "func init() {\n"
        '\t// panic("disabled")\n'
        "}\n"
        "\n"
        "func Vulnerable(cmd string) { run(cmd) }\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_block_commented_panic_not_detected():
    src = (
        "package p\n"
        "func init() {\n"
        '\t/* panic("disabled") */\n'
        "\tregister()\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_panic_in_string_not_detected():
    src = (
        "package p\n"
        "func init() {\n"
        '\ts := "panic(oops)"\n'
        "\t_ = s\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_commented_init_header_not_detected():
    # The whole init (header included) is commented out.
    src = (
        "package p\n"
        '// func init() { panic("x") }\n'
        "func Live() {}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_conditional_panic_with_brace_in_comment_not_detected():
    # A '}' inside a comment before the panic used to drop the depth
    # counter to zero, misreading a conditional panic as unconditional.
    src = (
        "package p\n"
        "func init() {\n"
        "\tif bad() {\n"
        "\t\t// note: }\n"
        '\t\tpanic("x")\n'
        "\t}\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_rune_quote_does_not_corrupt_depth():
    # A '"' rune used to mispair the string skipper, swallowing the
    # conditional's '{' and misreading the panic as unconditional.
    src = (
        "package p\n"
        "func init() {\n"
        "\tr := '\"'\n"
        '\tt := "a"\n'
        "\t_ = r\n"
        "\t_ = t\n"
        "\tif cond {\n"
        '\t\tpanic("boom")\n'
        "\t}\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_real_panic_after_comment_still_detected():
    # Sanitisation preserves newlines, so the reported line is exact.
    src = (
        "package p\n"
        "func init() {\n"
        "\t// abort on load\n"
        '\tpanic("must not load")\n'
        "}\n"
    )
    abort = detect_module_load_abort("go", src)
    assert isinstance(abort, ModuleLoadAbort)
    assert abort.line == 4
    assert abort.summary == "func init() { panic(...) }"


def test_go_unconditional_panic_after_rune_still_detected():
    # Sanitising rune interiors must not break real detection.
    src = (
        "package p\n"
        "func init() {\n"
        "\tr := '\"'\n"
        "\t_ = r\n"
        '\tpanic("x")\n'
        "}\n"
    )
    abort = detect_module_load_abort("go", src)
    assert abort is not None
    assert abort.line == 5


def test_go_raw_string_brace_still_conditional():
    src = (
        "package p\n"
        "func init() {\n"
        "\ts := `}`\n"
        "\t_ = s\n"
        "\tif cond {\n"
        '\t\tpanic("a")\n'
        "\t}\n"
        "}\n"
    )
    assert detect_module_load_abort("go", src) is None


def test_go_panic_walker_skips_comments_directly():
    # Defense in depth: the depth walker itself (not just the sanitised
    # entry point) must skip comments like its sibling brace matcher.
    body = '\n\tif bad() {\n\t\t// note: }\n\t\tpanic("x")\n\t}\n'
    offset = body.index("panic")
    assert _go_panic_is_unconditional(body, offset) is False


def test_go_panic_walker_top_level_still_true():
    body = '\n\t// abort\n\tpanic("x")\n'
    offset = body.index("panic")
    assert _go_panic_is_unconditional(body, offset) is True


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def test_rust_compile_error_fires():
    _requires_lexical_grammar("rust")
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
    _requires_lexical_grammar("php")
    r = detect_module_load_abort("php", "<?php\ndie('disabled');\nfunction f(){}\n")
    assert r is not None and r.line == 2 and r.summary == "die"


def test_php_top_level_throw_new_fires():
    _requires_lexical_grammar("php")
    r = detect_module_load_abort(
        "php", "<?php\nthrow new \\App\\DisabledException();\nclass C{}\n")
    assert r is not None and r.summary == "throw new DisabledException"


def test_php_exit_after_function_fires():
    _requires_lexical_grammar("php")
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
    _requires_lexical_grammar("ruby")
    r = detect_module_load_abort("ruby", "raise 'disabled'\nclass C\n  def m; end\nend\n")
    assert r is not None and r.line == 1 and r.summary == "raise"


def test_ruby_abort_after_oneliner_def_fires():
    _requires_lexical_grammar("ruby")
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


def test_ruby_exit_bang_detected():
    _requires_lexical_grammar("ruby")
    abort = detect_module_load_abort("ruby", "exit!\n")
    assert isinstance(abort, ModuleLoadAbort)
    assert abort.line == 1
    assert abort.summary == "exit!"


def test_ruby_exit_bang_with_modifier_not_detected():
    assert detect_module_load_abort("ruby", "exit! if broken\n") is None


def test_ruby_plain_exit_still_detected():
    _requires_lexical_grammar("ruby")
    abort = detect_module_load_abort("ruby", "exit\n")
    assert abort is not None
    assert abort.summary == "exit"


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
    from core.analysis.reachability import module_aborts_on_load

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


# ---------------------------------------------------------------------------
# JS statement-boundary guard (throw after non-boundary chars)
# ---------------------------------------------------------------------------

def test_js_conditional_throw_not_detected():
    code = "if (typeof window === 'undefined') throw new Error('no window')"
    result = detect_module_load_abort("javascript", code)
    assert result is None, (
        f"Conditional throw falsely detected as module abort: {result}"
    )


def test_js_conditional_throw_multiline_not_detected():
    code = textwrap.dedent("""\
        const x = require('x');
        if (!x.supported)
            throw new Error('unsupported');
        module.exports = x;
    """)
    result = detect_module_load_abort("javascript", code)
    assert result is None


def test_js_bare_throw_still_detected():
    _requires_lexical_grammar("javascript")
    code = "throw new Error('module not supported')"
    result = detect_module_load_abort("javascript", code)
    assert result is not None
    assert "Error" in result.summary


def test_js_throw_after_semicolon_detected():
    _requires_lexical_grammar("javascript")
    code = "const ver = process.version;\nthrow new RangeError('bad version')"
    result = detect_module_load_abort("javascript", code)
    assert result is not None
    assert "RangeError" in result.summary


def test_js_throw_after_block_detected():
    _requires_lexical_grammar("javascript")
    code = textwrap.dedent("""\
        if (false) {
            console.log('skip');
        }
        throw new TypeError('always abort')
    """)
    result = detect_module_load_abort("javascript", code)
    assert result is not None
    assert "TypeError" in result.summary


def test_js_throw_inside_function_not_detected():
    code = textwrap.dedent("""\
        function validate(x) {
            if (!x) throw new Error('invalid');
        }
        module.exports = validate;
    """)
    result = detect_module_load_abort("javascript", code)
    assert result is None


def test_js_while_throw_not_detected():
    code = "while (check()) throw new Error('loop abort')"
    result = detect_module_load_abort("javascript", code)
    assert result is None


def test_js_for_throw_not_detected():
    code = "for (let i = 0; i < 1; i++) throw new Error('for abort')"
    result = detect_module_load_abort("javascript", code)
    assert result is None


# ---------------------------------------------------------------------------
# Lexer-divergence regressions (U09-F29): a live file must never read
# as aborted — module_aborts is a hard-suppress whole-file witness.
# ---------------------------------------------------------------------------


def test_ruby_inline_rescue_modifier_not_an_abort():
    # `raise "boom" rescue nil` is caught on the same line; the file
    # loads and every def below binds.
    code = 'raise "boom" rescue nil\ndef live\n  1\nend\n'
    assert detect_module_load_abort("ruby", code) is None


def test_ruby_plain_raise_still_detected():
    _requires_lexical_grammar("ruby")
    code = 'raise "boom"\ndef live\n  1\nend\n'
    result = detect_module_load_abort("ruby", code)
    assert result is not None
    assert result.line == 1


def test_php_prose_outside_tags_is_output_not_code():
    # Text outside <?php ?> is echoed HTML; `die` in prose after a `;`
    # boundary used to fabricate the whole-file abort gate.
    code = (
        "<html>x; die hard fan page</html>\n"
        "<?php\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("php", code) is None


def test_php_abort_in_second_region_still_detected():
    _requires_lexical_grammar("php")
    code = (
        "<?php $x = 1; ?>\n"
        "prose with exit words;\n"
        "<?php\n"
        "exit;\n"
    )
    result = detect_module_load_abort("php", code)
    assert result is not None
    assert result.line == 4
    assert result.summary == "exit"


def test_php_close_tag_inside_string_stays_in_php_mode():
    _requires_lexical_grammar("php")
    # A `?>` inside a string does not leave PHP mode — the `die` that
    # follows in real code must still be seen.
    code = "<?php\n$s = 'not a close ?> tag';\ndie('nope');\n"
    result = detect_module_load_abort("php", code)
    assert result is not None
    assert result.line == 3


def test_js_regex_literal_brace_does_not_fake_module_scope():
    # `/}}/ ` inside a function body used to decrement brace depth to
    # zero, so the throw inside the never-called function read as a
    # module-scope abort.
    code = (
        "function never() {\n"
        "  var r = /}}/;\n"
        '  throw new Error("x");\n'
        "}\n"
    )
    assert detect_module_load_abort("javascript", code) is None


def test_js_string_unbalanced_brace_does_not_fake_module_scope():
    code = (
        "function f() {\n"
        '  const s = "}";\n'
        '  throw new Error("x");\n'
        "}\n"
    )
    assert detect_module_load_abort("javascript", code) is None


def test_js_module_scope_throw_after_regex_still_detected():
    _requires_lexical_grammar("javascript")
    code = (
        "var r = /}{/;\n"
        'throw new Error("nope");\n'
        "function f() {}\n"
    )
    result = detect_module_load_abort("javascript", code)
    assert result is not None
    assert result.line == 2
# ---------------------------------------------------------------------------
# JS hostile-shape fixtures: string/template data must never fabricate
# a whole-file abort, in either regex-vs-division direction. All
# fixtures are valid, node-verified JavaScript.
# ---------------------------------------------------------------------------


def test_js_real_regex_after_unbraced_if_header_no_fabricated_abort():
    # `/x`y/` after the `)` of an unbraced if header is a REAL regex;
    # a division read lets its backtick open a phantom template and the
    # later template's `; throw new Error(...)` data lex as code.
    src = (
        "if (a) /x`y/.test(b);\n"
        "function live() { return 2; }\n"
        "const t = `x;\n"
        'throw new Error("nope");\n'
        "`;\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_division_terminating_at_comment_opener_no_fabricated_abort():
    # `{a:1} /2; // don`t` — a fake-regex read ending at the comment
    # opener's first slash exposes the comment tail as code; its
    # backtick flips template parity file-wide and the later template's
    # abort-shaped data lexes as code.
    src = (
        "x = {a:1} /2; // don`t\n"
        "function live() { return 1; }\n"
        "const t = `x;\n"
        'throw new Error("nope");\n'
        "`;\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_no_fabricated_abort_from_template_data():
    # `a` is the string "}"; `b` holds STRING DATA that merely looks
    # like a top-level throw. The module loads fine under node.
    src = (
        "const a = `${`}`}`;\n"
        "const b = `\n"
        "; throw new Boom();\n"
        "`;\n"
        "function live(req) { return req.q; }\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_backtick_after_division_no_fabricated_abort():
    # `x = {a:1} /`/;` is real division by a template literal; the
    # throw on line 2 is template DATA. node: prints LOADED OK 42.
    src = (
        "x = {a:1} /`/;\n"
        "throw new Boom();\n"
        "`;\n"
        "function live() { return 42; }\n"
        'console.log("LOADED OK", live());\n'
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_postfix_increment_division_no_fabricated_abort():
    # Same class through the `++` preceder: `i++ /`/;` is division by
    # a template.
    src = (
        "let i = 2;\n"
        "let n = i++ /`/;\n"
        "throw new Boom();\n"
        "`;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_js_parse_error_bails_whole_file():
    src = "function f( {\nthrow new Error('x');\n"
    assert detect_module_load_abort("javascript", src) is None


def test_js_grammar_absent_fails_closed(monkeypatch):
    # Without the grammar the detector must report nothing (bail),
    # never fall back to a guessed lexical view.
    from core.inventory import lexical_view

    monkeypatch.setattr(
        lexical_view._ts_cache, "import_grammar", lambda name: None,
    )
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    src = "throw new Error('module disabled');\n"
    assert detect_module_load_abort("javascript", src) is None
# ---------------------------------------------------------------------------
# Rust hostile-shape fixtures: comment / string data must never
# fabricate a whole-file abort. All fixtures are valid, compiling Rust.
# ---------------------------------------------------------------------------


def test_rust_compile_error_in_block_comment_no_fabricated_abort():
    src = (
        "/* examples:\n"
        ' compile_error!("do not use on wasm")\n'
        "*/\n"
        "fn live() { target(); }\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_compile_error_in_string_no_fabricated_abort():
    src = (
        "fn f() -> &'static str {\n"
        '    "usage:\n'
        "compile_error!(x)\n"
        '"\n'
        "}\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_compile_error_in_line_comment_no_fabricated_abort():
    src = (
        "// compile_error!(\"never\")\n"
        "fn live() { target(); }\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_real_compile_error_after_comment_decoy_still_detected():
    _requires_lexical_grammar("rust")
    src = (
        "// docs mention compile_error! here\n"
        'compile_error!("unsupported target");\n'
        "fn never() {}\n"
    )
    result = detect_module_load_abort("rust", src)
    assert result is not None
    assert result.line == 2


def test_rust_parse_error_bails_whole_file():
    src = 'fn f( { let = ;\ncompile_error!("x");\n'
    assert detect_module_load_abort("rust", src) is None


def test_rust_grammar_absent_fails_closed(monkeypatch):
    from core.inventory import lexical_view

    monkeypatch.setattr(
        lexical_view._ts_cache, "import_grammar", lambda name: None,
    )
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    src = 'compile_error!("unsupported");\n'
    assert detect_module_load_abort("rust", src) is None
# ---------------------------------------------------------------------------
# Ruby hostile-shape fixtures: heredoc / multi-line-string data must
# never fabricate a whole-file abort. All fixtures are valid Ruby.
# ---------------------------------------------------------------------------


def test_ruby_raise_in_heredoc_no_fabricated_abort():
    src = (
        "banner = <<~EOT\n"
        "raise the alarm when ready\n"
        "EOT\n"
        "def live\n"
        "  1\n"
        "end\n"
    )
    assert detect_module_load_abort("ruby", src) is None


def test_ruby_exit_in_multiline_string_no_fabricated_abort():
    src = (
        's = "line one\n'
        'exit\n'
        'line three"\n'
        "def live\n"
        "  1\n"
        "end\n"
    )
    assert detect_module_load_abort("ruby", src) is None


def test_ruby_abort_in_end_data_section_no_fabricated_abort():
    src = (
        "x = 1\n"
        "__END__\n"
        "abort\n"
    )
    assert detect_module_load_abort("ruby", src) is None


def test_ruby_real_raise_after_heredoc_still_detected():
    _requires_lexical_grammar("ruby")
    src = (
        "banner = <<~EOT\n"
        "raise decoy\n"
        "EOT\n"
        'raise "real abort"\n'
        "def never\n"
        "  1\n"
        "end\n"
    )
    result = detect_module_load_abort("ruby", src)
    assert result is not None
    assert result.line == 4
    assert result.summary == "raise"


def test_ruby_raise_with_heredoc_argument_still_detected():
    # The heredoc OPENER survives blanking, so raise-with-argument is
    # still recognised when the message itself is a heredoc.
    _requires_lexical_grammar("ruby")
    src = (
        "raise <<~ERR\n"
        "  unsupported platform\n"
        "ERR\n"
    )
    result = detect_module_load_abort("ruby", src)
    assert result is not None
    assert result.line == 1


def test_ruby_grammar_absent_fails_closed(monkeypatch):
    from core.inventory import lexical_view

    monkeypatch.setattr(
        lexical_view._ts_cache, "import_grammar", lambda name: None,
    )
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    src = 'raise "boom"\n'
    assert detect_module_load_abort("ruby", src) is None
# ---------------------------------------------------------------------------
# PHP hostile-shape fixtures: heredoc / nowdoc string data must never
# fabricate a whole-file abort (the dead_scope sibling already modelled
# heredocs; this detector did not). All fixtures are valid PHP.
# ---------------------------------------------------------------------------


def test_php_die_in_heredoc_no_fabricated_abort():
    src = (
        "<?php\n"
        "$msg = <<<EOT\n"
        "something;\n"
        "die\n"
        "EOT;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("php", src) is None


def test_php_throw_in_heredoc_no_fabricated_abort():
    src = (
        "<?php\n"
        "$msg = <<<EOT\n"
        "x;\n"
        "throw new Boom();\n"
        "EOT;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("php", src) is None


def test_php_exit_in_nowdoc_no_fabricated_abort():
    src = (
        "<?php\n"
        "$msg = <<<'NOW'\n"
        "usage;\n"
        "exit\n"
        "NOW;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("php", src) is None


def test_php_real_die_after_heredoc_still_detected():
    _requires_lexical_grammar("php")
    src = (
        "<?php\n"
        "$msg = <<<EOT\n"
        "die decoy\n"
        "EOT;\n"
        "die('real');\n"
    )
    result = detect_module_load_abort("php", src)
    assert result is not None
    assert result.line == 5
    assert result.summary == "die"


def test_php_parse_error_bails_whole_file():
    src = "<?php\nfunction f( {\ndie('x');\n"
    assert detect_module_load_abort("php", src) is None


def test_php_grammar_absent_fails_closed(monkeypatch):
    from core.inventory import lexical_view

    monkeypatch.setattr(
        lexical_view._ts_cache, "import_grammar", lambda name: None,
    )
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    src = "<?php\ndie('disabled');\n"
    assert detect_module_load_abort("php", src) is None
def test_rust_compile_error_in_macro_rules_arm_no_fabricated_abort():
    # A compile_error! inside a macro_rules! arm is the ubiquitous
    # "bad invocation" guard — it fires only on a caller's mistake,
    # never at module load. Flagging it hard-suppressed live files.
    src = (
        "macro_rules! sel {\n"
        "    ($x:expr) => { $x };\n"
        "    () => {\n"
        '        compile_error!("requires at least one branch")\n'
        "    };\n"
        "}\n"
        "fn live() {}\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_compile_error_in_fn_body_no_fabricated_abort():
    src = (
        "fn f() {\n"
        'compile_error!("x");\n'
        "}\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_compile_error_in_paren_macro_token_tree_no_fabricated_abort():
    # Macro invocations take any token-tree delimiter: a compile_error!
    # inside ``ignore_it!( ... )`` never expands (the file compiles —
    # rustc-verified) yet leaves the prefix BRACE-balanced; only the
    # dangling ``(`` betrays the token tree.
    src = (
        "macro_rules! ignore_it { ($($t:tt)*) => {}; }\n"
        "ignore_it!(\n"
        'compile_error!("never expands")\n'
        ");\n"
        "pub fn live() {}\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_rust_compile_error_in_bracket_macro_token_tree_no_fabricated_abort():
    # Same shape with the ``[`` token-tree delimiter (rustc-verified
    # to compile).
    src = (
        "macro_rules! ignore_it { ($($t:tt)*) => {}; }\n"
        "ignore_it![\n"
        'compile_error!("never expands")\n'
        "];\n"
        "pub fn live() {}\n"
    )
    assert detect_module_load_abort("rust", src) is None


def test_php_prefixed_literals_do_not_fabricate_abort():
    # ``b'…'`` spans start at the prefix byte: an edges blanking that
    # keeps the raw first byte leaves the closing quote unpaired, the
    # depth walker's string skip swallows ``function f() {``'s brace,
    # and the die() INSIDE the function reads as a depth-0
    # statement-initial abort — a whole-file dead gate fabricated on
    # a live file.
    _requires_lexical_grammar("php")
    src = (
        "<?php\n"
        "$a = b'x';\n"
        "function f() {\n"
        "    $b = b'y';\n"
        '    die("nope");\n'
        "}\n"
    )
    assert detect_module_load_abort("php", src) is None


def test_php_real_abort_after_prefixed_literal_still_detected():
    _requires_lexical_grammar("php")
    src = (
        "<?php\n"
        "$a = b'x';\n"
        "die('real');\n"
        "function f() { work(); }\n"
    )
    result = detect_module_load_abort("php", src)
    assert result is not None
    assert result.line == 3
    assert result.summary == "die"


@pytest.mark.parametrize("language", ["javascript", "typescript", "tsx"])
def test_js_family_hashbang_does_not_fabricate_abort(language):
    # ``hash_bang_line`` parses clean and used to survive blanking:
    # abort-looking text in a one-line hashbang read as a depth-0
    # statement-initial throw — a whole-file dead gate fabricated on
    # a file whose every function is live.
    _requires_lexical_grammar(language)
    src = (
        "#!/usr/bin/env node; throw new Boom(1)\n"
        "function live() { work(); }\n"
    )
    assert detect_module_load_abort(language, src) is None


def test_js_real_abort_below_hashbang_still_detected():
    _requires_lexical_grammar("javascript")
    src = (
        "#!/usr/bin/env node\n"
        "throw new Boom(1);\n"
        "function live() { work(); }\n"
    )
    result = detect_module_load_abort("javascript", src)
    assert result is not None
    assert result.line == 2
    assert result.summary == "throw new Boom"
