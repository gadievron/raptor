"""Sanitized source view — comments/strings blanked, offsets preserved."""

from __future__ import annotations

import pytest

from core.audit.source_view import sanitized_view


class TestCFamily:
    def test_line_comment_blanked(self):
        view = sanitized_view("x = 1; // memcpy here\ny = 2;\n", "a.c")
        assert "memcpy" not in view
        assert "x = 1;" in view and "y = 2;" in view

    def test_block_comment_blanked_newlines_kept(self):
        src = "a;\n/* void check_perm(\n   spans lines */\nb;\n"
        view = sanitized_view(src, "a.c")
        assert "check_perm" not in view
        assert view.count("\n") == src.count("\n")
        assert view.splitlines()[3] == "b;"

    def test_string_contents_blanked_delimiters_kept(self):
        view = sanitized_view('call("system( is banned");', "a.c")
        assert "system" not in view
        assert '""' in view.replace(" ", "")

    def test_char_literal_blanked(self):
        view = sanitized_view("if (c == 'x') strcpy(a, b);", "a.c")
        assert "strcpy(a, b)" in view
        assert "'x'" not in view

    def test_rust_lifetime_tick_does_not_blank_the_line(self):
        # `'` opened a to-end-of-line string, so `&'a str` blanked
        # everything after the tick — code on the rest of the line
        # produced false absence receipts.
        view = sanitized_view(
            "fn f<'a>(x: &'a str) -> &'a str { check_perm(x); x }",
            "lib.rs",
        )
        assert "check_perm(x)" in view

    def test_escaped_char_literal_blanked(self):
        view = sanitized_view("if (c == '\\n') strcpy(a, b);", "a.c")
        assert "strcpy(a, b)" in view
        assert "'\\n'" not in view

    def test_hex_escape_char_literal_blanked(self):
        view = sanitized_view("if (c == '\\x41') go();", "a.c")
        assert "go()" in view
        assert "x41" not in view

    def test_js_single_quoted_string_still_blanked(self):
        # JS/TS treat '...' as a full string literal — the
        # char-literal shape restriction must not apply there.
        view = sanitized_view("var s = 'memcpy here'; run();", "a.js")
        assert "memcpy" not in view
        assert "run();" in view

    def test_escaped_quote_inside_string(self):
        view = sanitized_view(r'p("a\"b popen( c"); q();', "a.c")
        assert "popen" not in view
        assert "q();" in view

    def test_unterminated_string_stops_at_newline(self):
        view = sanitized_view("s = \"oops\nmemcpy(a, b, n);\n", "a.c")
        assert "memcpy(a, b, n);" in view

    def test_backtick_raw_string_for_go(self):
        view = sanitized_view("s := `exec( inside raw`\nrun()\n", "x.go")
        assert "exec" not in view
        assert "run()" in view

    def test_division_is_not_a_comment(self):
        view = sanitized_view("a = b / c; d = e / f;", "a.c")
        assert view == "a = b / c; d = e / f;"


class TestPythonLike:
    def test_hash_comment_blanked(self):
        view = sanitized_view("x = 1  # os.system here\ny = 2\n", "a.py")
        assert "os.system" not in view
        assert "y = 2" in view

    def test_docstring_blanked(self):
        src = 'def f():\n    """calls eval( on input"""\n    return g()\n'
        view = sanitized_view(src, "a.py")
        assert "eval" not in view
        assert "return g()" in view
        assert view.count("\n") == src.count("\n")

    def test_single_quoted_blanked(self):
        view = sanitized_view("cmd = 'subprocess.run( x'\nrun(cmd)\n", "a.py")
        assert "subprocess" not in view
        assert "run(cmd)" in view

    def test_code_survives(self):
        src = "import os\nos.system(cmd)\n"
        assert "os.system(cmd)" in sanitized_view(src, "a.py")


class TestEdgeCases:
    def test_empty_source(self):
        assert sanitized_view("", "a.c") == ""

    def test_unknown_extension_uses_c_family(self):
        view = sanitized_view("x; // memcpy\n", "a.unknown")
        assert "memcpy" not in view


class TestLanguageParam:
    def test_language_id_routes_hash_scanner(self):
        view = sanitized_view("x = 1  # os.system here\n",
                              language="python")
        assert "os.system" not in view

    def test_language_id_routes_c_family(self):
        view = sanitized_view("a(); // memcpy here\n", language="java")
        assert "memcpy" not in view

    def test_language_id_routes_backticks(self):
        view = sanitized_view("s := `exec( inside`\nrun()\n",
                              language="go")
        assert "exec(" not in view
        assert "run()" in view

    def test_segment_input_supported(self):
        # Not a whole file: a bare catch-clause segment.
        view = sanitized_view(
            "catch (Exception e) { /* System.exit(1) */ return true; }",
            language="java",
        )
        assert "System.exit" not in view
        assert "return true" in view

    def test_language_overrides_path(self):
        view = sanitized_view("x = 1  # nope\n", "a.c",
                              language="python")
        assert "nope" not in view


class TestPreprocessorDeadBlanking:
    """#if 0 regions and backslash-continued // comments are prose to
    the compiler — the C-family view blanks them; the #else/#elif arm
    of an #if 0 stays visible (it may be live). Whole-condition
    constant-zero spellings only (0/(0)/0x0/0L/00 — dead in every
    build): any macro-bearing condition, including a zero prefix like
    `#if 0 || FOO`, is build-dependent and deliberately not judged
    (documented residual)."""

    def test_if0_region_blanked(self):
        from core.audit.source_view import sanitized_view
        src = (
            "int a;\n"
            "#if 0\n"
            "int dead_decl;\n"
            "#endif\n"
            "int b;\n"
        )
        v = sanitized_view(src, "x.c")
        assert "dead_decl" not in v
        assert "int a;" in v and "int b;" in v
        assert len(v) == len(src)

    def test_nested_conditionals_stay_dead(self):
        from core.audit.source_view import sanitized_view
        src = (
            "#if 0\n"
            "#ifdef FOO\n"
            "int deep_dead;\n"
            "#endif\n"
            "int still_dead;\n"
            "#endif\n"
            "int live;\n"
        )
        v = sanitized_view(src, "x.c")
        assert "deep_dead" not in v
        assert "still_dead" not in v
        assert "int live;" in v

    def test_else_arm_of_if0_is_live(self):
        from core.audit.source_view import sanitized_view
        src = (
            "#if 0\n"
            "int dead;\n"
            "#else\n"
            "int live_arm;\n"
            "#endif\n"
        )
        v = sanitized_view(src, "x.c")
        assert "int dead;" not in v
        assert "int live_arm;" in v

    def test_nonzero_and_macro_conditions_not_judged(self):
        from core.audit.source_view import sanitized_view
        src = (
            "#if 1\n"
            "int kept_one;\n"
            "#endif\n"
            "#ifdef FOO\n"
            "int kept_macro;\n"
            "#endif\n"
        )
        v = sanitized_view(src, "x.c")
        assert "kept_one" in v
        assert "kept_macro" in v

    def test_if0_inside_comment_does_not_trigger(self):
        from core.audit.source_view import sanitized_view
        src = (
            "/*\n"
            "#if 0\n"
            "*/\n"
            "int live;\n"
        )
        v = sanitized_view(src, "x.c")
        assert "int live;" in v

    def test_unterminated_if0_blanks_to_end(self):
        from core.audit.source_view import sanitized_view
        src = "#if 0\nint dead;\n"
        v = sanitized_view(src, "x.c")
        assert "int dead;" not in v

    def test_line_continued_line_comment_blanked(self):
        from core.audit.source_view import sanitized_view
        src = (
            "int a; // note \\\n"
            "still comment text\n"
            "int b;\n"
        )
        v = sanitized_view(src, "x.c")
        assert "still comment" not in v
        assert "int a;" in v and "int b;" in v
        assert len(v) == len(src)

    def test_crlf_line_continued_comment_blanked(self):
        from core.audit.source_view import sanitized_view
        src = "int a; // note \\\r\nstill comment\r\nint b;\r\n"
        v = sanitized_view(src, "x.c")
        assert "still comment" not in v
        assert "int b;" in v

    def test_hash_languages_unaffected(self):
        from core.audit.source_view import sanitized_view
        src = "#if 0\nx = 1\n"
        v = sanitized_view(src, "x.py")
        # '#if 0' is a comment line in hash languages; code survives.
        assert "x = 1" in v

    def test_always_dead_constant_spellings_blanked(self):
        # Constant-only conditions are dead in EVERY build — a
        # spelling swap must not reopen the channel.
        from core.audit.source_view import sanitized_view
        for cond in ("(0)", "0x0", "0L", "00", "0u", "((0))",
                     "0X00", "0UL", "( 0 )"):
            src = f"#if {cond}\nint dead_decl;\n#endif\nint live;\n"
            v = sanitized_view(src, "x.c")
            assert "dead_decl" not in v, cond
            assert "int live;" in v, cond

    def test_no_space_paren_spelling_blanked(self):
        from core.audit.source_view import sanitized_view
        src = "#if(0)\nint dead_decl;\n#endif\nint live;\n"
        v = sanitized_view(src, "x.c")
        assert "dead_decl" not in v
        assert "int live;" in v

    def test_compound_zero_condition_not_judged(self):
        # `#if 0 || FOO` is live when FOO is truthy: a zero PREFIX
        # must never blank a macro-bearing (possibly-live) condition.
        from core.audit.source_view import sanitized_view
        for cond in ("0 || FOO", "0 + BAR", "0x0 && X", "0,1"):
            src = f"#if {cond}\nint maybe_live;\n#endif\n"
            v = sanitized_view(src, "x.c")
            assert "maybe_live" in v, cond

    def test_if0_trailing_comment_still_dead(self):
        from core.audit.source_view import sanitized_view
        src = "#if 0 /* disabled */\nint dead_decl;\n#endif\n"
        v = sanitized_view(src, "x.c")
        assert "dead_decl" not in v

    def test_crlf_if0_paren_spelling_blanked(self):
        from core.audit.source_view import sanitized_view
        src = "#if (0)\r\nint dead_decl;\r\n#endif\r\nint live;\r\n"
        v = sanitized_view(src, "x.c")
        assert "dead_decl" not in v
        assert "int live;" in v


class TestRawStrings:
    """Multi-line/raw string grammar: a comment marker or quote inside
    raw-string DATA must never desync the scanner (the swallow
    direction — code after the literal blanked or treated as
    comment), and the raw content itself must blank (absence/presence
    receipts are not steerable through raw literals)."""

    def test_cpp_raw_string_interior_quote_is_data(self):
        src = 'helper(c, R"(a " b /* )");\nsystem(c);\n'
        view = sanitized_view(src, "a.cpp")
        assert "system(c);" in view
        assert "/*" not in view

    def test_cpp_raw_string_with_delimiter(self):
        src = 'log(R"x(quote " and )" inside)x");\nrun(c);\n'
        view = sanitized_view(src, "a.cpp")
        assert "run(c);" in view
        assert "quote" not in view

    def test_cpp_raw_string_prefixed_forms(self):
        for prefix in ("u8", "u", "U", "L"):
            src = f'log({prefix}R"(data /* )");\nrun(c);\n'
            view = sanitized_view(src, "a.cpp")
            assert "run(c);" in view, prefix
            assert "data" not in view, prefix

    def test_identifier_ending_in_r_is_not_raw_opener(self):
        # `FOOR"..."` — the R is the tail of an identifier, so the
        # quote opens a PLAIN string (escapes honoured).
        src = 'x = FOOR"plain popen( data";\nrun(c);\n'
        view = sanitized_view(src, "a.cpp")
        assert "popen" not in view
        assert "run(c);" in view

    def test_cpp_raw_string_multiline_content_blanked(self):
        src = 'const char *s = R"(line one\nsystem( two\n)";\nlive(c);\n'
        view = sanitized_view(src, "a.cpp")
        assert "system" not in view
        assert "live(c);" in view
        assert view.count("\n") == src.count("\n")

    def test_rust_raw_string_interior_quote_is_data(self):
        src = 'let q = r#""/*"#;\nCommand::new(cmd);\n'
        view = sanitized_view(src, "lib.rs")
        assert "Command::new(cmd);" in view
        assert "/*" not in view

    def test_rust_raw_string_hash_depths(self):
        src = 'let q = r##"data "# still /* "##;\nrun(c);\n'
        view = sanitized_view(src, "lib.rs")
        assert "run(c);" in view
        assert "data" not in view

    def test_rust_byte_raw_string(self):
        src = 'let q = br#"bytes /* "#;\nrun(c);\n'
        view = sanitized_view(src, "lib.rs")
        assert "run(c);" in view
        assert "bytes" not in view

    def test_rust_identifier_ending_in_r_is_not_raw(self):
        src = 'let x = attr"..."; run(c);\n'
        view = sanitized_view(src, "lib.rs")
        assert "run(c);" in view


class TestJavaTextBlock:
    def test_text_block_content_blanked_across_lines(self):
        src = 'String s = """\nprose /* with system( calls\n""";\nrun(c);\n'
        view = sanitized_view(src, "A.java")
        assert "system" not in view
        assert "run(c);" in view

    def test_empty_string_pair_still_plain(self):
        # `"" + x` — two plain strings, not a text-block opener... but
        # `""` followed by `"` IS the opener per JLS; the scanner
        # treats the triple as a block and must still terminate at the
        # next triple.
        src = 'String s = "a" + "b";\nrun(c);\n'
        view = sanitized_view(src, "A.java")
        assert "run(c);" in view


class TestTemplateInterpolation:
    def test_template_continuation_comment_marker_is_data(self):
        src = "const q = `data\n/* more data`;\nexecSync(cmd);\n"
        view = sanitized_view(src, "a.js")
        assert "execSync(cmd);" in view
        assert "more data" not in view

    def test_interpolation_code_stays_visible(self):
        # `${…}` is executable code — blanking it forged absence
        # receipts (a sink call hidden inside a template).
        src = "run(`pre ${sink(x)} post`);\n"
        view = sanitized_view(src, "a.js")
        assert "sink(x)" in view
        assert "pre" not in view
        assert "post" not in view

    def test_nested_template_in_interpolation(self):
        src = "run(`a ${f(`inner ${g(y)} text`)} b`);\n"
        view = sanitized_view(src, "a.ts")
        assert "g(y)" in view
        assert "inner" not in view

    def test_escaped_backtick_does_not_close(self):
        src = "const q = `a \\` still string /* `;\nrun(c);\n"
        view = sanitized_view(src, "a.js")
        assert "run(c);" in view
        assert "still string" not in view

    def test_string_inside_interpolation_blanked(self):
        src = "run(`x ${f(\"prose popen( here\")} y`);\n"
        view = sanitized_view(src, "a.js")
        assert "popen" not in view
        assert "f(" in view


class TestHashLangInterpolation:
    """Python f-string / ruby ``#{…}`` / shell ``$(…)``/``${…}``/
    backtick interpolations are executable code and stay visible in
    the blanked view — the same direction contract as the JS/TS
    template arm. Blanking them hid a sink spelled inside an
    interpolation from every blanked-view consumer (absence-receipt
    forging, the swallow direction)."""

    def test_python_fstring_expression_visible(self):
        src = 'logger.info(f"r: {os.popen(cmd).read()}")\n'
        view = sanitized_view(src, "a.py")
        assert "os.popen(cmd).read()" in view
        assert "r:" not in view

    def test_python_plain_string_still_blanks(self):
        # No f prefix: brace text is DATA, exactly as before.
        src = 'logger.info("r: {os.popen(cmd)}")\n'
        view = sanitized_view(src, "a.py")
        assert "os.popen" not in view

    def test_python_fstring_doubled_braces_are_data(self):
        src = 'x = f"a {{prose popen( }} {run(c)}"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "popen" not in view

    def test_python_identifier_tail_f_is_not_a_prefix(self):
        # `shelf"…"` — the f is the tail of an identifier, not an
        # f-string prefix; treating it as one would leak string data.
        src = 'conf = shelf"{run(c)} data"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" not in view

    def test_python_triple_fstring_expression_visible(self):
        src = 'x = f"""head\n{os.system(c)}\ntail"""\n'
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view
        assert "head" not in view
        assert view.count("\n") == src.count("\n")

    def test_python_string_inside_interpolation_blanked(self):
        # A nested literal inside the kept expression is string data
        # again (mirrors the template arm's nested-string rule).
        src = 'x = f"{d[\'prose popen( here\'] and run(c)}"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "popen" not in view

    def test_python_fstring_backslash_brace_executes(self):
        # There is no brace escape in f-strings: CPython treats the
        # backslash as string data and EXECUTES the field —
        # f"\{1+1}" == "\2" — so the expression must stay visible.
        # Consuming \{ as an escape pair blanked the whole executable
        # interpolation (the swallow direction).
        src = 'x = f"\\{os.popen(c)}"\n'
        view = sanitized_view(src, "a.py")
        assert "os.popen(c)" in view
        raw = 'x = rf"\\{os.popen(c)}"\n'
        assert "os.popen(c)" in sanitized_view(raw, "a.py")

    def test_python_fstring_backslash_double_brace_is_data(self):
        # f"\{{x}}" == "\{x}" — the backslash is data AND the doubled
        # brace is a literal brace, so everything after the backslash
        # is string data. Consuming \{ as a pair left a single live {
        # that leaked the prose as code (the over-inclusion twin of
        # the swallow above).
        src = 'x = f"\\{{prose popen( }} ok"\n'
        view = sanitized_view(src, "a.py")
        assert "popen" not in view

    def test_python_pep701_same_quote_nesting_visible(self):
        # PEP 701 (3.12+) allows the outer quote char inside the
        # expression: the nested literal is string data (blanks) and
        # the code AFTER it stays visible — ending the outer string
        # at the first inner quote swallowed the sink call.
        src = 'x = f"{"cmd" + run(c)}"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "cmd" not in view
        assert len(view) == len(src)

    def test_python_nested_fstring_in_expression_visible(self):
        # A nested f-string inside a kept expression executes its own
        # interpolations: its literal text blanks as data, its {…}
        # fields stay visible as code.
        src = 'x = f"{f\'pre popen( {run(c)} post\' + y}"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "+ y" in view
        assert "popen" not in view
        assert "post" not in view
        assert len(view) == len(src)

    def test_python_pep701_nested_samequote_fstring_visible(self):
        # Both PEP 701 shapes at once: a same-quote NESTED F-STRING
        # inside the expression.
        src = 'x = f"{f"{run(c)}" + go(y)}"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "go(y)" in view

    def test_python_nested_triple_string_in_field_blanks(self):
        # A nested triple-quoted literal inside a field is data across
        # its whole (multi-line) body; code after it stays visible.
        src = 'x = f"""{ """da popen( ta""" + run(c) }"""\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "popen" not in view

    def test_python_format_spec_text_blanks_nested_field_visible(self):
        # Format-spec literal text is DATA handed to __format__; the
        # spec's own nested {…} fields are code and execute.
        src = 'x = f"{v:memcpy( {width}.{prec}f}"\n'
        view = sanitized_view(src, "a.py")
        assert "width" in view
        assert "prec" in view
        assert "memcpy" not in view
        assert len(view) == len(src)

    def test_python_conversion_tag_then_spec(self):
        # !r is field syntax (visible as code); the spec after the
        # depth-0 colon is data except its nested field.
        src = 'x = f"{user!r:>{pad}} tail"\n'
        view = sanitized_view(src, "a.py")
        assert "user!r" in view
        assert "pad" in view
        assert "tail" not in view

    def test_python_depth_colon_is_not_a_spec(self):
        # A colon inside brackets (dict display, slice) does not open
        # the format spec — only a depth-0 colon does.
        src = 'x = f"{ {"k": run(c)}["k"] } tail"\n'
        view = sanitized_view(src, "a.py")
        assert "run(c)" in view
        assert "tail" not in view

    def test_python_comment_in_multiline_field_blanks(self):
        # 3.12+ allows comments inside multi-line fields; comment
        # prose blanks like any other comment, the code stays.
        src = 'x = f"""{run( # note memcpy( lives here\n c)} data"""\n'
        view = sanitized_view(src, "a.py")
        assert "run(" in view
        assert "c)" in view
        assert "memcpy" not in view
        assert "data" not in view
        assert view.count("\n") == src.count("\n")

    def test_python_named_escape_is_data(self):
        # \N{…} is a named-character escape, not a field: data. In a
        # raw f-string the escape is disabled and the braces DO
        # interpolate.
        src = 'x = f"\\N{GREEK SMALL LETTER ALPHA}" + rf"\\N{run(c)}"\n'
        view = sanitized_view(src, "a.py")
        assert "GREEK" not in view
        assert "run(c)" in view

    def test_python_singlequote_multiline_field(self):
        # PEP 701 lets a field span lines in a SINGLE-quoted f-string
        # too: the field stays visible across the newline, trailing
        # literal data blanks, and code after the string survives.
        src = 'x = f"{run(\n c)} prose memcpy( here"\ny = go(z)\n'
        view = sanitized_view(src, "a.py")
        assert "run(" in view
        assert "go(z)" in view
        assert "memcpy" not in view
        assert view.count("\n") == src.count("\n")

    def test_python_singlequote_multiline_field_no_swallow(self):
        # Stopping the walk at the newline made the TRUE closing
        # quote re-open string state, blanking live code after the
        # string to end of line — the swallow direction on
        # compile-valid 3.12+ input.
        src = 'x = f"{a +\n b}" + os.system(cmd)\nq = 1\n'
        view = sanitized_view(src, "a.py")
        assert "os.system(cmd)" in view
        assert "q = 1" in view

    def test_python_fstring_nesting_bomb_no_recursion_error(self):
        # Non-compiling attacker shape: deep f"{ nesting must not
        # exhaust the interpreter stack; past the cap the walk stops
        # and the remainder stays VISIBLE (over-inclusion direction,
        # never a swallow).
        src = "x = " + 'f"{' * 3000 + "os.system(c)" + '}"' * 3000
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view

    def test_python_spec_nesting_bomb_no_recursion_error(self):
        # Same bound through the format-spec recursion.
        src = 'x = f"{a' + ":{a" * 3000 + " os.system(c)"
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view

    def test_python_compile_valid_max_depth_unaffected(self):
        # The cap sits above CPython's own compile-time nesting
        # limit: the deepest nesting that still compiles walks
        # normally (innermost expression visible, literal data
        # blanked).
        depth = 1
        while True:
            probe = 'f"{' * (depth + 1) + "1" + '}"' * (depth + 1)
            try:
                compile("x = " + probe, "<t>", "exec")
                depth += 1
            except (SyntaxError, RecursionError, MemoryError):
                break
        src = ('x = ' + 'f"data{' * depth
               + "os.system(c)" + '}tail"' * depth + "\n")
        compile(src, "<t>", "exec")
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view
        assert "data" not in view
        assert "tail" not in view

    def test_ruby_interpolation_visible(self):
        src = 'log("x: #{system(cmd)} y")\n'
        view = sanitized_view(src, language="ruby")
        assert "system(cmd)" in view
        assert "x:" not in view

    def test_ruby_single_quote_is_literal(self):
        # Ruby single-quoted strings do not interpolate.
        src = "log('x: #{system(cmd)} y')\n"
        view = sanitized_view(src, language="ruby")
        assert "system" not in view

    def test_ruby_escaped_sigil_is_data(self):
        # Ruby's escape genuinely suppresses interpolation:
        # "\#{system(c)}" is the literal text #{system(c)} — the
        # pair-blank matches the running language.
        src = 'log("a \\#{system(c)} b")\n'
        view = sanitized_view(src, language="ruby")
        assert "system" not in view

    def test_ruby_multiline_string_continuation_residual(self):
        # DECLARED residual: plain multi-line double-quoted strings
        # are unmodeled (single-line stop), so a continuation line
        # starting #{…} reads as a comment and blanks — pinned so a
        # change is visible (pre-existing; the wrapper tier's call
        # gates read raw lines and still refuse the shape).
        src = 'x = "a\n#{system(c)} b"\nrun(y)\n'
        view = sanitized_view(src, language="ruby")
        assert "system" not in view
        assert "run(y)" in view

    def test_shell_command_substitution_visible(self):
        src = 'echo "r: $(rm -rf $x) t"\n'
        view = sanitized_view(src, language="shell")
        assert "rm -rf $x" in view
        assert "r:" not in view

    def test_shell_parameter_expansion_visible(self):
        src = 'echo "v: ${x:-$(curl $u)}"\n'
        view = sanitized_view(src, language="shell")
        assert "curl $u" in view
        assert "v:" not in view

    def test_shell_backtick_substitution_visible(self):
        src = 'echo "r: `rm $x` t"\n'
        view = sanitized_view(src, language="shell")
        assert "rm $x" in view

    def test_shell_single_quote_is_literal(self):
        src = "echo 'a $(rm $x) b'\n"
        view = sanitized_view(src, language="shell")
        assert "rm" not in view

    def test_shell_single_quote_has_no_escapes(self):
        # `'\'` closes at the second quote — treating `\'` as an
        # escape desynced quote state and blanked live code after
        # the real closer to end of line (the swallow direction).
        src = "x='\\' ; run_thing $y\n"
        view = sanitized_view(src, language="shell")
        assert "run_thing $y" in view

    def test_shell_escaped_dollar_is_data(self):
        # Shell's double-quote escape genuinely suppresses
        # substitution: "\$(rm $x)" is literal text — the pair-blank
        # matches the running language.
        src = 'echo "a \\$(rm $x) b"\n'
        view = sanitized_view(src, language="shell")
        assert "rm" not in view

    def test_perl_interpolation_unchanged_residual(self):
        # DECLARED residual: perl string interpolation is variable-
        # only without the @{[…]} block idiom, whose grammar is the
        # unmodeled perl quote-construct class — pinned so a change
        # is visible.
        src = 'my $t = "a @{[system($c)]}";\n'
        view = sanitized_view(src, language="perl")
        assert "system" not in view

    def test_extension_routing_matches_language_routing(self):
        src = 'echo "r: $(rm -rf $x)"\n'
        assert (sanitized_view(src, "run.sh")
                == sanitized_view(src, language="shell"))
        rb = 'log("#{system(cmd)}")\n'
        assert (sanitized_view(rb, "a.rb")
                == sanitized_view(rb, language="ruby"))

    def test_keep_strings_view_unchanged(self):
        src = 'x = f"a {run(c)} b"\n'
        assert sanitized_view(src, "a.py", keep_strings=True) == src


class TestInterpolationNestingDesync:
    """Quote-state desyncs a hostile repo can spell in ONE line: the
    scanner pairing the outer quote with a NESTED string's opener, or
    applying the wrong escape model, resumed the scan mid-string and
    blanked live code out of the view (forged absence receipts /
    skip-steering — the swallow direction)."""

    def test_shell_ansi_c_quoting_escapes_apply(self):
        # $'It\'s' — ANSI-C quoting: \' stays INSIDE the literal.
        # Ending it there opened a phantom string over live code.
        src = "x=$'It\\'s'; eval \"$evil\""
        view = sanitized_view(src, language="bash")
        assert "eval" in view
        assert "It" not in view

    def test_shell_nested_single_quote_no_escapes(self):
        # Inside $(…) a nested 'a\' ends at the second quote (POSIX
        # single quotes have no escapes) — the default escape model
        # swallowed the following live code as string content.
        src = "x=\"$(echo 'a\\'; eval \"$evil\" 'junk')\""
        view = sanitized_view(src, language="bash")
        assert "eval" in view
        assert "junk" not in view

    def test_ruby_nested_string_in_interpolation(self):
        # "#{ f("#{a}") }" — the outer quote must pair with the TRUE
        # closer, not the nested string's opener; the desync made the
        # interior #{ read as a comment and blanked system(cmd).
        src = 'x = "#{ f("#{a}") }"; system(cmd)'
        view = sanitized_view(src, language="ruby")
        assert "system(cmd)" in view
        assert "f(" in view

    def test_ruby_nested_string_keep_strings_view(self):
        src = 'x = "#{ f("#{a}") }"; system(cmd)'
        view = sanitized_view(src, language="ruby", keep_strings=True)
        assert view == src

    def test_ruby_nested_literal_text_is_data(self):
        # The nested string's LITERAL text blanks; its own field
        # stays visible (same recursion rule as python f-strings).
        src = 'x = "#{ f("prose popen( #{run(c)}") }"; go()'
        view = sanitized_view(src, language="ruby")
        assert "run(c)" in view
        assert "popen" not in view
        assert "go()" in view

    def test_shell_expression_may_span_lines(self):
        # $(…) is code either way — a multi-line command substitution
        # must not desync the closing quote.
        src = "x=\"$(cmd one\ncmd two)\"; eval \"$y\""
        view = sanitized_view(src, language="bash")
        assert "eval" in view

    def test_shell_plain_single_quote_still_no_escapes(self):
        # The pre-existing POSIX rule is untouched: '\' closes at the
        # second quote and following code stays live.
        src = "x='a\\'; eval x"
        view = sanitized_view(src, language="bash")
        assert "eval x" in view

    def test_ruby_unterminated_interpolation_over_includes(self):
        # Unterminated #{ keeps the remainder visible — costs a
        # review, never a swallow.
        src = 'x = "#{ f(a ; system(cmd)'
        view = sanitized_view(src, language="ruby")
        assert "system(cmd)" in view


class TestPhp:
    def test_hash_line_comment_blanked(self):
        view = sanitized_view("$x = 1; # system( in prose\nrun($c);\n",
                              "a.php")
        assert "system" not in view
        assert "run($c);" in view

    def test_heredoc_body_blanked(self):
        src = "$x = <<<EOT\nbody /* hidden system( \nEOT;\nsystem($c);\n"
        view = sanitized_view(src, "a.php")
        assert "hidden" not in view
        assert "system($c);" in view

    def test_nowdoc_body_blanked(self):
        src = "$x = <<<'EOT'\nprose popen( here\nEOT;\nrun($c);\n"
        view = sanitized_view(src, "a.php")
        assert "popen" not in view
        assert "run($c);" in view

    def test_heredoc_terminator_may_be_indented(self):
        src = "$x = <<<END\n  data\n  END;\nrun($c);\n"
        view = sanitized_view(src, "a.php")
        assert "data" not in view
        assert "run($c);" in view

    def test_shift_left_is_not_heredoc(self):
        view = sanitized_view("$x = $a << 3; run($c);\n", "a.php")
        assert "run($c);" in view


class TestLineBlockCommentsAndConfigQuotes:
    """Perl POD and ruby =begin/=end are block comments — reading
    their prose as code minted call-shaped false positives in
    counting consumers. TOML literal / YAML single-quoted strings
    have no backslash escapes — the default escape model swallowed
    live same-line content after the true closer."""

    def test_perl_pod_blanked(self):
        src = "=pod\nhelper() twice from prose\n=cut\nreal_code();"
        view = sanitized_view(src, language="perl")
        assert "helper" not in view
        assert "real_code();" in view
        assert view.count("\n") == src.count("\n")

    def test_perl_any_pod_command_opens(self):
        src = "=head1 NAME\neval( prose\n=cut\ngo();"
        view = sanitized_view(src, language="perl")
        assert "eval" not in view
        assert "go();" in view

    def test_perl_bare_cut_blanks_one_line_only(self):
        view = sanitized_view("=cut\ncode();", language="perl")
        assert "code();" in view

    def test_perl_unterminated_pod_blanks_to_eof(self):
        view = sanitized_view("=pod\nprose eval(\nmore", language="perl")
        assert "eval" not in view
        assert "more" not in view

    def test_perl_mid_line_equals_is_code(self):
        src = "$x =~ s/a/b/;\n$y\n  = 5;"
        assert sanitized_view(src, language="perl") == src

    def test_ruby_begin_end_blanked(self):
        src = "=begin\nhelper() twice from prose\n=end\nreal_code"
        view = sanitized_view(src, language="ruby")
        assert "helper" not in view
        assert "real_code" in view

    def test_ruby_begin_needs_column_zero(self):
        src = "x = 5\n  =begin_ish\ny = 6"
        assert sanitized_view(src, language="ruby") == src

    def test_toml_single_quote_no_escapes(self):
        src = "key = 'a\\' ; hostile = \"x\"\nnext_key = 1"
        view = sanitized_view(src, file_path="config.toml")
        # The literal string closes at the second quote (backslash is
        # data) — the rest of the line is live, not swallowed.
        assert "; hostile =" in view
        assert "next_key = 1" in view
        # String CONTENTS still blank (both quote forms).
        assert "a\\" not in view
        first_line = view.split("\n")[0]
        assert '"x"' not in first_line and '" "' in first_line

    def test_yaml_doubled_quote_is_literal(self):
        src = "key: 'It''s fine' # eval( note\nnext: 2"
        view = sanitized_view(src, file_path="c.yaml")
        assert "eval" not in view
        assert "next: 2" in view
        assert "fine" not in view

    def test_perl_extension_routes_pod(self):
        src = "=pod\nprose popen(\n=cut\nrun();"
        view = sanitized_view(src, "script.pl")
        assert "popen" not in view
        assert "run();" in view


class TestPhpInterpolation:
    """PHP double-quoted strings and heredocs execute complex-syntax
    interpolation — `{$obj->method($arg)}` CALLS the method — so
    those expressions stay visible in both views (the template-arm
    direction contract). Simple $ident interpolation stays data
    (declared residual: a bare variable mention cannot spell a
    call)."""

    def test_dq_complex_interpolation_visible(self):
        src = '<?php $q = "prefix {$db->query($x)} suffix";'
        view = sanitized_view(src, "a.php")
        assert "$db->query($x)" in view
        assert "prefix" not in view

    def test_heredoc_complex_interpolation_visible(self):
        src = '<?php $q = <<<EOT\nbody {$db->query($x)} tail\nEOT;'
        view = sanitized_view(src, "a.php")
        assert "$db->query($x)" in view
        assert "body" not in view

    def test_nowdoc_never_interpolates(self):
        src = "<?php $q = <<<'EOT'\nbody {$db->query($x)} tail\nEOT;"
        view = sanitized_view(src, "a.php")
        assert "query" not in view

    def test_simple_variable_stays_data(self):
        src = '<?php $q = "hello $name world";'
        view = sanitized_view(src, "a.php")
        assert "$name" not in view

    def test_backslash_brace_dollar_still_executes(self):
        # PHP defines no \{ escape in double-quoted strings: the
        # backslash is data and {$...} interpolates anyway — the call
        # must stay visible (consuming the pair swallowed it).
        src = '<?php $q = "a \\{$db->run($t)} b";'
        view = sanitized_view(src, "a.php")
        assert "$db->run($t)" in view

    def test_escaped_dollar_in_brace_is_data(self):
        # "{\$x}" is the PHP spelling for a LITERAL {$x} — no
        # interpolation, whole body blanks.
        src = '<?php $q = "a {\\$db} b";'
        view = sanitized_view(src, "a.php")
        assert "$db" not in view

    def test_nested_string_in_expression_is_data(self):
        # The kept expression's own string argument blanks, and the
        # nested quote must not desync the outer close.
        src = '<?php $q = "x {$db->query("del")} y"; run($c);'
        view = sanitized_view(src, "a.php")
        assert "run($c)" in view
        assert "del" not in view
        assert "$db->query(" in view

    def test_keep_strings_view_verbatim(self):
        src = '<?php $q = "prefix {$db->query($x)} suffix";'
        assert sanitized_view(src, "a.php", keep_strings=True) == src


class TestLua:
    def test_line_comment_blanked(self):
        view = sanitized_view("local x = 1 -- os.execute prose\nrun(c)\n",
                              "a.lua")
        assert "os.execute" not in view
        assert "run(c)" in view

    def test_long_comment_blanked_across_lines(self):
        src = "--[[ comment\nos.execute prose\n]]\nrun(c)\n"
        view = sanitized_view(src, "a.lua")
        assert "os.execute" not in view
        assert "run(c)" in view

    def test_long_string_dashes_are_data(self):
        # `--` inside a long string is data, not a comment opener —
        # the old per-line strip cut the rest of the line (swallow).
        src = "submit([[x -- y]], os.execute)\n"
        view = sanitized_view(src, "a.lua")
        assert "os.execute" in view
        assert "x -- y" not in view

    def test_leveled_long_string(self):
        src = "local s = [=[ data ]] still ]=]\nrun(c)\n"
        view = sanitized_view(src, "a.lua")
        assert "data" not in view
        assert "run(c)" in view

    def test_integer_division_is_not_a_comment(self):
        view = sanitized_view("local x = a // b; os.execute(c)\n",
                              "a.lua")
        assert "os.execute(c)" in view

    def test_table_index_is_not_long_string(self):
        view = sanitized_view("local v = t[i][j]; run(c)\n", "a.lua")
        assert "t[i][j]" in view


class TestKeepStrings:
    """keep_strings=True: comments still blank, string literals stay
    verbatim (the prefilter's judged view — over-inclusion direction),
    and preprocessor-dead blanking is OFF (string data spelling
    `#if 0` must not mint a fake dead region)."""

    def test_strings_kept_comments_blanked(self):
        src = 'helper(c, "keep /* me"); // gone\nsystem(c);\n'
        view = sanitized_view(src, "a.c", keep_strings=True)
        assert '"keep /* me"' in view
        assert "gone" not in view
        assert "system(c);" in view

    def test_string_comment_marker_never_opens_comment_state(self):
        src = 'log("scan /*");\nsystem(c);\n/* real */ done();\n'
        view = sanitized_view(src, "a.c", keep_strings=True)
        assert "system(c);" in view
        assert "done();" in view
        assert "real" not in view

    def test_raw_string_kept_verbatim(self):
        src = 'helper(c, R"(a " b /* )");\nsystem(c);\n'
        view = sanitized_view(src, "a.cpp", keep_strings=True)
        assert 'R"(a " b /* )"' in view
        assert "system(c);" in view

    def test_if0_not_judged_in_keep_mode(self):
        # A kept multi-line string could spell `#if 0` on its own
        # line; dead-region detection is only sound over the fully
        # blanked view, so the keep-strings mode never applies it.
        src = "#if 0\nint dead_decl;\n#endif\n"
        view = sanitized_view(src, "x.c", keep_strings=True)
        assert "dead_decl" in view

    def test_python_like_keep_strings(self):
        src = "x = 'lit # data'  # comment\n"
        view = sanitized_view(src, "a.py", keep_strings=True)
        assert "'lit # data'" in view
        assert "comment" not in view

    def test_lua_keep_strings(self):
        src = "submit([[x -- y]], os.execute) -- note\n"
        view = sanitized_view(src, "a.lua", keep_strings=True)
        assert "[[x -- y]]" in view
        assert "note" not in view


class TestJsRegexLiterals:
    """JS/TS regex literals are lexed in value position so their
    interior can never mint comment state: `/\\//` read as
    division-then-`//` blanked real code after the regex out of BOTH
    views (the swallow direction). Division keeps working; the
    ambiguity fallback is scan-as-code (over-inclusion)."""

    def test_escaped_slash_regex_does_not_open_line_comment(self):
        src = "const re = /\\//; fs.unlinkSync(c);\n"
        for keep in (False, True):
            view = sanitized_view(src, "a.js", keep_strings=keep)
            assert "fs.unlinkSync(c);" in view, keep

    def test_escaped_slash_star_does_not_open_block_comment(self):
        src = "const re = /\\/*/ ; run(c);\nafter(c);\n"
        for keep in (False, True):
            view = sanitized_view(src, "a.js", keep_strings=keep)
            assert "run(c);" in view, keep
            assert "after(c);" in view, keep

    def test_regex_content_blanked_in_ref_view_kept_in_kept_view(self):
        src = "if (/sys.tem/.test(x)) run(x);\n"
        assert "sys.tem" not in sanitized_view(src, "a.js")
        assert "run(x);" in sanitized_view(src, "a.js")
        kept = sanitized_view(src, "a.js", keep_strings=True)
        assert "/sys.tem/" in kept

    def test_division_not_treated_as_regex(self):
        view = sanitized_view("a = b / c; run(x);\n", "a.js")
        assert "run(x);" in view
        view = sanitized_view("a = b / c / d; run(x);\n", "a.js")
        assert "run(x);" in view

    def test_line_comment_after_division_still_blanked(self):
        view = sanitized_view("x = a / b // prose run()\n", "a.js")
        assert "prose" not in view
        assert "x = a / b" in view

    def test_char_class_slash_does_not_close(self):
        view = sanitized_view("const r = /[/]x/; run(c);\n", "a.js")
        assert "run(c);" in view

    def test_unterminated_candidate_falls_back_to_division(self):
        view = sanitized_view("const y = a /b;\nrun(c);\n", "a.js")
        assert "run(c);" in view
        assert "a /b;" in view

    def test_regex_after_keyword(self):
        view = sanitized_view("return /x\\//; run(c);\n", "a.js")
        assert "run(c);" in view


class TestPerlSigilHash:
    def test_dollar_hash_is_not_a_comment_opener(self):
        view = sanitized_view(
            "my $n = $#arr; dispatch($c, \\&system);\n",
            language="perl")
        assert "dispatch($c, \\&system);" in view

    def test_real_perl_comment_still_blanked(self):
        view = sanitized_view(
            "my $n = 1; # prose system(\n", language="perl")
        assert "system" not in view
        assert "my $n = 1;" in view


class TestCppRawDelimQuote:
    def test_quote_never_joins_the_delimiter(self):
        # `R"abc"` is R + an ordinary string literal (d-chars exclude
        # `"` per the C++ grammar); admitting it false-opened a raw
        # string that blanked to EOF in the ref view.
        src = 'x = R"abc" + f(y);\nrun(c);\n'
        view = sanitized_view(src, "a.cpp")
        assert "f(y);" in view
        assert "run(c);" in view


class TestKotlinView:
    def test_kt_extension_routes_c_family(self):
        view = sanitized_view("val x = 1 // system( here\nrun()\n", "A.kt")
        assert "system" not in view
        assert "run()" in view

    def test_kts_extension_routes_too(self):
        view = sanitized_view("/* system( */\ngo()\n", "build.kts")
        assert "system" not in view
        assert "go()" in view

    def test_nested_block_comment_fully_blanked(self):
        # Kotlin block comments NEST: closing at the first `*/` left
        # interior comment prose visible as code (the over-inclusion
        # direction — a comment mentioning a sink minted a presence
        # receipt).
        src = "a()\n/* outer /* inner */ check_perm() */\nrun()\n"
        view = sanitized_view(src, "A.kt")
        assert "check_perm" not in view
        assert "run()" in view
        assert view.count("\n") == src.count("\n")

    def test_raw_string_backslash_is_data(self):
        # Kotlin `"""` raw strings have NO escape processing — a
        # trailing backslash before the closer must not push the
        # close past the real terminator (the swallow direction).
        view = sanitized_view('val x = """abc\\"""\nrunIt()\n', "A.kt")
        assert "runIt()" in view
        assert "abc" not in view

    def test_raw_string_content_blanked_across_lines(self):
        src = 'val q = """\nselect exec( from t\n"""\ngo()\n'
        view = sanitized_view(src, "A.kt")
        assert "exec" not in view
        assert "go()" in view
        assert view.count("\n") == src.count("\n")


class TestSwiftView:
    def test_swift_extension_routes_c_family(self):
        view = sanitized_view("let x = 1 // system( here\nrun()\n", "m.swift")
        assert "system" not in view
        assert "run()" in view

    def test_nested_block_comment_fully_blanked(self):
        view = sanitized_view(
            "f()\n/* a /* b */ system( */\ngo()\n", "m.swift")
        assert "system" not in view
        assert "go()" in view

    def test_multiline_string_escapes_honoured(self):
        # Swift multi-line strings DO process escapes (the Java text
        # block model): an escaped interior quote never closes early.
        src = 'let s = """\nhas \\" quote system( here\n"""\ngo()\n'
        view = sanitized_view(src, "m.swift")
        assert "system" not in view
        assert "go()" in view


class TestCSharpVerbatimStrings:
    def test_trailing_backslash_does_not_desync(self):
        # `@"dir\"` — verbatim strings give the backslash NO escape
        # meaning; the default escape model read `\"` as an escaped
        # quote and blanked live code after the string (the swallow
        # direction).
        view = sanitized_view(r'var p = @"C:\dir\"; Check(a);', "P.cs")
        assert "Check(a);" in view
        assert "dir" not in view

    def test_doubled_quote_is_data(self):
        view = sanitized_view(
            'var s = @"say ""hi"" exec( more"; Run();', "P.cs")
        assert "exec" not in view
        assert "Run();" in view

    def test_doubled_quote_then_newline_stays_string(self):
        # A doubled `""` is DATA, not a terminator — and the failure
        # mode only surfaces across a NEWLINE (verbatim strings span
        # newlines; plain strings do not, so an early close desyncs
        # the lexer at the line break and string payload surfaces as
        # visible code: an attacker-plantable abort idiom inside a
        # catch block would then mint a fail-closed receipt).
        src = ('var s = @"a""\n'
               'Environment.Exit(1); // still string data\n'
               '";\n'
               'Run();')
        view = sanitized_view(src, "P.cs")
        assert "Environment.Exit" not in view, (
            "verbatim-string payload leaked as visible code")
        assert "Run();" in view, "real code after the string was lost"

    def test_interpolated_verbatim_prefixes(self):
        for src, marker in (
            (r'var s = $@"path\"; Go();', "Go();"),
            (r'var s = @$"path\"; Go2();', "Go2();"),
        ):
            view = sanitized_view(src, "P.cs")
            assert marker in view
            assert "path" not in view

    def test_verbatim_beats_triple_quote_arm(self):
        # `@"""x"` is a verbatim string whose content starts with a
        # doubled quote — not a raw-string opener.
        view = sanitized_view('var s = @"""x"; After();', "P.cs")
        assert "After();" in view
        assert "x" not in view.replace("After();", "")

    def test_verbatim_multiline_content_blanked(self):
        src = 'var s = @"multi\nline exec( data";\nDone();\n'
        view = sanitized_view(src, "P.cs")
        assert "exec" not in view
        assert "Done();" in view
        assert view.count("\n") == src.count("\n")

    def test_raw_string_literal_backslash_is_data(self):
        # C# raw string literals (`"""…"""`) have no escapes either.
        view = sanitized_view(
            'var s = """raw exec( body""";\nNext();\n', "P.cs")
        assert "exec" not in view
        assert "Next();" in view


class TestPhpSingleQuotedStrings:
    """PHP `'…'` is a full string literal (only `\\'` and `\\\\` are
    escapes), not a C char literal. Read as a char-literal candidate,
    `'/*'` was skipped and its comment marker opened a phantom block
    comment that blanked live code after it — the swallow direction."""

    def test_block_comment_marker_in_string_is_data(self):
        src = "<?php $u='/*'; system($c);\nrun($d);"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "run($d);" in view

    def test_char_shaped_control_unchanged(self):
        view = sanitized_view("<?php $u='x'; system($c);", "a.php")
        assert "system($c);" in view
        assert "'x'" not in view

    def test_line_comment_marker_in_string_is_data(self):
        view = sanitized_view("<?php $u = 'http://x'; system($cmd);",
                              "a.php")
        assert "system($cmd);" in view
        assert "http" not in view

    def test_double_quote_inside_single_quotes_is_data(self):
        view = sanitized_view("<?php $x = 'a\"b'; system($cmd);", "a.php")
        assert "system($cmd);" in view

    def test_escaped_single_quote_does_not_close(self):
        view = sanitized_view("<?php $x = 'it\\'s /* x'; system($cmd);",
                              "a.php")
        assert "system($cmd);" in view
        assert "it" not in view

    def test_escaped_backslash_then_close(self):
        view = sanitized_view("<?php $x = 'dir\\\\'; system($cmd);",
                              "a.php")
        assert "system($cmd);" in view
        assert "dir" not in view

    def test_empty_and_adjacent_quotes(self):
        # `''` is an empty literal; `'a' . '' . 'b'` closes each one.
        view = sanitized_view(
            "<?php $x = 'a' . '' . 'b/*'; system($cmd);", "a.php")
        assert "system($cmd);" in view
        assert "$x = ' ' . '' . '   ';" in view

    def test_string_prose_blanked(self):
        view = sanitized_view("<?php $x = 'call system( here'; run($c);",
                              "a.php")
        assert "system" not in view
        assert "run($c);" in view

    def test_language_param_routes_too(self):
        view = sanitized_view("$s = '/*'; system($cmd); $t = '*/';",
                              language="php")
        assert "system($cmd);" in view

    def test_keep_strings_keeps_literal_but_not_phantom_comment(self):
        src = "<?php $u='/*'; system($c); // prose eval(\n"
        view = sanitized_view(src, "a.php", keep_strings=True)
        assert "$u='/*'; system($c);" in view
        assert "eval" not in view

    def test_unterminated_single_quote_falls_back_to_single_line(self):
        # An unterminated multi-line string means string parity is
        # untrusted: the scan falls back to single-line strings, so the
        # next line's code is SHOWN (and the view reports ambiguity).
        src = "<?php $x = 'abc\nsystem($c);"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "abc" not in view
        assert len(view) == len(src) and view.count("\n") == 1

    def test_multiline_single_quote_spans_lines(self):
        src = "<?php $q = 'SELECT a\n FROM t'; system($c);\nrun($d);"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "run($d);" in view
        assert "FROM" not in view


class TestPhpCloseTag:
    """PHP ends a one-line comment (`//` or `#`) at `?>` and leaves
    PHP mode there; inline HTML up to the next `<?` is not PHP source.
    Blanking the comment to end of line hid live code after a
    `?> … <?php` re-open (the swallow direction)."""

    def test_slash_comment_ends_at_close_tag(self):
        src = "<?php // end ?> <?php $st = $c->prepare($q);"
        view = sanitized_view(src, "a.php")
        assert "$c->prepare($q);" in view
        assert "end" not in view
        assert "?>" in view

    def test_hash_comment_ends_at_close_tag(self):
        src = "<?php # end ?> <?php $st = $c->prepare($q);"
        view = sanitized_view(src, "a.php")
        assert "$c->prepare($q);" in view
        assert "end" not in view

    def test_block_comment_ignores_close_tag(self):
        # `?>` has no meaning inside /* … */.
        view = sanitized_view("<?php /* a ?> system( */ run($c);", "a.php")
        assert "system" not in view
        assert "run($c);" in view

    def test_close_tag_in_string_is_data(self):
        view = sanitized_view('<?php $x = "?>"; // system( prose\n',
                              "a.php")
        assert "system" not in view

    def test_inline_html_apostrophe_is_not_a_string(self):
        # After `?>` the text is inline HTML: an apostrophe there must
        # not open string state over the re-opened PHP block.
        src = "<?php $a = 1; ?><p>Don't</p><?php system($c); ?>\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view

    def test_inline_html_comment_marker_is_not_a_comment(self):
        src = "<?php ?><a href=x>//</a><?= run($c) ?>\n"
        view = sanitized_view(src, "a.php")
        assert "run($c)" in view

    def test_close_tag_without_reopen_rest_is_html_data(self):
        # Inline HTML to end of input is output data: blanked in the
        # full view, verbatim in keep_strings, never lexed (the `'` and
        # `/*` there open nothing).
        src = "<?php $a = 1; ?>\n<p>it's /* html</p>\n"
        view = sanitized_view(src, "a.php")
        assert view.startswith("<?php $a = 1; ?>")
        assert "html" not in view
        assert sanitized_view(src, "a.php", keep_strings=True) == src

    def test_inline_html_hash_if_zero_is_not_a_dead_region(self):
        # PHP has no preprocessor; inline HTML spelling `#if 0` must
        # not blank a later live PHP block.
        src = "<?php $a = 1; ?>\n#if 0\n<?php system($c); ?>\n#endif\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view

    def test_close_tag_rule_is_php_only(self):
        # In C a `?>` inside a line comment is comment text.
        view = sanitized_view("x(); // a ?> run(c);\n", "a.c")
        assert "run" not in view


class TestPhpAttributes:
    """PHP 8 `#[…]` is an attribute (code), not a `#` comment —
    blanking from it hid the rest of the line."""

    def test_attribute_is_code(self):
        src = "<?php #[Pure] function f() { system($c); }\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "#[Pure]" in view

    def test_attribute_string_argument_blanked(self):
        src = "<?php #[Route('/a/*')] function f() { run($c); }\n"
        view = sanitized_view(src, "a.php")
        assert "run($c);" in view
        assert "/a/*" not in view

    def test_plain_hash_comment_still_blanked(self):
        view = sanitized_view("<?php # [not attr] system(\nrun($c);\n",
                              "a.php")
        assert "system" not in view
        assert "run($c);" in view


class TestRustNestedBlockComments:
    """Rust block comments NEST (the Rust reference) — closing at the
    first `*/` left interior comment prose visible as code."""

    def test_nested_block_comment_fully_blanked(self):
        src = "a();\n/* outer /* inner */ check_perm() */\nrun();\n"
        view = sanitized_view(src, "lib.rs")
        assert "check_perm" not in view
        assert "run();" in view
        assert view.count("\n") == src.count("\n")

    def test_language_param_routes_too(self):
        view = sanitized_view("/* a /* b */ hidden( */ run(c);",
                              language="rust")
        assert "hidden" not in view
        assert "run(c);" in view

    def test_c_block_comments_still_do_not_nest(self):
        view = sanitized_view("/* a /* b */ run(c);", "a.c")
        assert "run(c);" in view


class TestHashTripleQuotes:
    """Triple-quoted literals honour the language's escape model: a
    backslash-escaped quote run inside a Python triple string is data,
    not the closer
    (closing there blanked live code after the real closer). An
    unterminated triple blanks to end of input — the last three
    characters too."""

    def test_python_escaped_triple_quote_is_data(self):
        src = 'x = """a \\""" b"""; os.system(c)'
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view
        assert " b" not in view

    def test_python_raw_triple_escaped_quote_is_data(self):
        # Even in a raw literal a backslash keeps the quote from
        # terminating the string.
        src = 'x = r"""a \\""" b"""; os.system(c)'
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view

    def test_python_unterminated_triple_blanks_to_eof(self):
        view = sanitized_view("x = '''abc\nos.system(c)", "a.py")
        assert "system" not in view
        assert "(c)" not in view

    def test_toml_literal_triple_has_no_escapes(self):
        # TOML ''' literal strings have no escapes — the backslash is
        # data and the first ''' closes.
        src = "k = '''a\\''' ; hostile = 1\nnext = 2"
        view = sanitized_view(src, file_path="c.toml")
        assert "; hostile = 1" in view
        assert "next = 2" in view

    def test_python_triple_comment_marker_is_data(self):
        src = 'x = """a # b\n\' c"""; os.system(c)'
        view = sanitized_view(src, "a.py")
        assert "os.system(c)" in view


class TestLexicalResidualsPinned:
    """Constructs the sanitized view deliberately does NOT model —
    pinned so a change is visible. Perl quote-like operators (q qq qw
    qx m qr s tr y with arbitrary/bracketed delimiters) and heredocs
    are a sub-grammar with regex-vs-division and bareword ambiguity,
    not a local lexer fix; perl guards must read raw text (prefilter.py
    perl branch)."""

    def test_perl_hash_in_regex_residual(self):
        # `#` inside qr/…/, s/…//, m/…/ and `=~ /…/` reads as a comment
        # and blanks the rest of the line (swallow direction).
        for src in ("my $re = qr/#/; my $o = encode_entities($q);",
                    "$s =~ s/#//r; my $o = encode_entities($q);",
                    "if ($x =~ m/#/) { encode_entities($q); }",
                    "if ($x =~ /#/) { encode_entities($q); }"):
            view = sanitized_view(src, language="perl")
            assert "encode_entities" not in view, src

    def test_perl_quote_like_and_heredoc_text_residual(self):
        # q{}/qq{}/heredoc bodies stay visible as code (over-inclusion
        # direction).
        assert "escape" in sanitized_view(
            "my $x = q{CGI::escape later}; print $y;", language="perl")
        assert "encode_entities" in sanitized_view(
            "my $x = qq{encode_entities later}; print $y;",
            language="perl")
        assert "encode_entities" in sanitized_view(
            "print <<EOT;\nencode_entities here\nEOT\nprint $y;",
            language="perl")

    def test_php_leading_text_inline_html_residual(self):
        # DECLARED residual: a source whose leading inline text does
        # NOT start with markup (plain text before the first `<?`)
        # starts in PHP mode — snippets carry no open tag — so an
        # apostrophe there opens string state up to the next quote.
        src = "Don't edit <?php run($a); ?> 'x'\n<?php system($c); ?>\n"
        view = sanitized_view(src, "a.php")
        assert "run($a);" not in view

    def test_php_leading_markup_with_inline_php(self):
        src = "<p>Don't <?php run($a); ?></p>\n<?php system($c); ?>\n"
        view = sanitized_view(src, "a.php")
        assert "run($a);" in view
        assert "system($c);" in view

    def test_unterminated_single_line_strings_stop_at_eol(self):
        for src, fp, live in (('x = "abc\nsystem(c);', "a.c", "system(c);"),
                              ("x = 'abc\nsystem(c);", "a.js", "system(c);"),
                              ("x = 'abc\nos.system(c)", "a.py",
                               "os.system(c)")):
            assert live in sanitized_view(src, fp), (fp, src)

    def test_js_template_literal_forms_unchanged(self):
        view = sanitized_view("x = `${ {a:'}'}.a }`; run(c);", "a.js")
        assert "run(c);" in view
        view = sanitized_view("x = `line1\n' system(\n`; run(c);", "a.js")
        assert "system" not in view and "run(c);" in view


_INVARIANT_CORPUS = [
    ("<?php $u='/*'; system($c);\nrun($d); // x ?> <p>it's</p><?php\n"
     "#[A('x')] function f() { return 'a\\'b'; } # c\n$h = <<<EOT\n"
     "body {$o->m('/*')}\nEOT;\n", "a.php"),
    ("a();\n/* o /* i */ x */ b(); // c\nlet s = r#\"/* \"#;\n", "a.rs"),
    ('x = """a \\""" b"""; y()\nz = \'\'\'q\n', "a.py"),
    ("my $re = qr/#/; f();\n=pod\nx\n=cut\nprint <<EOT;\nb\nEOT\n", "a.pl"),
    ("x = `a ${b('/*')} c`; /re\\//; d(); // e\n", "a.js"),
    ("int a = 'x'; /* b\n c */ d(\"//\"); // e\\\nf\n", "a.c"),
]


class TestOffsetInvariants:
    """Every view keeps length and newline positions 1:1, and every
    character it does not blank is the original character (code is
    never rewritten, only blanked)."""

    def test_length_newlines_and_untouched_code(self):
        for src, fp in _INVARIANT_CORPUS:
            for keep in (False, True):
                view = sanitized_view(src, fp, keep_strings=keep)
                assert len(view) == len(src), fp
                assert ([i for i, c in enumerate(view) if c == "\n"]
                        == [i for i, c in enumerate(src) if c == "\n"]), fp
                assert all(v == s for v, s in zip(view, src)
                           if v != " "), fp


class TestLineCommentSplicing:
    """Backslash-newline splicing (translation phase 2) exists only in
    the C preprocessor languages: there a `// … \\` comment continues
    onto the next physical line. Every other C-family language ends a
    `//` comment at the newline — splicing there blanked the next LIVE
    line (the swallow direction)."""

    _SRC = "x = 1; // note \\\nexec(cmd);\ny = 2;\n"

    def test_non_splicing_languages_keep_next_line_live(self):
        for fp in ("A.java", "a.js", "a.ts", "a.go", "lib.rs", "A.cs",
                   "A.kt", "m.swift"):
            view = sanitized_view(self._SRC, fp)
            assert "exec(cmd);" in view, fp
            assert "note" not in view, fp
            assert len(view) == len(self._SRC), fp

    def test_php_keeps_next_line_live(self):
        src = "<?php $x = 1; // note \\\nsystem($c);\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "note" not in view

    def test_language_param_routes_too(self):
        for lang in ("java", "javascript", "typescript", "go", "rust",
                     "csharp", "kotlin", "swift", "php"):
            view = sanitized_view(self._SRC, language=lang)
            assert "exec(cmd);" in view, lang

    def test_crlf_non_splicing_language(self):
        src = "x = 1; // note \\\r\nexec(cmd);\r\n"
        assert "exec(cmd);" in sanitized_view(src, "A.java")

    def test_c_and_cpp_still_splice(self):
        for fp in ("x.c", "x.h", "x.cc", "x.cpp", "x.hpp"):
            view = sanitized_view(self._SRC, fp)
            assert "exec" not in view, fp
            assert "y = 2;" in view, fp
        for lang in ("c", "cpp"):
            assert "exec" not in sanitized_view(self._SRC, language=lang)

    def test_unknown_extension_keeps_c_preprocessor_default(self):
        # Unmapped extensions (.inc/.ipp/.inl/.cu/.m …) are mostly
        # C-preprocessed headers/sources — the C default is kept.
        assert "exec" not in sanitized_view(self._SRC, "x.inc")


class TestPhpStringStateOwnsCloseTag:
    """`?>` closes PHP only in CODE state. PHP '…', "…" and backtick
    strings may span lines; with a single-line stop, a `?>` on a
    continuation line (a multi-line XML prolog) or inside a backtick
    string read as a close tag and left the rest of the function
    unlexed — real comments after it re-exposed as code."""

    _F = "<?php\nfunction f($f) {\n%s\n  return file_get_contents($f);\n}\n"

    def _view(self, body):
        return sanitized_view(self._F % body, "a.php")

    def test_close_tag_on_multiline_single_quote_continuation(self):
        view = self._view("  $x = 'a\n?>';\n  // basename")
        assert "basename" not in view
        assert "return file_get_contents($f);" in view

    def test_close_tag_on_multiline_double_quote_continuation(self):
        view = self._view('  $x = "<b>\n?></b>";\n  // basename')
        assert "basename" not in view

    def test_close_tag_inside_backtick_string(self):
        view = self._view("  $o = `echo ?>`;\n  // basename")
        assert "basename" not in view
        assert "echo" not in view

    def test_multiline_xml_prolog_then_comment_and_string(self):
        prolog = "  $xml = '<?xml version=\"1.0\"\n    encoding=\"UTF-8\"?>';\n"
        view = self._view(prolog + "  // TODO: basename")
        assert "basename" not in view
        view = self._view(prolog + "  error_log('no realpath here');")
        assert "realpath" not in view
        assert "error_log(" in view

    def test_multiline_single_quote_closing_line_code_live(self):
        src = "<?php\n$sql = 'SELECT *\n  WHERE id = ' . $_GET['id']; system($c);\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert "WHERE" not in view
        assert view.count("\n") == src.count("\n")

    def test_multiline_string_middle_line_prose_blanked(self):
        view = self._view("  $h = 'Usage:\n we call basename later';")
        assert "basename" not in view
        view = self._view('  $h = "Usage:\n we call basename later";')
        assert "basename" not in view

    def test_backtick_complex_interpolation_stays_visible(self):
        view = sanitized_view('<?php $o = `ls {$db->query($x)} -l`;', "a.php")
        assert "$db->query($x)" in view
        assert "ls" not in view

    def test_inline_html_is_output_data(self):
        # Inline HTML is output (echoed data), never code: blanked in
        # the full view like a string literal, kept in keep_strings.
        src = ("<?php\nfunction f($f) { ?>\n<p>names are basename-checked</p>\n"
               "<?php return file_get_contents($f); }\n")
        view = sanitized_view(src, "a.php")
        assert "basename" not in view
        assert "return file_get_contents($f);" in view
        kept = sanitized_view(src, "a.php", keep_strings=True)
        assert "basename-checked" in kept

    def test_short_echo_tag_reopens_code(self):
        # `<?=` re-enters PHP: a comment after it is a real comment.
        src = "<?php ?><p>x</p><?= $a; // system( prose\n"
        view = sanitized_view(src, "a.php")
        assert "system" not in view
        assert "$a;" in view

    def test_leading_markup_before_first_open_tag_is_unlexed(self):
        # A source starting with markup: the apostrophe in the leading
        # HTML must not open string state over the code. Whole template
        # vs markup-shaped fragment is a guess, so the leading run is
        # shown verbatim (and reported), never blanked.
        src = "<p>Don't</p>\n<?php\nfunction f() { system($c); $x = 'a'; }\n"
        view = sanitized_view(src, "a.php")
        assert "system($c);" in view
        assert view.startswith("<p>Don't</p>\n<?php")
        assert "$x = ' ';" in view

    def test_snippet_starting_with_heredoc_is_code(self):
        # A segment cut at a heredoc opener is PHP code, not markup.
        src = "<<<EOT\nbody system( prose\nEOT;\nrun($c); // note\n"
        view = sanitized_view(src, "a.php")
        assert "system" not in view
        assert "run($c);" in view
        assert "note" not in view


class TestTomlTripleUnterminated:
    def test_unterminated_literal_triple_blanks_to_eof(self):
        # The no-escape (plain find) branch also blanks through end of
        # input — none of the last three characters leak.
        view = sanitized_view("k = '''abc\nsystem(x)", file_path="c.toml")
        assert "system" not in view
        assert "(x)" not in view


from core.audit.source_view import (  # noqa: E402
    SanitizedView, sanitized_view_with_status,
)


def _st(src, fp="a.php", **kw):
    return sanitized_view_with_status(src, fp, **kw)


class TestStatusApi:
    """`sanitized_view_with_status` returns the SAME text as
    `sanitized_view` plus the ambiguity report; `sanitized_view` keeps
    its signature and str return for every existing caller."""

    def test_text_identical_to_sanitized_view(self):
        for src, fp in _INVARIANT_CORPUS + [
                ("#[todo] don't\n$m = 'x';\n", "a.php"),
                ("<p>a</p><?php run(); ?><? x ?>\n", "a.php"),
                ("x = '''abc\n", "a.py"), ("--[[ a\n", "a.lua"),
                ("/* a\n", "A.java")]:
            for keep in (False, True):
                st = sanitized_view_with_status(src, fp, keep_strings=keep)
                assert isinstance(st, SanitizedView)
                assert st.text == sanitized_view(src, fp, keep_strings=keep)
                assert st.ambiguous == bool(st.reasons)
                assert list(st.reasons) == sorted(set(st.reasons))

    def test_language_param_routes_status(self):
        st = sanitized_view_with_status("x = '''abc\n", language="python")
        assert st.reasons == ("unterminated-triple-string",)

    def test_clean_sources_are_unambiguous(self):
        for src, fp in (("<?php #[Pure] function f() { system($c); }\n", "a.php"),
                        ("<?php $a = 'x'; ?><p>y</p><?= $b ?>\n", "a.php"),
                        ("int a = 1; /* c */\n", "a.c"),
                        ('x = """a"""\n', "a.py"), ("", "a.php")):
            st = _st(src, fp)
            assert st.ambiguous is False and st.reasons == (), (fp, src)

    def test_sanitized_view_still_returns_str(self):
        assert type(sanitized_view("<?php $a;", "a.php")) is str


class TestPhpHashBracketAmbiguity:
    """PHP-7 `#[…]` comment vs PHP-8 attribute: unambiguous only when
    the bracket parses as an attribute group on its line and what
    follows can follow an attribute. Otherwise the line is shown
    verbatim (never lexed — a prose apostrophe cannot flip string
    parity for the rest of the function) and reported."""

    def test_prose_after_bracket_is_verbatim_and_bounded(self):
        src = ("function f($p) {\n    #[todo] don't\n"
               "    $m = 'we call basename later';\n    unlink($p);\n}\n")
        st = _st(src)
        assert "php-hash-bracket" in st.reasons
        assert "#[todo] don't" in st.text
        assert "basename" not in st.text
        assert "unlink($p);" in st.text
        assert "unlink($p);" in _st(src, keep_strings=True).text

    def test_comment_markers_in_later_strings_do_not_swallow(self):
        # `#[…] don't` then '/*' … '*/' must not swallow the sink
        # out of the keep (comments-only) view.
        src = ("function f($c) {\n #[todo] don't\n $a = '/*';\n"
               " unlink($c);\n $b = '*/';\n}\n")
        for keep in (False, True):
            assert "unlink($c);" in _st(src, keep_strings=keep).text

    def test_unclosed_bracket_is_ambiguous(self):
        st = _st("<?php #[not closed system( prose\nrun($c);\n")
        assert "php-hash-bracket" in st.reasons
        assert "run($c);" in st.text

    def test_valid_attribute_forms_are_not_ambiguous(self):
        for src in ("<?php #[Pure] function f() { system($c); }\n",
                    "<?php function f(#[SensitiveParameter] $x) {}\n",
                    "<?php function f(#[A] string $x, #[B] ?int $y) {}\n",
                    "<?php #[A, B(1, 'x]')] class X {}\n",
                    "<?php #[Route('/a', methods: ['GET'])]\n"
                    "function f() {}\n",
                    "<?php #[A] #[B] public function f() {}\n"):
            st = _st(src)
            assert "php-hash-bracket" not in st.reasons, src


class TestPhpInlineHtmlAmbiguity:
    def test_bare_short_tag_in_html_is_verbatim(self):
        # short_open_tag unknown: `<? 3, don't` is HTML (Off) or code
        # (On). Shown verbatim up to the next unambiguous open tag.
        src = ("<?php ?><p>2 <? 3, don't</p><?php system($c);"
               " $m = 'basename later';\n")
        st = _st(src)
        assert "php-short-open-tag" in st.reasons
        assert "system($c);" in st.text
        assert "basename" not in st.text
        assert "<? 3, don't</p>" in st.text

    def test_bare_short_tag_region_ends_at_close_tag(self):
        src = "<?php ?>aa<? x ?>bb<?php run();\n"
        st = _st(src)
        assert "<? x ?>" in st.text
        assert "aa" not in st.text and "bb" not in st.text
        assert "run();" in st.text

    def test_xml_prolog_in_html_is_reported(self):
        st = _st("<?php ?><?xml version='1.0'?><r/><?php run();\n")
        assert "php-short-open-tag" in st.reasons
        assert "run();" in st.text

    def test_script_language_php_is_verbatim(self):
        src = ('<?php ?><script language="php"> system($c); </script>'
               "<p>x</p>\n")
        st = _st(src)
        assert "php-script-tag" in st.reasons
        assert "system($c);" in st.text

    def test_unambiguous_open_tags_are_not_reported(self):
        st = _st("<?php ?><p>x</p><?php run(); ?><b>y</b><?= $z ?>\n")
        assert st.reasons == ()


class TestPhpLeadingState:
    def test_leading_bom_is_reported(self):
        st = _st("\ufeff<?php system($c);\n")
        assert st.reasons == ("php-leading-bom",)
        assert "system($c);" in st.text

    def test_bom_then_markup_apostrophe_does_not_swallow(self):
        src = "\ufeff<html>don't\n<?php system($c); $m = 'c';\n"
        st = _st(src)
        assert {"php-leading-bom", "php-leading-markup"} <= set(st.reasons)
        assert "system($c);" in st.text

    def test_leading_markup_is_reported_and_kept_in_both_views(self):
        src = "<p>it's</p><?php system($c);\n"
        for keep in (False, True):
            st = _st(src, keep_strings=keep)
            assert st.reasons == ("php-leading-markup",)
            assert st.text == src

    def test_leading_whitespace_before_markup(self):
        src = "\n<p>don't</p>\n<?php system($c);\n"
        st = _st(src)
        assert "php-leading-markup" in st.reasons
        assert "system($c);" in st.text

    def test_fragment_starting_with_markup_and_no_open_tag_is_shown(self):
        src = "<div>{$x->run()}</div>\nsystem($c);\n"
        st = _st(src)
        assert st.text == src
        assert "php-leading-markup" in st.reasons

    def test_operator_led_fragments_are_code(self):
        # `<=`/`< $x` continuation lines are code, never markup.
        for src in ("<= $x; system($c); // note\n",
                    "< $max) {\n  system($c); // note\n"):
            st = _st(src)
            assert "system($c);" in st.text and "note" not in st.text
            assert st.reasons == (), src

    def test_leading_open_tag_not_reported(self):
        assert _st("  <?php run();\n").reasons == ()

    def test_hash_if_zero_in_verbatim_markup_is_not_a_dead_region(self):
        src = "<p>\n#if 0\n</p>\n<?php system($c);\n# endif\n"
        assert "system($c);" in sanitized_view(src, "a.php")


class TestUnterminatedReported:
    """A multi-line construct that runs off the end of the input is
    reported (`unterminated-*`). Single-line literals stop at their
    newline and are not reported."""

    CASES = [
        ("<?php $x = 'abc\nrun();", "a.php", "php-unterminated-string"),
        ('<?php $x = "abc\nrun();', "a.php", "php-unterminated-string"),
        ("<?php $x = `abc\nrun();", "a.php", "php-unterminated-string"),
        ("<?php $x = <<<EOT\nbody\n", "a.php", "php-unterminated-heredoc"),
        ("a();\n/* never closed\n", "a.c", "unterminated-block-comment"),
        ("a()\n/* /* */ open\n", "A.kt", "unterminated-block-comment"),
        ('String s = """\nbody\n', "A.java", "unterminated-text-block"),
        ('var s = @"abc\n', "A.cs", "unterminated-verbatim-string"),
        ('auto s = R"d(abc\n', "a.cpp", "unterminated-raw-string"),
        ('let s = r#"abc\n', "a.rs", "unterminated-raw-string"),
        ("s := `abc\n", "a.go", "unterminated-raw-string"),
        ("x = `abc ${y}\n", "a.js", "unterminated-template-literal"),
        ("x = '''abc\n", "a.py", "unterminated-triple-string"),
        ("k = '''abc\n", "c.toml", "unterminated-triple-string"),
        ("=pod\nprose\n", "a.pl", "unterminated-doc-block"),
        ("=begin\nprose\n", "a.rb", "unterminated-doc-block"),
        ("x = 1 --[[ open\n", "a.lua", "unterminated-long-bracket"),
        ("x = [[ open\n", "a.lua", "unterminated-long-bracket"),
    ]

    def test_each_form_reports(self):
        for src, fp, reason in self.CASES:
            assert reason in _st(src, fp).reasons, (fp, src)

    def test_terminated_forms_do_not_report(self):
        for src, fp in (("<?php $x = 'a\nb'; $y = \"c\nd\"; $z = `e`;\n", "a.php"),
                        ("<?php $x = <<<EOT\nbody\nEOT;\n", "a.php"),
                        ("/* a */ /* b\n*/\n", "a.c"),
                        ('s = """a"""\n', "A.java"), ('s = @"a"\n', "A.cs"),
                        ('s = R"d(a)d"\n', "a.cpp"), ('s = r#"a"#\n', "a.rs"),
                        ("s := `a`\n", "a.go"), ("x = `a${b}`\n", "a.js"),
                        ("x = '''a'''\n", "a.py"), ("=pod\nx\n=cut\n", "a.pl"),
                        ("=begin\nx\n=end\n", "a.rb"), ("--[[ a ]]\n", "a.lua"),
                        ("x = 'unterminated single line", "a.c")):
            assert _st(src, fp).reasons == (), (fp, src)

    def test_unterminated_heredoc_falls_back_to_code(self):
        st = _st("<?php $x = <<<EOT\nsystem($c);\n")
        assert "system($c);" in st.text


class TestPhpParityFallback:
    """Any quote the lexer mis-reads flips PHP string parity for the
    rest of the input; that always ends in an unterminated literal at
    end of input. The scan then falls back to single-line strings with
    inline HTML shown (damage bounded per line, code shown) and
    reports `php-unterminated-string`."""

    def test_stray_quote_bounded_to_its_line(self):
        src = "<?php $s = 'a'b'; system($c);\nrun();\n$t = 'x';\n"
        st = _st(src)
        assert "php-unterminated-string" in st.reasons
        assert "run();" in st.text
        assert "$t = ' ';" in st.text

    def test_fallback_shows_inline_html(self):
        src = "<?php $x = 'a\n?><p>basename</p>\n"
        st = _st(src)
        assert st.ambiguous
        assert "basename" in st.text

    def test_backtick_string_closes_on_backtick_not_double_quote(self):
        view = sanitized_view('<?php $r = `echo "x"`; system($c);\n', "a.php")
        assert "system($c);" in view
        assert "echo" not in view


class TestHeredocTerminatorIndex:
    """The terminator lookup is an index, exactly equivalent to a
    `^[ \\t]*IDENT(?!<label char>)` search under PHP's label rule
    (ASCII word characters and every non-ASCII character continue a
    label)."""

    def test_terminator_shapes(self):
        from core.audit.source_view import _HeredocTerminators
        import re as _re
        src = ("<?php $a = <<<EOT\nEOTX\n  EOTé;\nEOT;\n"
               "$b = <<<ÜB\nx\n ÜB;\n")
        idx = _HeredocTerminators(src)
        for ident in ("EOT", "EOTX", "ÜB", "NOPE", "ÜX"):
            for start in range(len(src) + 1):
                m = _re.compile(
                    rf"^[ \t]*{_re.escape(ident)}(?![0-9A-Za-z_\u0080-\U0010ffff])",
                    _re.M).search(src, start)
                want = None if m is None else (m.start(), m.end())
                got = idx.find(ident, start)
                assert (None if got is None else got[:2]) == want, (ident, start)

    def test_long_and_non_ascii_labels(self):
        from core.audit.source_view import _HeredocTerminators
        import re as _re
        lab = "L" * 130
        src = (f"<?php $a = <<<{lab}\n{lab}X\n{lab}\u00e9;\n"
               f"{lab}Y\u00e9\n {lab};\n" + "\u00e9" * 300 + "\n")
        idx = _HeredocTerminators(src)
        for ident in (lab, lab + "X", lab + "Y", lab + "Z",
                      "\u00e9" * 129, "\u00e9" * 300, "\u00e9" * 5):
            for start in range(0, len(src) + 1, 7):
                m = _re.compile(
                    rf"^[ \t]*{_re.escape(ident)}(?![0-9A-Za-z_\u0080-\U0010ffff])",
                    _re.M).search(src, start)
                want = None if m is None else (m.start(), m.end())
                got = idx.find(ident, start)
                assert (None if got is None else got[:2]) == want, (ident[:5], start)

    def test_many_unterminated_heredocs_view(self):
        src = "<?php " + "<<<A\n" * 50 + "run($c);\n"
        st = _st(src)
        assert "php-unterminated-heredoc" in st.reasons
        assert "run($c);" in st.text


class TestPhpHeredocLabelRules:
    """Heredoc labels follow PHP's label rule: ASCII letters, digits,
    `_` and every byte 0x80-0xff continue a label. A body line `Té "x`
    is NOT the closer of `<<<T` (it is the longer label `Té`) — taking
    it as one closed the heredoc early and flipped quote parity over
    live code, silently (ambiguous=False)."""

    def test_non_ascii_letter_continues_the_label(self):
        src = ('<?php\n$m = <<<T\nTé "x\nT;\n'
               'system($_GET["f"]); echo "?>";\n')
        st = _st(src)
        assert 'system($_GET[' in st.text
        assert '"x' not in st.text
        kept = _st(src, keep_strings=True).text
        assert 'system($_GET["f"]);' in kept

    def test_non_word_non_ascii_label_opens_a_heredoc(self):
        src = "<?php $x = <<<EOT€\nbody /* x\nEOT€;\nsystem($c);\n"
        st = _st(src)
        assert "body" not in st.text
        assert "system($c);" in st.text
        assert st.reasons == ()

    def test_digit_first_is_not_a_label(self):
        # `<<<1A` is a shift-left, not a heredoc opener.
        st = _st("<?php $x = $a <<<1A\nsystem($c); // note\n")
        assert "system($c);" in st.text and "note" not in st.text

    def test_pre_73_closer_is_certain(self):
        st = _st("<?php $x = <<<EOT\nbody\nEOT;\nrun($c);\n")
        assert st.reasons == () and "run($c);" in st.text

    def test_flexible_closer_is_reported_and_taken(self):
        # Indented closers and `EOT);` are closers only on PHP >= 7.3;
        # that reading shows more code, and the guess is reported.
        for src in ("<?php $x = <<<EOT\n  body\n  EOT;\nrun($c);\n",
                    "<?php f(<<<EOT\nbody\nEOT, $y); run($c);\n"):
            st = _st(src)
            assert "php-heredoc-closer" in st.reasons, src
            assert "run($c);" in st.text and "body" not in st.text


class TestPhpAttributeFollowers:
    """An attribute can precede only a declaration (function, closure,
    arrow fn, class-like, class member), a parameter inside a
    parameter list, or `class` after `new`. A statement after `#[…]`
    means the PHP 7 comment reading is the only valid one — reported
    as `php-hash-bracket` (the line is shown verbatim)."""

    def test_statement_after_bracket_is_ambiguous(self):
        for src in ("<?php\n#[note] $arg = escapeshellarg($arg);\n"
                    "exec(\"ls \" . $arg);\n",
                    "<?php\n#[old] new Guard($x);\n",
                    "<?php\n#[x] , basename($p);\n",
                    "<?php\n#[note]\n$arg = escapeshellarg($arg);\n",
                    "<?php\nfoo();\n#[A] ?>x\n"):
            st = _st(src)
            assert "php-hash-bracket" in st.reasons, src

    def test_declaration_and_parameter_followers(self):
        for src in ("<?php $o = new #[A] class {};\n",
                    "<?php #[A]\n/** doc */\npublic function f() {}\n",
                    "<?php #[A] // why\nfunction f() {}\n",
                    "<?php function f(\n    #[Sensitive] $x,\n"
                    "    #[A] #[B] int $y,\n    #[C] ...$z\n) {}\n",
                    "<?php $r = array_map(#[A] fn($x) => $x, $a);\n",
                    "<?php $f = #[A] static function () {};\n",
                    "<?php class C { #[A] public int $p;"
                    " #[B] const X = 1; }\n",
                    "<?php #[A, ] function f() {}\n"):
            st = _st(src)
            assert "php-hash-bracket" not in st.reasons, src

    def test_digit_attribute_name_is_ambiguous(self):
        st = _st("<?php #[1]\nfunction f() {}\n")
        assert "php-hash-bracket" in st.reasons

    def test_ambiguous_region_stops_at_close_tag(self):
        # Both readings leave PHP at `?>`; the HTML after it is output
        # data (blanked), not part of the verbatim region.
        src = "<?php #[x] it's ?> <b>'x</b> <?php run();\n"
        st = _st(src)
        assert "<b>" not in st.text
        assert "run();" in st.text
        assert "#[x] it's ?>" in st.text


class TestPhpTagAndFallbackCells:
    """Cells pinning leading-state and fallback details."""

    def test_xml_prolog_start_is_short_tag_not_markup(self):
        src = '<?xml version="1.0"?>\n<?php\nrun($f);\n'
        st = _st(src)
        assert st.reasons == ("php-short-open-tag",)
        assert st.text == src

    def test_closing_tag_start_is_markup(self):
        st = _st("</div>\n<?php run();\n")
        assert st.reasons == ("php-leading-markup",)

    def test_php_tag_needs_whitespace(self):
        st = _st("<?phpx run();\n")
        assert "php-short-open-tag" in st.reasons

    def test_fallback_double_quote_is_single_line(self):
        src = "<?php\n$a = 'x\n$b = \"y\nrun();\n$c = 1;\n"
        st = _st(src)
        assert "php-unterminated-string" in st.reasons
        assert "run();" in st.text and "$c = 1;" in st.text


class TestPhpViewLinearTime:
    """Hostile shapes that were quadratic stay linear."""

    def test_attribute_chain_on_one_line(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        src = "<?php\n" + "#[A]" * 400000 + "\nfunction f() {}\n"
        start = time.monotonic()
        st = _st(src)
        assert time.monotonic() - start < 30.0
        assert st.reasons == ()

    def test_unterminated_long_label_heredocs(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        lab = "A" * 130
        src = "<?php\n" + "".join(
            f"$x = <<<{lab}B\n{lab}C\n" for _ in range(16000))
        start = time.monotonic()
        st = _st(src)
        assert time.monotonic() - start < 30.0
        assert "php-unterminated-heredoc" in st.reasons


class TestPhpMultiLineAttributes:
    """A well-formed PHP 8 attribute may span lines (Symfony/Doctrine
    style) and may be followed by a comment before its declaration —
    neither is ambiguous (flagging them disabled suppressors for the
    whole function)."""

    def test_multi_line_attribute_is_not_ambiguous(self):
        src = ("<?php\n#[Route(\n    '/dl',\n    name: 'dl',\n)]\n"
               "public function dl($p) { return realpath($p); }\n")
        st = _st(src)
        assert st.reasons == ()
        assert "'   '" in st.text and "realpath($p)" in st.text

    def test_attribute_then_comment_then_declaration(self):
        for src in ("<?php\n#[Pure] // cached\nfunction f() {}\n",
                    "<?php\n#[Pure] /* cached */ function f() {}\n",
                    "<?php\n#[\n  A,\n  B(1),\n]\n# why\nfinal class C {}\n"):
            assert _st(src).reasons == (), src

    def test_multi_line_attribute_before_statement_is_ambiguous(self):
        st = _st("<?php\n#[A(\n1)]\n$x = guard($x);\n")
        assert "php-hash-bracket" in st.reasons

    def test_attribute_past_the_span_cap_is_ambiguous(self):
        st = _st("<?php\n#[A(" + "x" * 5000 + ")]\nfunction f() {}\n")
        assert "php-hash-bracket" in st.reasons


class TestJsRegexAfterParen:
    """After `)` a `/` divides unless the paren closed an
    if/while/for/with head (then a statement — a regex — follows).
    Parens are tracked on the forward scan, so parens inside strings,
    comments and regexes never count; a `)` with no open `(` keeps the
    division reading and is reported."""

    def test_regex_after_control_head(self):
        for src in ("if (p) /(/.test(p);\n",
                    "while (x) /a\\//.exec(y);\n",
                    "for (;;) /[(]/g.exec(s);\n",
                    "if (s === \")\") /(/.test(s);\n"):
            st = sanitized_view_with_status(src, "a.js")
            code = st.text
            assert code.count("(") == code.count(")"), src
            assert st.reasons == (), src

    def test_division_after_expression_paren(self):
        src = "x = (a + b) / 2 / c; y = f(x) / g(z) / 3;\n"
        st = sanitized_view_with_status(src, "a.js")
        assert st.text == src and st.reasons == ()

    def test_unmatched_paren_keeps_division_and_reports(self):
        st = sanitized_view_with_status("a) / 2; // c\n", "a.js")
        assert "js-regex-after-paren" in st.reasons
        assert "a) / 2;" in st.text and "c" not in st.text.split(";")[1]

    def test_template_and_comment_parens_do_not_count(self):
        src = "if (a) /* ) */ /(/.test(b); f(`)`) / 2;\n"
        st = sanitized_view_with_status(src, "a.js")
        assert st.reasons == ()
        assert "/ 2;" in st.text


class TestPhpAttributeContextCells:
    def test_after_new_only_class_may_follow(self):
        # `new #[A] function () {}` is not valid PHP 8 — only the PHP 7
        # comment reading remains.
        st = _st("<?php $o = new #[A] function () {};\n")
        assert "php-hash-bracket" in st.reasons

    def test_unclosed_comment_after_attribute_is_ambiguous(self):
        st = _st("<?php #[A] /* never closed\nfunction f() {}\n")
        assert "php-hash-bracket" in st.reasons


def _js(src, fp="a.js"):
    return sanitized_view_with_status(src, fp)


class TestJsControlHeadKeywordPosition:
    """`if`/`while`/`for`/`with` start a control head only as statement
    keywords: a member/private access (`.for(`, `?.if(`, `#for(`) or a
    `$`-identifier is a call expression whose `)` is followed by
    division. `for await (` and a comment between keyword and `(` are
    still control heads."""

    def test_member_calls_named_like_keywords_divide(self):
        for src in ("const k = Symbol.for(name) / 2; exec(cmd); z = b / 3;\n",
                    "const t = arr.with(i, v) / n; cp.exec(cmd); r = a / b;\n",
                    "x = o?.if(a) / 2; ev(code); y = c / d;\n",
                    "x = obj . for (k) / 2; ev(code); y = c / d;\n",
                    "class C { #for(x){return x} m(){ return this.#for(1)"
                    " / 2; ev(c); q = a / 3; } }\n",
                    "y = $if(k) / 2; exec(c); z = a / b;\n"):
            st = _js(src)
            assert st.text == src, src
            assert st.reasons == (), src

    def test_while_and_with_heads_are_control(self):
        for src in ("while (i--) /'/.test(s) && exec(s);\nrun(t);\n",
                    "with (o) /'/.test(s) && exec(s);\nrun(t);\n"):
            st = _js(src)
            assert "exec(s);" in st.text and "run(t);" in st.text, src
            assert "'" not in st.text, src

    def test_for_await_and_commented_heads_are_control(self):
        for src in ("for await (const l of s) /'/.test(l) && exec(l);\n"
                    "foo(bar);\n",
                    "if /*c*/ (s) /\"/.test(s) && exec(s);\nexec(t);\n",
                    "if // why\n(s) /\"/.test(s) && exec(s);\nexec(t);\n"):
            st = _js(src)
            assert "&& exec(" in st.text, src
            assert '"' not in st.text and "'" not in st.text, src
            assert st.reasons == (), src


class TestJsSlashAfterRegexLiteral:
    def test_slash_after_regex_literal_divides(self):
        src = "x = /a/ / 2; run(c); y = b / 3;\n"
        st = _js(src)
        assert "run(c);" in st.text and st.reasons == ()


class TestPhpAttributeParamListContext:
    """`param` context requires the open `(` to be a function/fn/closure
    declaration's parameter list; call arguments, arrays and `if (`
    conditions are not. `static` is a declaration start only before
    `function`/`fn` or as a class-member modifier."""

    def test_non_declaration_parens_are_not_param_lists(self):
        for src in ("<?php\n$r = run($cmd, #[todo] $opts = esc($cmd)\n);\n",
                    "<?php\n$a = [$x, #[note] $safe = h($x)\n];\n",
                    "<?php\nif (#[todo] $ok = check($x)\n) {}\n"):
            st = _st(src)
            assert "php-hash-bracket" in st.reasons, src

    def test_declaration_param_lists(self):
        for src in ("<?php function f(#[A] $x, #[B] int $y) {}\n",
                    "<?php function &f(#[A] $x) {}\n",
                    "<?php $g = function (#[A] $x) use ($y) {};\n",
                    "<?php $h = fn(#[A] $x) => $x;\n",
                    "<?php class C { public function __construct(\n"
                    "    #[A] private int $x,\n  ) {} }\n"):
            st = _st(src)
            assert "php-hash-bracket" not in st.reasons, src

    def test_statement_level_static(self):
        for src in ("<?php\nfunction f($in) {\n#[todo] static $q = esc($in);\n"
                    "system($in);\n}\n",
                    "<?php\n#[note] static::guard($x);\n"):
            assert "php-hash-bracket" in _st(src).reasons, src
        for src in ("<?php $f = #[A] static function () {};\n",
                    "<?php $f = #[A] static fn() => 1;\n",
                    "<?php class C {\n  #[A] static $p;\n  #[B] public static"
                    " function m() {}\n}\n"):
            assert "php-hash-bracket" not in _st(src).reasons, src

    def test_member_modifiers_need_a_class_body(self):
        for src in ("<?php\n#[todo] public function names are camelCase;\n",
                    "<?php\n#[todo] const X = esc($y);\n"):
            assert "php-hash-bracket" in _st(src).reasons, src
        src = "<?php enum E { #[A] case One; #[B] const X = 1; }\n"
        assert "php-hash-bracket" not in _st(src).reasons

    def test_class_constant_reference_is_not_a_class_body(self):
        # `Foo::class` before a `{` must not make that block a class
        # body (`#[A] public` inside a function body is not valid).
        src = ("<?php\nfunction f($a = X::class) {\n"
               "#[todo] public $x = esc($a);\n}\n")
        assert "php-hash-bracket" in _st(src).reasons

    def test_close_tag_in_follower_comment_is_ambiguous(self):
        src = "<?php\n#[A] # ?> <b>'</b> <?php\nfunction f() {}\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_comment_inside_attribute_arguments_is_ambiguous(self):
        src = "<?php\n#[A('x' /* )] function f() {}\nsystem($_GET['f']); /* */\n"
        st = _st(src)
        assert "php-hash-bracket" in st.reasons
        assert "system($_GET[" in st.text


class TestPhpBracketStackCells:
    def test_by_reference_arrow_fn_param_list(self):
        assert "php-hash-bracket" not in _st(
            "<?php $h = fn&(#[A] $x) => $x;\n").reasons

    def test_stray_closer_does_not_pop_a_class_body(self):
        # A `)` with no open `(` must not pop the class body off the
        # bracket stack (only a matching closer pops).
        src = "<?php class C {\n  )\n  #[A] const X = 1;\n}\n"
        assert "php-hash-bracket" not in _st(src).reasons


class TestPhpAttributeContextEdgeCells:
    """Attribute-context edge cells: adjacency, word boundaries, long
    lines, argument strings, line ends and end of input."""

    def test_inherited_context_needs_adjacent_attribute(self):
        src = ("<?php\nfunction f(#[A] $p) {}\n$v = $arr[0]\n"
               "#[todo] $x = esc($y);\n;\n")
        assert "php-hash-bracket" in _st(src).reasons

    def test_new_needs_a_word_boundary(self):
        assert _st("<?php\n$x = $renew\n#[A] function f() {}\n;\n").reasons == ()

    def test_long_single_line_attribute(self):
        src = ("<?php\n#[Route('/a/very/long/path/that/goes/on/and/on',"
               " name: 'route_name')]\nfunction f() {}\n")
        assert _st(src).reasons == ()

    def test_hash_bracket_inside_argument_string_ends_scan(self):
        assert "php-hash-bracket" in _st(
            "<?php\n#[A('#[x')] function f() {}\n").reasons

    def test_newline_after_argument_list(self):
        assert _st("<?php\n#[A(1)\n] function f() {}\n").reasons == ()

    def test_attribute_at_end_of_input(self):
        assert "php-hash-bracket" in _st("<?php\n#[A]").reasons

    def test_declaration_keyword_needs_a_word_boundary(self):
        src = "<?php\n#[todo] function_exists('x') or staticfoo($x);\n"
        assert "php-hash-bracket" in _st(src).reasons


class TestPhpHeredocCloserNeverHides:
    """A closer only PHP >= 7.3 accepts is a guess between two readings.
    Both are scanned and the view keeps every character either shows,
    so body prose in one reading cannot hide the other's live code."""

    def test_legacy_body_line_with_quote(self):
        src = ("<?php\n$x = <<<EOT\nEOT is 'great\nEOT;\n"
               "system($_GET['f']);\n// '\n")
        st = _st(src)
        assert "php-heredoc-closer" in st.reasons
        assert "system($_GET[" in st.text

    def test_indented_legacy_line_then_body_prose(self):
        src = ("<?php\n$x = <<<EOT\n  EOT is great\ndon't do this\nEOT;\n"
               "system($c);\n")
        st = _st(src)
        assert "php-heredoc-closer" in st.reasons
        assert "system($c);" in st.text

    def test_laravel_style_closer_still_closes(self):
        src = ("<?php\n$q = DB::select(<<<SQL\n    SELECT * FROM t\n"
               "    SQL, [$id]);\nsystem($c);\n")
        st = _st(src)
        assert "php-heredoc-closer" in st.reasons
        assert "SELECT" not in st.text and "system($c);" in st.text

    def test_trailing_whitespace_after_semicolon_is_uncertain(self):
        src = "<?php\n$x = <<<EOT\nit's\nEOT;  \nsystem($_GET['f']);\n"
        st = _st(src)
        assert "php-heredoc-closer" in st.reasons
        assert "system($_GET[" in st.text

    def test_digit_first_label_does_not_open(self):
        src = "<?php\n$a = <<<1A\nit's\n1A;\nsystem($x);\n"
        assert "it'" in sanitized_view(src, "a.php")


class TestPhpAttributeCommentLinearTime:
    def test_unclosed_comment_after_attributes(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        src = "<?php\n" + "#[A] /*\n" * 256000
        start = time.monotonic()
        st = _st(src)
        assert time.monotonic() - start < 30.0
        assert "php-hash-bracket" in st.reasons


# Safety differential corpus: every call token `name(` in each source
# must stay visible in the full view unless it is listed as dead (in a
# string, comment, heredoc body or inline HTML by construction).
_SAFETY_CORPUS = [
    # (source, path, names that are dead by construction)
    ("const k = Symbol.for(name) / 2; run(cmd); const z = b / 3;\n", "a.js", set()),
    ("const t = arr.with(i, v) / n; run(cmd);\n", "a.js", set()),
    ("if (p) /run(/.test(p); go(x);\n", "a.js", {"run"}),
    ("for await (const l of s) /'/.test(l) && run(l);\ngo(b);\n", "a.js", set()),
    ("if /*c run( */ (s) /\"/.test(s) && go(s);\nok(t);\n", "a.js", {"run"}),
    ("x = (a + b) / 2; y = f(x) / g(z) / 3; run(1);\n", "a.js", set()),
    ("a) / 2; run(c); // dead(\n", "a.js", {"dead"}),
    ("<?php\n#[Route(\n  '/x',\n)]\npublic function dl($p) { return run($p); }\n",
     "a.php", set()),
    ("<?php\n#[A] // why dead(\nfunction f() { run(); }\n", "a.php", {"dead"}),
    ("<?php\n#[note] $arg = esc($arg);\nrun($arg);\n", "a.php", set()),
    ("<?php\n$r = call($cmd, #[todo] $o = esc($cmd)\n);\nrun($cmd);\n", "a.php", set()),
    ("<?php\n#[A('x' /* )] function f() {}\nrun($_GET['f']); /* */\n", "a.php", set()),
    ("<?php\nfunction f($in) {\n#[todo] static $q = esc($in);\nrun($in);\n}\n",
     "a.php", set()),
    ("<?php\n$m = <<<T\nTé \"x dead(\nT;\nrun($_GET[\"f\"]); echo \"?>\";\n",
     "a.php", {"dead"}),
    ("<?php\n$x = <<<EOT\nEOT is 'great\nEOT;\nrun($_GET['f']);\n// '\n",
     "a.php", set()),
    ("<?php\n$x = <<<EOT\n  EOT is great\ndon't do this\nEOT;\nrun($c);\n",
     "a.php", set()),
    ("<?php\n$q = DB::select(<<<SQL\n    SELECT dead(1)\n    SQL, [$id]);\nrun($c);\n",
     "a.php", {"dead"}),
    ("<?php\n$x = <<<EOT\nit's\nEOT;  \nrun($_GET['f']);\n", "a.php", set()),
    ("<?php ?><p>dead(1) <? 3, don't</p><?php run($c);\n", "a.php", {"dead"}),
    ("<p>Don't dead()</p>\n<?php\nfunction f() { run($c); }\n", "a.php", set()),
]


class TestSafetyDifferential:
    def test_no_live_call_token_hidden(self):
        import re as _re
        call_re = _re.compile(r"[A-Za-z_][A-Za-z0-9_]*\(")
        for src, fp, dead in _SAFETY_CORPUS:
            view = sanitized_view(src, fp)
            for m in call_re.finditer(src):
                name = m.group(0)[:-1]
                if name in dead:
                    continue
                assert view[m.start():m.end()] == m.group(0), (fp, name, src)


def _calls_after_slash_visible(src, view):
    """Every `name(` token after the first `/` in src is visible."""
    import re as _re
    first = src.index("/")
    for m in _re.finditer(r"[A-Za-z_][A-Za-z0-9_]*\(", src):
        if m.start() > first:
            assert view[m.start():m.end()] == m.group(0), (m.group(0), view)


class TestJsUndecidedSlashShowsCode:
    """JS regex-vs-division cases the view does not try to resolve are
    reported (`js-regex-or-division`) and the slash is rendered as
    division — code shown, never blanked as a regex body."""

    def test_postfix_increment_decrement(self):
        for src in ("x++ / 2; exec(c); y = 3 / 1;\n",
                    "n = i-- / 2; exec(c); y = 3 / 1;\n",
                    "r = a[i]++ / n; exec(c); y = 3 / 1;\n",
                    "r = x++\n/ 2; exec(c); y = 3 / 1;\n",
                    "r = ++/a/.lastIndex; exec(c); y = 3 / 1;\n"):
            st = _js(src)
            assert "js-regex-or-division" in st.reasons, src
            _calls_after_slash_visible(src, st.text)

    def test_regex_literal_across_newline_or_comment(self):
        for src in ("x = /a/\n/ 2; exec(c); y = 3 / 1;\n",
                    "x = /a/ /*c*/ / 2; exec(c); y = 3 / 1;\n"):
            st = _js(src)
            assert "js-regex-or-division" in st.reasons, src
            assert "exec(c);" in st.text, src

    def test_same_line_regex_division_stays_unambiguous(self):
        st = _js("x = /a/ / 2; run(c); y = b / 3;\n")
        assert st.reasons == () and "run(c);" in st.text

    def test_invisible_or_combining_character_before_keyword(self):
        for src in ("v = a\u200dif(x) / 2; exec(c); y = 3 / 1;\n",
                    "v = caféfor(x) / 2; exec(c); y = 3 / 1;\n",
                    "v = a·while(x) / 2; exec(c); y = 3 / 1;\n"):
            st = _js(src)
            assert "js-regex-after-paren" in st.reasons, src
            _calls_after_slash_visible(src, st.text)

    def test_plain_identifier_ending_in_keyword(self):
        st = _js("v = awhile(x) / 2; exec(c); y = 3 / 1;\n")
        assert st.reasons == () and "exec(c);" in st.text


class TestJsRegexFlagsAndTemplateRegex:
    def test_flags_belong_to_the_regex_value(self):
        src = "x = /a/u /* c */ / 2; exec(c); y = 3 / 1;\n"
        st = _js(src)
        assert "js-regex-or-division" in st.reasons
        _calls_after_slash_visible(src, st.text)

    def test_regex_literal_inside_template_interpolation(self):
        for src in ("s = `${/'/.source}`; exec(c); t = '';\n",
                    "s = `(${/[/']\\/a/gi + k}` / ((a) => a / 2); exec(c);\n"):
            st = _js(src)
            assert "exec(c);" in st.text, src
            assert st.reasons == (), src

    def test_template_regex_flags_then_comment_then_slash(self):
        src = "s = `${/a/g /*c*/ / 2}`; exec(c); y = 3 / 1;\n"
        st = _js(src)
        assert "js-regex-or-division" in st.reasons
        assert "exec(c);" in st.text

    def test_division_inside_template_interpolation(self):
        src = "s = `${(a) / 2 + exec(c) / 3}`;\n"
        st = _js(src)
        assert st.text == src and st.reasons == ()


class TestJsSlashAfterValueOnEarlierLine:
    """No ASI happens before `/`: a value ender on an earlier line (a
    comment may sit between) still makes the next-line `/` a division."""

    def test_line_start_slash_after_value(self):
        for src in ("v = (n) // c\n/ g(x); exec(c); y = 3 / 1;\n",
                    "v = a[0] /* c */\n// d\n/ g(x); exec(c); y = 3 / 1;\n",
                    "v = ''\n/ g(x); exec(c); y = 3 / 1;\n"):
            st = _js(src)
            _calls_after_slash_visible(src, st.text)
            assert st.reasons == (), src

    def test_keyword_then_newline_still_regex(self):
        st = _js("function f(s) { return\n/'/.test(s); }\nexec(c);\n")
        assert "'" not in st.text and "exec(c);" in st.text


class TestPhpCallsNamedLikeKeywords:
    """Method/static calls named like keywords (`->fn(`, `::fn(`,
    `?->function(`) are not declarations; functions/methods/calls named
    `enum`/`trait`/`interface` do not open class-like bodies; a quoted
    `'class'` in a header is data."""

    def test_member_calls_are_not_parameter_lists(self):
        for src in ("<?php\n$db->fn(#[x] $id, escape($id));\n",
                    "<?php\n$o->function(#[x] $id, escape($id));\n",
                    "<?php\nX::fn(#[x] $id, escape($id));\n",
                    "<?php\n$o?->fn(#[x] $id, escape($id));\n"):
            assert "php-hash-bracket" in _st(src).reasons, src

    def test_keyword_named_functions_are_not_class_bodies(self):
        for src in ("<?php\nfunction enum($x) {\n    #[todo] static $ok = s($x);\n}\n",
                    "<?php\nclass C { public function trait($x) {\n"
                    "    #[todo] static $ok = s($x);\n} }\n",
                    "<?php\nif (enum($x)) {\n    #[todo] static $ok = s($x);\n}\n",
                    "<?php\nfunction f($o, $x) {\n  if ($o->class) {\n"
                    "    #[todo] static $ok = s($x);\n  }\n}\n"):
            for keep in (False, True):
                st = _st(src, keep_strings=keep)
                assert "php-hash-bracket" in st.reasons, (keep, src)

    def test_quoted_class_word_in_header_is_data(self):
        src = ("<?php\nif ($k === 'class') {\n"
               "    #[todo] static $ok = s($x);\n}\n")
        for keep in (False, True):
            assert "php-hash-bracket" in _st(src, keep_strings=keep).reasons

    def test_real_class_like_bodies(self):
        for src in ("<?php\nenum Suit: string {\n  #[A] case H = 'h';\n}\n",
                    "<?php\n$o = new class($a) extends B {\n"
                    "  #[A] public function f() {}\n};\n",
                    "<?php\nfinal class C implements I {\n  #[A] var $x;\n}\n",
                    "<?php\ntrait T {\n  #[A] public static function m() {}\n}\n"):
            assert "php-hash-bracket" not in _st(src).reasons, src


class TestPhpHeredocAndAttributeContextCells:
    """Heredoc-closer union, attribute contexts and case-insensitive
    keywords."""

    def test_union_keeps_the_73_reading(self):
        # Keeping only the PHP < 7.3 reading would blank the sink.
        src = ("<?php\n$x = <<<EOT\n  body\n  EOT;\nsystem($_GET['c']);\n"
               "$y = <<<EOT\nb\nEOT;\n")
        st = _st(src)
        assert "php-heredoc-closer" in st.reasons
        assert "system($_GET[" in st.text

    def test_bracket_inside_class_body_is_not_member_context(self):
        # Inside `[` an attribute is not valid PHP 8.
        src = "<?php\nclass C {\n  const A = [\n#[x] const B = 1;\n];\n}\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_new_is_case_insensitive(self):
        # `NEW` is the keyword `new` (keywords are case-insensitive).
        src = "<?php\n$o = NEW #[x] fn() => sanitize($a);\nstdClass;\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_dollar_name_is_not_a_declaration(self):
        # `function $f(` declares nothing: no parameter list.
        assert "php-hash-bracket" in _st("<?php\nfunction $f(#[A] $x) {}\n").reasons

    def test_function_keyword_is_case_insensitive(self):
        # `FUNCTION (` is a closure: a parameter list.
        assert _st("<?php\n$f = FUNCTION (#[A] $x) {};\n").reasons == ()

    def test_var_property_in_class_body(self):
        # A `var` property in a class body is a member declaration.
        assert _st("<?php\nclass C {\n  #[A] var $x;\n}\n").reasons == ()

    def test_top_level_typed_property(self):
        # A typed property after a top-level attribute.
        assert _st("<?php\n#[ORM\\Column]\npublic int $x;\n").reasons == ()

    def test_hash_comment_inside_attribute_arguments(self):
        # A `#` comment inside the arguments disqualifies the group.
        src = "<?php\n#[A(1, # note\n 2)]\nfunction f() {}\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_close_tag_inside_attribute_arguments(self):
        # A `?>` inside the arguments disqualifies the group.
        src = "<?php\n#[A(1, ?>\n<?php 2)]\nfunction f() {}\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_context_reads_the_comment_blanked_view(self):
        # A comment between `,` and `#[` must not change the
        # context — the declaration's parameter list still holds.
        src = "<?php function f($a, /* ( */ #[A] $b) {}\n"
        assert _st(src).reasons == ()


class TestPhpAttributeWindows:
    """A window that OPENS with a PHP 8 attribute (a method cut out of
    its class — Symfony/Laravel routes, Doctrine mappings) followed by a
    declaration is not ambiguous; PHP-7-comment lines stay flagged."""

    VALID = [
        '#[Route("/dl")]\npublic function dl($f) {\n'
        '    return file_get_contents(basename($f));\n}\n',
        "#[Route('/a/b', methods: ['GET'])]\npublic static function f() {}\n",
        '#[A, B("x/y")]\nfinal public function f() {}\n',
        '#[A]\n#[B("x")]\nprotected function f() {}\n',
        "#[A]\nabstract protected function f();\n",
        '#[ORM\\Column(type: "string")]\nprivate readonly string $name;\n',
        '#[Description("x")]\ncase Hearts = \'H\';\n',
        "public function __construct(\n    #[Autowire] private Foo $foo,\n"
        "    #[SensitiveParameter] string $p,\n) {}\n",
        "#[Pure]\nfunction f() {}\n",
        "#[A] // why\npublic function f() {}\n",
        "  #[Route('/x')]\n  public function x() {}\n",
    ]
    PHP7_COMMENTS = [
        "#[todo] $x = esc($x);\n",
        "#[note] public function names are camelCase\nrun();\n",
        "#[todo] const X = esc($y);\n",
        "#[x] , basename($p);\n",
        "#[note] static::guard($x);\n",
        "#[todo] don't\nrun();\n",
        "function f() {\n  #[todo] static $q = esc($in);\n}\n",
    ]

    def test_attribute_led_windows_are_unambiguous(self):
        for src in self.VALID:
            for fp in ("Controller.php", "a.php"):
                st = sanitized_view_with_status(src, fp)
                assert st.ambiguous is False, (fp, src, st.reasons)
            st = sanitized_view_with_status("<?php\n" + src, "a.php")
            assert st.ambiguous is False, src

    def test_php7_comment_windows_stay_ambiguous(self):
        for src in self.PHP7_COMMENTS:
            st = sanitized_view_with_status(src, "Controller.php")
            assert "php-hash-bracket" in st.reasons, src


class TestJsUnicodeWhitespace:
    """JS WhiteSpace (TAB VT FF SP NBSP ZWNBSP + Unicode Zs) and
    LineTerminator (LF CR LS PS) are whitespace for every JS decision —
    never identifier characters. PHP keeps its own rule (NBSP is a
    label byte there)."""

    WS = ["\u00a0", "\ufeff", "\u3000", "\u2028", "\u2029", "\u2003",
          "\u202f", "\u205f", "\u1680"]

    def test_regex_after_operator_keyword_paren_across_unicode_ws(self):
        for w in self.WS:
            for src in (f"x ={w}/'/.test(s); exec(c);\n",
                        f"function f(s){{ return{w}/'/.test(s); }} exec(c);\n",
                        f"f({w}/'/.test(s)); exec(c);\n",
                        f"if (a){w}/'/.test(s) && exec(s);\n"):
                st = _js(src)
                assert "exec(" in st.text, (repr(w), src, st.text)
                assert "'" not in st.text, (repr(w), src)

    def test_division_after_value_across_unicode_ws(self):
        for w in self.WS:
            src = f"x = a{w}/ 2; exec(c); y = 3 / 1;\n"
            st = _js(src)
            assert "exec(c);" in st.text, (repr(w), st.text)

    def test_keyword_head_across_unicode_ws(self):
        st = _js("for\u00a0(const k in o) /'/.test(k) && exec(k);\n")
        assert "exec(k);" in st.text and "'" not in st.text

    def test_line_comment_ends_at_ls_ps(self):
        for w in ("\u2028", "\u2029"):
            st = _js(f"// note{w}exec(c);\n")
            assert "exec(c);" in st.text, repr(w)

    def test_js_whitespace_never_joins_an_identifier(self):
        # `k<NBSP>in /'/` — `in` is a keyword (regex follows), not the
        # tail of an identifier `k<NBSP>in`.
        st = _js("x = k\u00a0in /'/; exec(c); y = 3 / 1;\n")
        assert "exec(c);" in st.text and "'" not in st.text

    def test_php_nbsp_stays_a_label_byte(self):
        # PHP: NBSP is not whitespace (label byte) — a heredoc label
        # followed by NBSP is a longer label, not the closer.
        src = "<?php\n$x = <<<EOT\nEOT\u00a0x\nEOT;\nrun($c);\n"
        view = sanitized_view(src, "a.php")
        assert "run($c);" in view and "x\nEOT;" not in view


class TestJsKeywordAsPropertyName:
    def test_property_named_like_a_keyword_divides(self):
        for src in ("kb = traffic.in / 1024 + exec(c) / 2;\n",
                    "x = obj.return / 2; exec(c); y = 3 / 1;\n",
                    "x = obj?.typeof / 2; exec(c); y = 3 / 1;\n",
                    "x = this.#delete / 2; exec(c); y = 3 / 1;\n"):
            st = _js(src)
            assert st.text == src and st.reasons == (), src

    def test_real_keyword_still_regex(self):
        st = _js("function f(s) { return /'/.test(s); } exec(c);\n")
        assert "'" not in st.text and "exec(c);" in st.text


class TestJsTemplateNestingDepth:
    def test_deep_template_nesting_does_not_crash(self):
        for depth in (1000, 3000):
            src = "x = " + "`${" * depth + "a" + "}`" * depth + "; exec(c);\n"
            st = _js(src)
            assert len(st.text) == len(src)
            assert "unterminated-template-literal" in st.reasons
            src = "x = " + "`${" * depth + "\nexec(c);\n"
            st = _js(src)
            assert "exec(c);" in st.text


class TestPhpAnonymousClassVariants:
    def test_new_with_attribute_or_readonly_opens_a_body(self):
        for src in ("<?php $o = new #[Immutable] class('x') {\n"
                    "  #[A] public function f() {}\n};\n",
                    "<?php $o = new readonly class() {\n"
                    "  #[A] public function f() {}\n};\n",
                    "<?php $o = NEW class($a) { #[A] public function f() {} };\n"):
            assert "php-hash-bracket" not in _st(src).reasons, src


class TestJsSlashAndPhpEnumCaseCells:
    def test_single_plus_then_regex(self):
        # Only a doubled `++`/`--` is the undecided case.
        st = _js("x = a + /'/.test(s); exec(c);\n")
        assert st.reasons == () and "exec(c);" in st.text

    def test_non_ascii_identifier_then_slash_divides(self):
        # An identifier ending in a non-alnum ID_Continue character
        # (combining mark, ZWJ) is still a value — division follows.
        for src in ("x = á / 2; exec(c); y = 3 / 1;\n",
                    "x = á / 2; exec(c); y = 3 / 1;\n",
                    "x = a\u200d / 2; exec(c); y = 3 / 1;\n"):
            assert "exec(c);" in _js(src).text, src

    def test_enum_case_needs_assignment_or_semicolon(self):
        # `case FOO:` without `=` or `;` is not an enum case.
        st = _st("#[todo] case FOO: return escapeshellarg($a);\n")
        assert "php-hash-bracket" in st.reasons

    def test_nested_template_reports(self):
        # The flag reaches nested templates.
        st = _js("s = `${`${x++ / 2}`}`;\n")
        assert "js-regex-or-division" in st.reasons


class TestPhpTopLevelMemberShapes:
    def test_class_constant_and_complex_type_windows(self):
        for src in ("#[\\Deprecated]\npublic const LEGACY = 'x';\n",
                    "#[Inject]\nprivate A&B $x;\n",
                    "#[Inject]\nprivate (A&B)|null $x = null;\n",
                    "#[A]\nconst string X = 'y';\n"):
            assert _st(src).reasons == (), src

    def test_bare_top_level_const_stays_ambiguous(self):
        assert "php-hash-bracket" in _st("#[todo] const X = esc($y);\n").reasons


class TestJsMemberDotIsASingleDot:
    """Only a single `.`/`?.` (or a private `#`) makes the next name a
    member; a spread's last dot and a number's trailing dot do not, so a
    keyword after them is still a keyword (a regex follows)."""

    def test_spread_then_keyword_regex(self):
        for src in ("async function f(s){ g(...await /'/.exec(s)); exec(c); }\n",
                    "function* f(s){ g(...yield /'/); exec(c); }\n",
                    "[...typeof /'/]; exec(c);\n"):
            st = _js(src)
            assert "exec(c);" in st.text and "'" not in st.text, src

    def test_numeric_trailing_dot_then_keyword(self):
        for src in ("function f(s){ x = 1.\nreturn /'/.test(s) && exec(s); }\n",
                    "x = 1.\ntypeof /'/; exec(c);\n",
                    "x = 1.\nif (a) /'/.test(s) && exec(s);\n"):
            st = _js(src)
            assert "exec(" in st.text and "'" not in st.text, src

    def test_member_names_still_divide(self):
        for src in ("x = o.await / 2; exec(c); y = 3 / 1;\n",
                    "x = a1.typeof / 2; exec(c); y = 3 / 1;\n",
                    "x = o?.in / 2; exec(c); y = 3 / 1;\n"):
            st = _js(src)
            assert st.text == src, src


class TestLineTerminatorAndWhitespaceCells:
    """JS line terminators, Unicode whitespace and template depth; a PHP
    name joined by NBSP; nested brackets in an anonymous-class
    attribute."""

    def test_cr_and_ls_end_comments_regexes(self):
        # CR and LS end a line comment and a line.
        for src in ("// note\rexec(c);\r",
                    "x = a\r/ 2; exec(c); y = 3 / 1;\r",
                    "x = {} / 2\u2028exec(c); y = 3 / 1;\n",
                    "x = {} / 2\rexec(c); y = 3 / 1;\r"):
            assert "exec(c);" in _js(src).text, repr(src)

    def test_vt_ff_are_whitespace(self):
        # VT and FF are whitespace.
        for w in ("\v", "\f"):
            src = f"x = a{w}/ 2; exec(c); y = 3 / 1;\n"
            assert "exec(c);" in _js(src).text, repr(w)

    def test_unicode_ws_inside_keyword_and_member_checks(self):
        # Unicode whitespace inside `for await` and around member dots.
        for src in ("async function f(){ for\u00a0await (const a of b) /'/.test(a) && exec(a); }",
                    "v = o.\u00a0if(x) / 2; exec(c); y = 3 / 1;\n",
                    "v = o.\u00a0in / 2; exec(c); y = 3 / 1;\n",
                    ".in / 2; exec(c); y = 3 / 1;\n",
                    "v = o. in / 2; exec(c); y = 3 / 1;\n"):
            assert "exec(" in _js(src).text, repr(src)

    def test_no_false_ambiguity(self):
        # None of these shapes is ambiguous.
        for src in ("x\u2028if (a) /'/.test(s) && exec(s);\n",
                    "x = /a/\u00a0/ 2; exec(c); y = 3 / 1;\n",
                    "s = `a${`b${`c${x}`}`}`; exec(c);\n"):
            assert _js(src).reasons == (), repr(src)

    def test_depth_cap_shows_the_rest(self):
        # Past the cap the remainder is shown (not resumed one
        # character later, where a quote would open a string).
        for src in ("s = " + "`${" * 201 + "'\nexec(c);\n",
                    "s = " + "`${" * 201 + "'" + "}`" * 201 + "; exec(c);\n",
                    "s = " + "`${" * 200 + "`a'b`" + "}`" * 200 + "; exec(c);\n"):
            assert "exec(c);" in _js(src).text

    def test_php_nbsp_joins_a_name(self):
        # `x<NBSP>fn` is one PHP name — a call, not a declaration.
        src = "<?php\nx\u00a0fn(#[x] $id, escape($id));\n"
        assert "php-hash-bracket" in _st(src).reasons

    def test_anonymous_class_attribute_with_nested_brackets(self):
        # Nested brackets inside an anonymous-class attribute.
        src = ("<?php\n$o = new #[A(['k' => 1])] class('x') {\n"
               "    #[Pure]\n    public function f() {}\n};\n")
        assert _st(src).reasons == ()


class TestLineTerminatorLinearTime:
    def test_line_comments_without_lf(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        for lt in ("\r", "\u2028"):
            src = ("// c" + lt) * 800000
            start = time.monotonic()
            _js(src)
            assert time.monotonic() - start < 30.0, repr(lt)

    def test_repeated_regex_openers_on_one_line(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        src = "(/[" * 48000
        start = time.monotonic()
        _js(src)
        assert time.monotonic() - start < 30.0


class TestJsRegexLengthBound:
    def test_regex_within_bound_is_lexed(self):
        src = "x = /" + "a" * 1500 + "'/.test(s); exec(c);\n"
        st = _js(src)
        assert st.reasons == () and "exec(c);" in st.text and "'" not in st.text

    def test_overlong_regex_is_reported(self):
        # Real tables (7-8.5 KB) are followed; 40 000 chars is past the
        # bound.
        src = "x = /" + "a" * 40000 + "/.test(s); exec(c);\n"
        st = _js(src)
        assert "js-regex-or-division" in st.reasons
        assert "exec(c);" in st.text


    def test_unclosed_candidate_ending_at_line_end_is_not_reported(self):
        # The length bound is reported only when it, not a line end,
        # stopped the scan.
        src = "f(/x\n" + "y = 1;\n" * 6000
        assert "js-regex-or-division" not in _js(src).reasons


class TestJsNumericLiteralMemberDot:
    """Whether a `.` is a member access after a number is decided by
    lexing the numeric literal per ECMAScript: a literal consumes at
    most one `.` (`1.` is a number with a trailing dot), so the next
    `.` — and any `.` after a complete literal (`1.5`, `1e3`, `0b1`,
    `1_0.5`, `.5`) — is a member access."""

    PREFIXES = ["o.", "1..", "1.5.", "0x1F.", "1e3.", "10n.", "0b1.",
                "0o7.", "1.e3.", "a1.", "$1.", "_1.", "1 .", "(1).",
                "x" + chr(0x661) + ".", ".5.", "0.5.", "1_0.5.", "1e+3.",
                "1E-3."]

    def test_member_calls_and_properties_on_numbers(self):
        # Number and name prefixes, with fraction/separator/exponent
        # variants: a member call named like a control keyword, a
        # keyword property, and a `for` member call all divide.
        for pre in self.PREFIXES:
            for src in ("v = " + pre + "if(a) / 2; exec(c); z = 3 / 4;\n",
                        "v = " + pre + "in / 2; exec(c); z = 3 / 4;\n",
                        "v = " + pre + "for(a) / 2; exec(c); z = 3 / 4;\n"):
                st = _js(src)
                assert "exec(c);" in st.text, (pre, src, st.text)

    def test_member_calls_after_numbers_explicit_cases(self):
        for src, fp in (("v = 1..if(a) / 2; exec(c); z = 3 / 4;\n", "a.js"),
                        ("v = 1.5.for(a) / 2; exec(c); z = 3 / 4;\n", "a.js"),
                        ("v = 1e3.while(a) / 2; exec(c); z = 3 / 4;\n", "a.js"),
                        ("v = 0b1.with(a) / 2; exec(c); z = 3 / 4;\n", "a.ts"),
                        ("const r = 1..if(x)\n  / 2; exec(cmd); const q = n / 4;\n", "a.js"),
                        ("v = o.if(a) / 2; exec(c); z = 3 / 4;\n", "a.js"),
                        ("v = (1).if(a) / 2; exec(c); z = 3 / 4;\n", "a.js")):
            st = sanitized_view_with_status(src, fp)
            assert "exec(c" in st.text, src

    def test_trailing_dot_and_spread_still_keep_the_keyword(self):
        for src in ("function f(s){ x = 1.\nreturn /'/.test(s) && exec(s); }\n",
                    "x = 1_000.\nif (a) /'/.test(s) && exec(s);\n",
                    "[...typeof /'/]; exec(c);\n"):
            st = _js(src)
            assert "exec(" in st.text and "'" not in st.text, src


class TestJsRegexCandidateBoundaryCells:
    def test_unclosed_regex_at_end_of_input_not_reported(self):
        # An unclosed regex at end of input is not reported.
        for src in ("x = /abc", "if (a) /'"):
            assert "js-regex-or-division" not in _js(src).reasons, src

    def test_regex_length_boundary(self):
        # At the length bound, and one past it.
        from core.audit.source_view import _JS_REGEX_MAX_LEN
        ok = "const r = /" + "a" * (_JS_REGEX_MAX_LEN - 2) + "/; exec(c);\n"
        st = _js(ok)
        assert st.reasons == () and "exec(c);" in st.text
        over = "const r = /'" + "a" * _JS_REGEX_MAX_LEN + "/; exec(c);\n"
        assert "js-regex-or-division" in _js(over).reasons

    def test_class_and_plain_body_stop_at_line_end(self):
        # A class body and a plain body both stop at the line end.
        for src in ("let of = 4; x = of / [1,\nexec(c)][0] / 2;\n",
                    "let of = 4; x = of / [a; exec(c); y = 1 / 2;\n"):
            assert "exec(c)" in _js(src).text, src

    def test_escape_does_not_carry_a_regex_over_a_line_end(self):
        # `\` + line terminator ends the candidate (a regex literal
        # cannot span lines, escaped or not).
        src = "let of = 4; x = of / 2 + 'abc\\\ndef'; exec(c); y = 1 / 2;\n"
        assert "exec(c);" in _js(src).text

    def test_real_unicode_table_regex_is_not_ambiguous(self):
        body = "".join("\\x%02X-\\x%02X" % (i, i + 1) for i in range(0, 250, 2))
        body = body * 12
        src = "exports.ID_Start = /[" + body + "]/; run(c);\n"
        assert len(body) > 7000
        st = _js(src)
        assert st.reasons == () and "run(c);" in st.text


    def test_repeated_regex_openers_inside_a_template(self):
        # Guards against catastrophic (super-linear) blowup, not speed.
        import time
        src = "s = `${" + "(/[" * 40000 + "}`;\n"
        start = time.monotonic()
        _js(src)
        assert time.monotonic() - start < 30.0


class TestPhpClassHeaderScansLinear:
    """The class-header helpers are linear hand scans, equivalent to the
    regexes they replace (kept here as the oracle): quoted-text blanking
    (`'(?:\\\\.|[^'\\\\])*'|"(?:\\\\.|[^"\\\\])*"` substituted by spaces) and
    the anonymous-class prefix (`\\bnew` + attribute groups + optional
    `readonly` at the end of the header).

    Linearity is pinned three ways: deterministic work counts (the
    module's `_PHP_HEADER_STATS` hook) that must grow in proportion to
    the input over a doubling ladder; CPU-time scaling of the real entry
    point with the hook off (slow tier, nightly); and subprocess hang
    guards with a 30 s wall-clock limit and a result check, at sizes the
    regex version took far longer on."""

    QUOTED = r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\""
    NEWPFX = r"\bnew(?:\s*#\[(?:[^\[\]]|\[[^\]]*\])*\])*(?:\s+readonly)?$"

    # -- oracles -------------------------------------------------------

    def _blank_oracle(self, s):
        import re as _re
        return _re.sub(self.QUOTED, lambda m: " " * len(m.group(0)), s)

    def _prefix_oracle(self, s):
        import re as _re
        return _re.search(self.NEWPFX, s, _re.IGNORECASE) is not None

    def _old_class_brace(self, chars, i):
        # _php_class_brace in its regex version, verbatim apart from names.
        import re as _re
        hdr_re = _re.compile(
            r"(?<![\w$:>\\])(?:class|interface|trait|enum)(?![\w$\\])")
        j = i - 1
        while j >= 0 and chars[j] not in ";{}":
            j -= 1
        header = _re.sub(self.QUOTED, lambda m: " " * len(m.group(0)),
                         "".join(chars[j + 1:i]))
        for m in hdr_re.finditer(header):
            before = header[:m.start()].rstrip()
            after = header[m.end():].lstrip()
            if after.startswith("(") and not _re.search(
                    self.NEWPFX, before, _re.IGNORECASE):
                continue
            return True
        return False

    # -- quoted-text blanking -------------------------------------------

    def test_quoted_blanking_matches_the_regex(self):
        import random
        from core.audit.source_view import _php_blank_quoted
        rnd = random.Random(12)
        alpha = ["'", '"', "\\", "\n", "\r", "a", " ", "x"]
        for _ in range(20000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 14)))
            assert _php_blank_quoted(s) == self._blank_oracle(s), repr(s)

    def test_quoted_blanking_explicit_cases(self):
        from core.audit.source_view import _php_blank_quoted
        cases = {
            # failed scan ending at EOF: left as is
            "x 'abc": "x 'abc",
            # terminal backslash: no close
            "x 'ab\\": "x 'ab\\",
            # backslash-LF cannot be an escape: the string does not close
            # there, and the quote after it opens nothing either
            "'a\\\nb'": "'a\\\nb'",
            # a bare LF and a CR are ordinary string characters, and a
            # backslash-CR is an escape
            "'a\nb' c": "      c",
            "'a\rb' c": "      c",
            "'a\\\rb' c": "       c",
            # escaped same-kind quotes stay inside
            "'a\\'b' c": "       c",
            '"a\\"b" c': "       c",
            # an unclosed single quote around a complete double-quoted
            # string: the double-quoted string is still blanked
            "'a \"x\" b": "'a     b",
            # recovery: after a run that dies at backslash-LF, a later
            # valid same-kind string is blanked
            "'\\'\\'\\\n 'ok' z": "'\\'\\'\\\n      z",
            # an escaped quote, then a real close: one string; the
            # quote after the backslash-LF then opens nothing
            "'\\' '\\\n 'q'": "     \\\n    ",
            # a dead run is skipped, but a same-kind quote past the
            # dead point still opens a string
            "'\\'\\'\\\n'q' '\\''": "'\\'\\'\\\n        ",
        }
        for src, want in cases.items():
            got = _php_blank_quoted(src)
            assert got == self._blank_oracle(src), repr(src)
            assert got == want, (repr(src), repr(got))

    # -- anonymous-class prefix -----------------------------------------

    def test_anonymous_class_prefix_matches_the_regex(self):
        import random
        from core.audit.source_view import _php_new_class_prefix
        rnd = random.Random(13)
        alpha = ["new", "NEW", "re", "#[", "[", "]", "(", " ", "\n",
                 "readonly", "a", "#"]
        for _ in range(20000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 9)))
            s = s.rstrip()
            assert _php_new_class_prefix(s, len(s)) == self._prefix_oracle(
                s), repr(s)

    def test_shared_prefix_index_matches_the_regex_at_every_end(self):
        # One header can hold several `class`/`enum` keywords; the
        # index built once per header must answer each keyword's end
        # (any end not preceded by whitespace — the caller trims it).
        import random
        from core.audit.source_view import _PhpNewPrefixes
        rnd = random.Random(14)
        alpha = ["new", "nEw", "anew", "_new", "readonly", "#[", "[", "]",
                 "#", " ", "\t", "\n", "a", "(", "]]", "[[", chr(0x3000),
                 chr(0xE9)]
        for _ in range(6000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 12)))
            idx = _PhpNewPrefixes(s)
            for end in range(len(s) + 1):
                if end and s[end - 1].isspace():
                    continue
                assert idx.ends_at(end) == self._prefix_oracle(s[:end]), (
                    repr(s), end)

    def test_prefix_precondition_trimmed_end(self):
        # The regex's `$` also matches before a final LF; the index does
        # not, and need not: the caller always passes an end that is 0
        # or follows a non-whitespace character.
        from core.audit.source_view import _PhpNewPrefixes
        assert self._prefix_oracle("new\n")
        assert not _PhpNewPrefixes("new\n").ends_at(4)
        assert _PhpNewPrefixes("new\n").ends_at(3)

    def test_prefix_explicit_cases(self):
        from core.audit.source_view import _php_new_class_prefix
        ws3000, ws2003, nbsp, nel = (chr(0x3000), chr(0x2003), chr(0xA0),
                                     chr(0x85))
        cases = {
            # nested `[` the permissive grammar accepts: an inner `[`
            # runs to the first `]`, `[` included
            "new #[A([1, [2])]": True,
            "new #[A[[[b]]": True,
            "new #[A([1,[2]])]": False,
            # missing closers
            "new #[A": False,
            "new #[A[b": False,
            "new #[A[b]": False,
            # merged chains: both `new`s reach the same group end
            "new #[ new #[ a [b] c ] #[y] #[y]": True,
            # Unicode whitespace, and NEL
            "new" + ws3000 + "#[A]" + ws2003 + "readonly": True,
            "new" + nel + "readonly": True,
            "new" + nbsp + "#[A]": True,
            # word-boundary predecessors, ASCII and not
            "_new": False,
            "anew": False,
            chr(0xE9) + "new": False,
            chr(0xDF) + "new": False,
            chr(0x663) + "new": False,   # ARABIC-INDIC DIGIT THREE (\w)
            chr(0x301) + "new": True,    # combining mark (not \w)
            "$new": True,
            "->new": True,
            # mixed case
            "NeW #[a] ReadOnly": True,
            "nEW READONLY": True,
            "new readonlyx": False,
            "newreadonly": False,
            # a positive prefix far longer than 4096 characters
            "new" + " #[x]" * 1500 + " readonly": True,
            "new" + " #[x(1)]" * 1000: True,
        }
        for s, want in cases.items():
            assert self._prefix_oracle(s) == want, repr(s)
            assert _php_new_class_prefix(s, len(s)) == want, repr(s)

    def test_group_close_at_the_query_boundary(self):
        from core.audit.source_view import _PhpNewPrefixes
        s = "new #[A] x #[B]"
        idx = _PhpNewPrefixes(s)
        close = s.index("]")
        for end in (close, close + 1, close + 3):
            assert idx.ends_at(end) == self._prefix_oracle(s[:end]), end
        assert not idx.ends_at(close)       # group not yet closed
        assert idx.ends_at(close + 1)       # just after `]`
        assert not idx.ends_at(close + 3)   # `x` follows
        assert not idx.ends_at(len(s))      # `x` breaks the chain

    # -- the caller ------------------------------------------------------

    def test_class_brace_matches_the_old_function(self):
        import random
        from core.audit.source_view import _php_class_brace
        rnd = random.Random(15)
        toks = [";", "{", "}", "class", "enum", "trait", "interface", "new",
                "#[", "[", "]", "(", "'", '"', "\\", " ", "\n", "x", "::",
                "readonly", "$", "a", "->", "#[A]", "NEW"]
        n = 0
        for _ in range(12000):
            chars = list("".join(rnd.choice(toks)
                                 for _ in range(rnd.randint(1, 14))) + "{")
            for i, c in enumerate(chars):
                if c == "{":
                    assert _php_class_brace(chars, i) == self._old_class_brace(
                        chars, i), ("".join(chars), i)
                    n += 1
        assert n > 12000

    def test_class_brace_explicit_cases(self):
        from core.audit.source_view import _php_class_brace
        for hdr, want in {
                "$o = " + "enum($a) + " * 300 + "new class() ": True,
                "$o = " + "enum($a) + " * 300 + "f() ": False,
                "$o = new" + " #[A]" * 1200 + " class() ": True,
                "function enum($a) ": False,
                "$o = new #[A] readonly class($a) extends B ": True,
                "if ($k === 'class') ": False,
                "$o = X::class ": False,
                "final class C implements I ": True}.items():
            chars = list(hdr + "{")
            i = len(chars) - 1
            assert self._old_class_brace(chars, i) == want, hdr[:60]
            assert _php_class_brace(chars, i) == want, hdr[:60]

    def test_member_attribute_distinction_in_views(self):
        # Inside a class-like body a `#[A]` before a member declaration
        # is an attribute; inside any other block it is ambiguous.
        body = " {\n  #[A] public function f() {}\n};\n"
        # (`new #[A] readonly class` is left out: the lexer judges the
        # `#[A]` on that line ambiguous on its own, before any brace.)
        for head in ("$o = new #[A] class($a)",
                     "$o = new readonly class($a)",
                     "$o = new" + " #[A]" * 1200 + " class()",
                     "$o = " + "enum($a) + " * 300 + "new class()",
                     "$o = new class($a) extends B"):
            for keep in (False, True):
                st = _st("<?php\n" + head + body, keep_strings=keep)
                assert "php-hash-bracket" not in st.reasons, (head[:50], keep)
        for head in ("function enum($a)",
                     "$o = " + "enum($a) + " * 300 + "f()",
                     "if (trait($x))",
                     "if ($k === 'new class')"):
            for keep in (False, True):
                st = _st("<?php\n" + head + body, keep_strings=keep)
                assert "php-hash-bracket" in st.reasons, (head[:50], keep)

    # -- linear work (deterministic counts) -------------------------------

    def _work(self, src, keep_strings=True):
        import collections
        import core.audit.source_view as sv
        stats = collections.Counter()
        sv._PHP_HEADER_STATS = stats
        try:
            sanitized_view_with_status(src, "a.php", keep_strings=keep_strings)
        finally:
            sv._PHP_HEADER_STATS = None
        return stats

    def _assert_linear(self, make, keys, sizes=(500, 1000, 2000, 4000)):
        rows = []
        for k in sizes:
            src = make(k)
            st = self._work(src)
            rows.append((k, len(src), {key: st[key] for key in keys}))
        for key in keys:
            counts = [r[2][key] for r in rows]
            assert counts[-1] > 0, (key, rows)
            # density: work per input character stays bounded ...
            assert counts[-1] <= 8 * rows[-1][1], (key, rows)
            # ... and doubling the input at most doubles the work (+5%).
            for a, b in zip(counts, counts[1:]):
                assert b <= 2.1 * a + 64, (key, rows)

    def test_quoted_scan_work_is_linear(self):
        self._assert_linear(
            lambda k: "<?php\n$a = '" + "\\'" * k + "\n{}\n",
            ("quote_steps",))
        self._assert_linear(
            lambda k: "<?php\n$a = \"x\" '" + "\\\"\\'" * k + "\n{}\n",
            ("quote_steps",))

    def test_prefix_index_work_is_linear(self):
        # Unclosed groups after many `new`s; merged chains sharing one
        # long tail; long `#[x]` runs before `readonly class (`.
        self._assert_linear(
            lambda k: "<?php\n$o = new" + "#[new" * k + "\nclass() {}\n",
            ("prefix_steps", "prefix_ends"))
        self._assert_linear(
            lambda k: ("<?php\n$o = " + "new #[ " * k + "a [b] c ]"
                       + " #[y]" * k + " class (\n{}\n"),
            ("prefix_steps", "prefix_ends", "prefix_ws"))
        self._assert_linear(
            lambda k: ("<?php\n$o = " + "new #[x] " * k
                       + "readonly class (\n{}\n"),
            ("prefix_steps", "prefix_ends", "prefix_ws", "query_ws"))

    def test_caller_work_is_linear(self):
        # Many rejected keywords in one header: each keyword costs only
        # its own whitespace, and the header is copied once.
        self._assert_linear(
            lambda k: "<?php\n$o = " + "new #[ class (" * k + "\n{}\n",
            ("header_chars", "caller_ws", "prefix_steps"))
        self._assert_linear(
            lambda k: "<?php\n$o = " + "enum  (  $a) + " * k + "f() {}\n",
            ("header_chars", "caller_ws"))

    # Every key the scans write to the hook. A key added to the source
    # fails the inventory test below until it is listed here and the
    # plain-dict test reaches it.
    _HOOK_KEYS = frozenset({
        "header_chars", "caller_ws", "quote_steps", "prefix_steps",
        "prefix_ends", "prefix_ws", "query_ws"})

    def test_stats_hook_key_inventory_matches_the_source(self):
        # Derived independently of the tests' inputs: every subscript
        # store into the hook (through its local alias `st` or by name)
        # in the module's source.
        import ast
        import inspect
        import core.audit.source_view as sv
        found = set()
        for node in ast.walk(ast.parse(inspect.getsource(sv))):
            if (isinstance(node, ast.Subscript)
                    and isinstance(node.ctx, ast.Store)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in ("st", "_PHP_HEADER_STATS")):
                assert isinstance(node.slice, ast.Constant), ast.dump(node)
                found.add(node.slice.value)
        assert found == self._HOOK_KEYS, sorted(found ^ self._HOOK_KEYS)

    def test_stats_hook_accepts_a_plain_dict(self):
        # A fresh empty dict, and an input that reaches every key (the
        # `new readonly class (` header takes the readonly-tail query):
        # each key's first write must work on a plain dict, and each
        # count is pinned exactly.
        import core.audit.source_view as sv
        src = ("<?php\n$o = 'a' . enum ($x) . new class() {};\n"
               "$p = new readonly class () {};\n")
        want = {"header_chars": 69, "caller_ws": 5, "quote_steps": 2,
                "prefix_steps": 69, "prefix_ends": 2, "prefix_ws": 2,
                "query_ws": 1}
        assert set(want) == self._HOOK_KEYS
        for keep in (False, True):
            stats = {}
            sv._PHP_HEADER_STATS = stats
            try:
                sanitized_view_with_status(src, "a.php", keep_strings=keep)
            finally:
                sv._PHP_HEADER_STATS = None
            assert stats == want, (keep, stats)

    # -- CPU-time scaling (hook off, production objects) -----------------
    #
    # The step counts above come from each scan's own loop bounds, so
    # they cannot see work added elsewhere: a header copy per keyword, a
    # header built by repeated concatenation, or an output rebuild per
    # closed string leave them unchanged. These tests time the real entry
    # point with the hook off and assert the CPU time at most ~doubles
    # when the input doubles (bound 2.8). Each such regression, applied
    # alone, measured 3.3-4.2 here, and the unmodified code 1.9-2.1
    # (machine load at most 16). These are empirical
    # regression checks, not a proof of linearity.
    #
    # Tier: these tests are marked slow, so per-PR CI (pytest.ini's
    # default `-m "not integration and not slow and not corpus"`) skips
    # them; the nightly workflow runs them with `-m slow`. The step-count
    # tests and the hang guards above and below are in the default tier.

    _RATIO_BOUND = 2.8

    def _cpu_ratio(self, make, k, keep_strings, reps=5):
        import statistics
        import time
        small, big = make(k), make(2 * k)   # built outside the timing

        def per_run(src, batch):
            start = time.process_time()
            for _ in range(batch):
                sanitized_view_with_status(src, "a.php",
                                           keep_strings=keep_strings)
            return (time.process_time() - start) / batch

        per_run(small, 1)                   # warm-up
        per_run(big, 1)
        first = per_run(small, 1)
        batch = max(1, int(0.2 / max(first, 1e-4)))
        ts, tb = [], []
        for _ in range(reps):               # interleaved
            ts.append(per_run(small, batch))
            tb.append(per_run(big, batch))
        ms, mb = statistics.median(ts), statistics.median(tb)
        return mb / ms, ms, mb, batch

    def _assert_cpu_scales(self, make, k, keep_strings=False):
        ratio, ms, mb, batch = self._cpu_ratio(make, k, keep_strings)
        print(f"PERF-MEASURE k={k} keep={keep_strings} {ms:.4f}s -> "
              f"{mb:.4f}s x{ratio:.2f} batch {batch}")
        assert ratio <= self._RATIO_BOUND, (
            f"PERF: CPU time x{ratio:.2f} for 2x input (k={k}: "
            f"{ms:.4f}s -> {mb:.4f}s, batch {batch}); bound "
            f"{self._RATIO_BOUND}")

    @pytest.mark.slow
    def test_perf_rejected_keywords_scale_linearly(self):
        # A per-keyword copy of the header would be quadratic here.
        self._assert_cpu_scales(
            lambda k: "<?php\n$o = " + "enum (1) " * k + "\n{}\n", 128000)

    @pytest.mark.slow
    def test_perf_rejected_keywords_with_whitespace_scale_linearly(self):
        self._assert_cpu_scales(
            lambda k: "<?php\n$o = " + "enum   (1)   " * k + "\n{}\n",
            128000)

    @pytest.mark.slow
    def test_perf_many_closed_strings_scale_linearly(self):
        # An output rebuild per closed string, or a header built by
        # repeated concatenation, would be quadratic here.
        self._assert_cpu_scales(
            lambda k: "<?php\n$o = " + "'a' . " * k + "\n{}\n", 8000)

    @pytest.mark.slow
    def test_perf_many_mixed_closed_strings_scale_linearly(self):
        for keep in (False, True):
            self._assert_cpu_scales(
                lambda k: "<?php\n$o = " + "\"b\" . 'c' . " * k + "\n{}\n",
                8000, keep_strings=keep)

    # -- hang guards (subprocess, wall-clock watchdog) ------------------
    #
    # Each guard runs the scan in a subprocess under a 30 s wall-clock
    # timeout. The subprocess prints a sentinel after the scan: the view's
    # length and the sha256 of the whole view. The parent requires exit 0,
    # exactly one well-formed sentinel line and, once the watchdogged run
    # has finished (so this cannot hang), the same length and digest
    # computed in-process on the identical input — an exact oracle, since
    # the view is a deterministic function of the input. A target that
    # exits early, crashes, prints a stale or partial result, or runs
    # past the limit fails.

    _SENTINEL = "VIEW-SENTINEL"

    def _root(self):
        import os
        return os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))

    def _run_guard(self, code, limit):
        import re as _re
        import subprocess
        import sys
        try:
            r = subprocess.run([sys.executable, "-B", "-c", code,
                                self._root()],
                               timeout=limit, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"HANG: still running after {limit}s")
        if r.returncode != 0:
            raise AssertionError(
                f"GUARD: exit {r.returncode}: {r.stderr[-300:]}")
        lines = [ln for ln in r.stdout.splitlines()
                 if ln.split(" ", 1)[0] == self._SENTINEL]
        if len(lines) != 1:
            raise AssertionError(f"GUARD: {len(lines)} sentinel lines")
        m = _re.fullmatch(self._SENTINEL + r" (\d+) ([0-9a-f]{64})",
                          lines[0])
        if m is None:
            raise AssertionError(f"GUARD: malformed sentinel {lines[0]!r}")
        return int(m.group(1)), m.group(2)

    def _guard_target(self, expr, keep_strings):
        return ("import hashlib, sys; sys.path.insert(0, sys.argv[1]); "
                "from core.audit.source_view import "
                "sanitized_view_with_status as S; "
                f"v = S({expr}, 'a.php', keep_strings={keep_strings!r}).text; "
                f"print({self._SENTINEL!r}, len(v), "
                "hashlib.sha256(v.encode('utf-8')).hexdigest())")

    def _finishes_within(self, expr, keep_strings, limit=30.0, code=None):
        import hashlib
        if code is None:
            code = self._guard_target(expr, keep_strings)
        got = self._run_guard(code, limit)
        src = eval(expr, {"__builtins__": {}})
        view = sanitized_view_with_status(
            src, "a.php", keep_strings=keep_strings).text
        want = (len(view), hashlib.sha256(view.encode("utf-8")).hexdigest())
        assert got == want, ("GUARD: result differs", got, want)

    def test_guard_accepts_a_well_formed_sentinel(self):
        digest = "0" * 64
        assert self._run_guard(
            f"print('noise'); print({self._SENTINEL!r}, 7, {digest!r})",
            30.0) == (7, digest)

    def test_guard_rejects_a_missing_sentinel(self):
        with pytest.raises(AssertionError, match="0 sentinel lines"):
            self._run_guard("pass", 30.0)

    def test_guard_rejects_a_malformed_sentinel(self):
        for line in ("12 abc", "x " + "0" * 64, "12 " + "0" * 63):
            with pytest.raises(AssertionError, match="malformed sentinel"):
                self._run_guard(f"print({self._SENTINEL!r}, {line!r})",
                                30.0)

    def test_guard_rejects_a_nonzero_exit(self):
        with pytest.raises(AssertionError, match="exit 3"):
            self._run_guard(
                f"print({self._SENTINEL!r}, 1, {'0' * 64!r}); "
                "raise SystemExit(3)", 30.0)

    def test_guard_rejects_a_timeout(self):
        with pytest.raises(AssertionError, match="HANG"):
            self._run_guard("import time; time.sleep(30)", 1.0)

    def test_guard_rejects_a_wrong_result(self):
        # A target that prints the right length but the digest of only
        # part of the view.
        expr = "'<?php\\n$o = ' + \"'a' . \" * 100 + '\\n{}\\n'"
        code = self._guard_target(expr, False).replace(
            "hashlib.sha256(v.encode('utf-8'))",
            "hashlib.sha256(v[:40].encode('utf-8'))")
        assert code != self._guard_target(expr, False)
        self._finishes_within(expr, False)          # the real target passes
        with pytest.raises(AssertionError, match="result differs"):
            self._finishes_within(expr, False, code=code)


    def test_hang_guard_escaped_quote_run(self):
        # The regex version took about 61 s CPU here (quadratic).
        self._finishes_within(
            "\"<?php\\n$a = '\" + \"\\\\'\" * 80000 + \"\\n{}\\n\"", True)

    def test_hang_guard_attribute_run_after_new(self):
        # The regex version took about 45 s CPU here (quadratic).
        self._finishes_within(
            "'<?php\\n$o = new' + '#[new' * 160000 + '\\nclass() {}\\n'",
            False)

    def test_hang_guard_keywords_in_one_header(self):
        # The regex version took over 300 s here (cubic).
        self._finishes_within(
            "'<?php\\n$o = ' + 'new #[ class (' * 8000 + '\\n{}\\n'", False)

    def test_hang_guard_many_closed_strings(self):
        # An output rebuild per closed string: about 145 s here.
        self._finishes_within(
            "'<?php\\n$o = ' + \"'a' . \" * 64000 + '\\n{}\\n'", False)
