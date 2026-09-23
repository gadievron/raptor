"""Sanitized source view — comments/strings blanked, offsets preserved."""

from __future__ import annotations

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
