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
