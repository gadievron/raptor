"""Two-direction adjudication for the C output-encoding sub-shape
rules: ``c/crlf-protocol-line.yaml`` (CWE-93 — a bare variable
formatted into a protocol line with no CR/LF strip) and
``c/quoted-string-escape.yaml`` (CWE-116 — an escaper that handles one
of {double-quote, backslash} but not the other).

Both rules are CONFIRM-ONLY (`# raptor: confirm-only` marker): the
correct-code direction asserts the rule does not match AND that
run_semgrep_sweep grades the silence inconclusive, never refuted — a
sub-shape rule's zero-match answers only its own shape, and a refuted
outcome would let the documented FN modes discard real bugs.

Rule-level tests only — dispatch wiring is covered separately. All
snippets are synthetic. The live tests run the real semgrep binary
through ``run_semgrep_sweep`` (the exact call the tool chain
dispatches) and are skipped when semgrep is not installed — the
``test_cwe_dispatch_php`` convention.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "semgrep" / "rules"
)

_CRLF_RULE = "c/crlf-protocol-line.yaml"
_QUOTE_RULE = "c/quoted-string-escape.yaml"

# ── CRLF rule fixtures: (name, snippet, should_fire) ─────────────────
# One shape per named FP/FN mode, both directions.

_CRLF_CASES: list[tuple[str, str, bool]] = [
    (
        "bare_variable_fires",
        "void f(int fd, char *buf, const char *rcpt) {\n"
        '    sprintf(buf, "RCPT TO:<%s>\\r\\n", rcpt);\n'
        "    emit(fd, buf);\n"
        "}\n",
        True,
    ),
    (
        # Positive-polarity strpbrk with the emit INSIDE the detect
        # branch — the vulnerable inverse of the guarded shapes; a
        # polarity-blind exclusion would silence exactly this bug.
        "emit_inside_detect_branch_fires",
        "void f(FILE *s, char *v) {\n"
        '    if (strpbrk(v, "\\r\\n")) {\n'
        '        fprintf(s, "CMD %s\\r\\n", v);\n'
        "    }\n"
        "}\n",
        True,
    ),
    (
        # A DIFFERENT variable being stripped does not silence the
        # emit of the untouched one.
        "other_variable_strip_still_fires",
        "void f(FILE *s, char *name, char *other) {\n"
        "    other = strip_crlf(other);\n"
        '    fprintf(s, "USER %s\\r\\n", name);\n'
        "}\n",
        True,
    ),
    (
        "negated_guard_emit_inside_silent",
        "void f(FILE *s, char *v) {\n"
        '    if (!strpbrk(v, "\\r\\n")) {\n'
        '        fprintf(s, "MAIL FROM:%s\\r\\n", v);\n'
        "    }\n"
        "}\n",
        False,
    ),
    (
        "reject_then_emit_silent",
        "void f(FILE *s, char *v) {\n"
        '    if (strpbrk(v, "\\r\\n"))\n'
        "        return;\n"
        '    fprintf(s, "USER %s\\r\\n", v);\n'
        "}\n",
        False,
    ),
    (
        "goto_reject_silent",
        "void f(FILE *s, char *v) {\n"
        '    if (strpbrk(v, "\\r\\n")) goto fail;\n'
        '    fprintf(s, "USER %s\\r\\n", v);\n'
        "fail:\n"
        "    return;\n"
        "}\n",
        False,
    ),
    (
        "strchr_reject_silent",
        "void f(FILE *s, char *v) {\n"
        "    if (strchr(v, '\\r') || strchr(v, '\\n'))\n"
        "        return;\n"
        '    fprintf(s, "USER %s\\r\\n", v);\n'
        "}\n",
        False,
    ),
    (
        "manual_strip_loop_silent",
        "void f(FILE *s, char *v) {\n"
        "    for (char *p = v; *p; p++)\n"
        "        if (*p == '\\r' || *p == '\\n')\n"
        "            *p = ' ';\n"
        '    fprintf(s, "USER %s\\r\\n", v);\n'
        "}\n",
        False,
    ),
    (
        "inplace_sanitizer_call_silent",
        "void f(FILE *s, char *v) {\n"
        "    sanitize_crlf_inplace(v);\n"
        '    fprintf(s, "USER %s\\r\\n", v);\n'
        "}\n",
        False,
    ),
    (
        "rebinding_from_call_silent",
        "void f(FILE *s, char *buf, char *rcpt) {\n"
        "    rcpt = strip_crlf(rcpt);\n"
        '    sprintf(buf, "RCPT TO:<%s>\\r\\n", rcpt);\n'
        "}\n",
        False,
    ),
    (
        # Misattribution guard: a bare int argument next to an escaped
        # string in a multi-conversion template must not be claimed —
        # the single-conversion anchor drops the whole shape.
        "multi_conversion_misattribution_silent",
        "void f(FILE *s, int code, const char *user) {\n"
        '    fprintf(s, "%d %s\\r\\n", code, escape_crlf(user));\n'
        "}\n",
        False,
    ),
    (
        # Paren-free compound expressions are not bare variables.
        "compound_expression_silent",
        "void f(char *buf, int a, int b, int ok, char *x, char *y) {\n"
        '    sprintf(buf, "LEN %s\\r\\n", a + b);\n'
        '    sprintf(buf, "USER %s\\r\\n", ok ? x : y);\n'
        "}\n",
        False,
    ),
    (
        # Call results (potential escapers) and literals never fire.
        "call_result_and_literal_silent",
        "void f(char *buf) {\n"
        '    sprintf(buf, "USER %s\\r\\n", get_user());\n'
        '    sprintf(buf, "MODE %s\\r\\n", "PASV");\n'
        "}\n",
        False,
    ),
    (
        # No trailing-CRLF %s template — %d cannot carry CR/LF.
        "no_protocol_template_silent",
        "void f(char *buf, const char *m, int code) {\n"
        '    sprintf(buf, "note: %s ok", m);\n'
        '    sprintf(buf, "CODE %d\\r\\n", code);\n'
        "}\n",
        False,
    ),
]

# ── quote rule fixtures ──────────────────────────────────────────────

_QUOTE_CASES: list[tuple[str, str, bool]] = [
    (
        "quote_only_escaper_fires",
        "void quote(char *dst, const char *src) {\n"
        "    while (*src) {\n"
        "        if (*src == '\"') {\n"
        "            *dst++ = '\\\\';\n"
        "        }\n"
        "        *dst++ = *src++;\n"
        "    }\n"
        "}\n",
        True,
    ),
    (
        "backslash_only_escaper_fires",
        "void quote(char *dst, const char *src) {\n"
        "    while (*src) {\n"
        "        if (*src == '\\\\') { *dst++ = '\\\\'; }\n"
        "        *dst++ = *src++;\n"
        "    }\n"
        "}\n",
        True,
    ),
    (
        # Incomplete escaper next to an UNRELATED helper that tests
        # the backslash in a different function — must still fire
        # (the completeness test is function-scoped).
        "cross_function_backslash_test_still_fires",
        "static int helper(char c) { return c == '\\\\'; }\n"
        "void quote(char *dst, const char *src) {\n"
        "    while (*src) {\n"
        "        if (*src == '\"') { *dst++ = '\\\\'; }\n"
        "        *dst++ = *src++;\n"
        "    }\n"
        "}\n",
        True,
    ),
    (
        "or_combined_complete_silent",
        "void quote(char *dst, const char *src) {\n"
        "    while (*src) {\n"
        "        if (*src == '\"' || *src == '\\\\') {\n"
        "            *dst++ = '\\\\';\n"
        "        }\n"
        "        *dst++ = *src++;\n"
        "    }\n"
        "}\n",
        False,
    ),
    (
        "else_if_chain_complete_silent",
        "void quote(char *dst, const char *src) {\n"
        "    while (*src) {\n"
        "        if (*src == '\\\\') {\n"
        "            *dst++ = '\\\\';\n"
        "        } else if (*src == '\"') {\n"
        "            *dst++ = '\\\\';\n"
        "        }\n"
        "        *dst++ = *src++;\n"
        "    }\n"
        "}\n",
        False,
    ),
    (
        # Yoda-order backslash test still reads as complete.
        "yoda_complete_silent",
        "void quote(const char *in, char *out) {\n"
        "    for (; *in; in++) {\n"
        "        char c = *in;\n"
        "        if ('\\\\' == c) { *out++ = '\\\\'; continue; }\n"
        "        if (c == '\"') { *out++ = '\\\\'; continue; }\n"
        "        *out++ = c;\n"
        "    }\n"
        "}\n",
        False,
    ),
    (
        # Braceless backslash branch still reads as complete.
        "braceless_complete_silent",
        "void quote(const char *in, char *out) {\n"
        "    for (; *in; in++) {\n"
        "        char c = *in;\n"
        "        if (c == '\\\\')\n"
        "            *out++ = '\\\\';\n"
        "        if (c == '\"') { *out++ = '\\\\'; }\n"
        "        *out++ = c;\n"
        "    }\n"
        "}\n",
        False,
    ),
    (
        # State-machine tokenizer storing '\\' into a plain variable
        # as a marker — no output store, not an escaper.
        "state_marker_assignment_silent",
        "void scan(const char *in) {\n"
        "    char expect = 0;\n"
        "    for (; *in; in++) {\n"
        "        if (*in == '\"') { expect = '\\\\'; }\n"
        "    }\n"
        "    (void)expect;\n"
        "}\n",
        False,
    ),
]


class TestRuleFiles:
    @pytest.mark.parametrize("rule", [_CRLF_RULE, _QUOTE_RULE])
    def test_rule_file_exists(self, rule: str):
        assert (_RULES_DIR / rule).is_file()

    @pytest.mark.parametrize("rule", [_CRLF_RULE, _QUOTE_RULE])
    def test_rule_languages_are_c_and_cpp(self, rule: str):
        # The idioms were validated on both frontends; a language the
        # fixtures never exercised must not be claimed.
        text = (_RULES_DIR / rule).read_text(encoding="utf-8")
        assert "languages: [c, cpp]" in text
        for lang in ("php", "python", "java", "javascript", "go"):
            assert f"languages: [{lang}]" not in text

    @pytest.mark.parametrize("rule", [_CRLF_RULE, _QUOTE_RULE])
    def test_rules_declare_confirm_only(self, rule: str):
        from core.audit.sweep import is_confirm_only_rule

        assert is_confirm_only_rule(str(_RULES_DIR / rule))

    def test_php_rules_keep_refutation_semantics(self):
        # The confirm-only marker is per-rule opt-in; the PHP legs
        # keep their pinned scanned-witness refutations.
        from core.audit.sweep import is_confirm_only_rule

        for name in ("php/attr-encoding.yaml", "php/crlf-injection.yaml"):
            assert not is_confirm_only_rule(str(_RULES_DIR / name))


needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed",
)


def _sweep(tmp_path: Path, rule: str, snippet: str, *, fname: str,
           file_name: str = "app.c"):
    from core.audit.sweep import run_semgrep_sweep

    (tmp_path / file_name).write_text(snippet)
    return run_semgrep_sweep(
        target_path=tmp_path,
        file_path=file_name,
        function_name=fname,
        rule_config=str(_RULES_DIR / rule),
    )


@needs_semgrep
class TestCrlfRuleLive:
    """The real semgrep binary adjudicates every named mode through
    run_semgrep_sweep — the exact call the tool chain dispatches."""

    @pytest.mark.parametrize(
        ("name", "snippet", "should_fire"),
        _CRLF_CASES,
        ids=[c[0] for c in _CRLF_CASES],
    )
    def test_mode(self, name: str, snippet: str, should_fire: bool,
                  tmp_path: Path):
        result = _sweep(tmp_path, _CRLF_RULE, snippet, fname="f")
        if should_fire:
            assert result.outcome == "confirmed", (
                f"{name}: {result.outcome} {result.errors}"
            )
            assert result.matches
        else:
            # Confirm-only: correct code is SILENT and the silence is
            # graded inconclusive (dark), never refuted.
            assert result.outcome == "inconclusive", (
                f"{name}: {result.outcome} {result.errors}"
            )
            assert not result.matches
            assert "confirm-only" in (result.details or {}).get(
                "reason", "",
            )

    def test_fires_on_cpp(self, tmp_path: Path):
        result = _sweep(
            tmp_path, _CRLF_RULE, _CRLF_CASES[0][1], fname="f",
            file_name="app.cpp",
        )
        assert result.outcome == "confirmed", (
            f"{result.outcome} {result.errors}"
        )


@needs_semgrep
class TestQuoteRuleLive:
    @pytest.mark.parametrize(
        ("name", "snippet", "should_fire"),
        _QUOTE_CASES,
        ids=[c[0] for c in _QUOTE_CASES],
    )
    def test_mode(self, name: str, snippet: str, should_fire: bool,
                  tmp_path: Path):
        fname = "scan" if "state_marker" in name else "quote"
        result = _sweep(tmp_path, _QUOTE_RULE, snippet, fname=fname)
        if should_fire:
            assert result.outcome == "confirmed", (
                f"{name}: {result.outcome} {result.errors}"
            )
            assert result.matches
        else:
            assert result.outcome == "inconclusive", (
                f"{name}: {result.outcome} {result.errors}"
            )
            assert not result.matches
            assert "confirm-only" in (result.details or {}).get(
                "reason", "",
            )

    def test_complete_cpp_method_escaper_silent(self, tmp_path: Path):
        # The completeness test must bind C++ method bodies too.
        snippet = (
            "class Esc {\n"
            "public:\n"
            "    void escape(const char *in, char *out);\n"
            "};\n"
            "void Esc::escape(const char *in, char *out) {\n"
            "    for (; *in; in++) {\n"
            "        char c = *in;\n"
            "        if (c == '\\\\') { *out++ = '\\\\'; continue; }\n"
            "        if (c == '\"') { *out++ = '\\\\'; continue; }\n"
            "        *out++ = c;\n"
            "    }\n"
            "}\n"
        )
        result = _sweep(
            tmp_path, _QUOTE_RULE, snippet, fname="escape",
            file_name="app.cpp",
        )
        assert result.outcome == "inconclusive", (
            f"{result.outcome} {result.errors}"
        )
        assert not result.matches

    def test_incomplete_cpp_method_escaper_fires(self, tmp_path: Path):
        snippet = (
            "class Esc {\n"
            "public:\n"
            "    void escape(const char *in, char *out) {\n"
            "        for (; *in; in++) {\n"
            "            char c = *in;\n"
            "            if (c == '\"') { *out++ = '\\\\'; }\n"
            "            *out++ = c;\n"
            "        }\n"
            "    }\n"
            "};\n"
        )
        result = _sweep(
            tmp_path, _QUOTE_RULE, snippet, fname="escape",
            file_name="app.cpp",
        )
        assert result.outcome == "confirmed", (
            f"{result.outcome} {result.errors}"
        )


class TestConfirmOnlyMarkerScope:
    """The confirm-only role is curated-library-scoped and
    header-anchored: a dynamic (LLM-authored) rule cannot opt itself
    out of refutation semantics, and marker-shaped text outside the
    leading comment block never activates the role."""

    def test_tempfile_rule_with_marker_is_not_confirm_only(
        self, tmp_path: Path,
    ):
        from core.audit.sweep import is_confirm_only_rule

        rule = tmp_path / ".sweep-rule-inline.yaml"
        rule.write_text(
            "# raptor: confirm-only\n"
            "rules:\n"
            "  - id: inline-probe\n"
            "    languages: [c]\n"
            "    severity: INFO\n"
            "    message: probe\n"
            "    pattern: evil_call(...)\n",
        )
        assert not is_confirm_only_rule(str(rule))

    def test_header_anchoring(self):
        from core.audit.sweep import _parse_confirm_only_header

        assert _parse_confirm_only_header(
            "# raptor: confirm-only\nrules: []\n",
        )
        # BOM-prefixed first line still parses.
        assert _parse_confirm_only_header(
            "\ufeff# raptor: confirm-only\nrules: []\n",
        )
        # Later header comment line still parses.
        assert _parse_confirm_only_header(
            "# note\n# raptor: confirm-only\nrules: []\n",
        )
        # Marker text after the header block, inside a message
        # block, or as a near-miss spelling never parses.
        assert not _parse_confirm_only_header(
            "rules: []\n# raptor: confirm-only\n",
        )
        assert not _parse_confirm_only_header(
            "rules:\n  - id: x\n    message: >\n"
            "      # raptor: confirm-only\n",
        )
        assert not _parse_confirm_only_header(
            "# raptor : confirm-only\nrules: []\n",
        )

    def test_curated_library_markers_all_parse(self):
        """Loud-failure guard for future authors: any curated rule
        file that MENTIONS confirm-only must carry a well-formed
        header marker — a near-miss spelling would otherwise silently
        revert the rule to refutation semantics."""
        from core.audit.sweep import is_confirm_only_rule

        mentioning = [
            path for path in sorted(_RULES_DIR.rglob("*.yaml"))
            if "confirm-only" in path.read_text(encoding="utf-8")
        ]
        assert mentioning, "expected at least the two C encoding rules"
        for path in mentioning:
            assert is_confirm_only_rule(str(path)), (
                f"{path.name} mentions confirm-only but its marker "
                "does not parse — fix the header marker line"
            )

    @needs_semgrep
    def test_tempfile_marker_rule_still_refutes(self, tmp_path: Path):
        # End-to-end: an inline rule carrying the marker keeps the
        # scanned-witness refutation (author opt-out blocked).
        from core.audit.sweep import run_semgrep_sweep

        rule = tmp_path / ".sweep-rule-inline.yaml"
        rule.write_text(
            "# raptor: confirm-only\n"
            "rules:\n"
            "  - id: inline-probe\n"
            "    languages: [c]\n"
            "    severity: INFO\n"
            "    message: probe\n"
            "    pattern: evil_call(...)\n",
        )
        (tmp_path / "app.c").write_text(
            "void f(void) { benign_call(); }\n",
        )
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="app.c",
            function_name="f",
            rule_config=str(rule),
        )
        assert result.outcome == "refuted", (
            f"{result.outcome} {result.errors}"
        )


@needs_semgrep
class TestExpandedViewHonesty:
    """Fidelity-3 preprocessing rewrites the libc guard idioms the
    CRLF rule's exclusions anchor on (glibc strpbrk/strchr become
    _Generic selections), so the expanded second pass must never
    CONFIRM for confirm-only rules — correct code would read as
    confirmed there. The macro-hidden-sink rescue survives as an
    inconclusive lead."""

    def test_correct_code_with_libc_guard_and_macro_never_confirms(
        self, tmp_path: Path,
    ):
        # The false-confirm trigger shape: correct negated-strpbrk
        # guard + any ALL_CAPS macro invocation (arms the expanded
        # pass) + a real <string.h> include (arms the glibc rewrite).
        snippet = (
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "#define LOG_OK(v) log_ok(v)\n"
            "void f(FILE *s, char *v) {\n"
            '    if (!strpbrk(v, "\\r\\n")) { '
            'fprintf(s, "USER %s\\r\\n", v); }\n'
            "    LOG_OK(v);\n"
            "}\n"
        )
        result = _sweep(tmp_path, _CRLF_RULE, snippet, fname="f")
        assert result.outcome == "inconclusive", (
            f"{result.outcome} {result.errors}"
        )
        # Whether or not the preprocessor was available to run the
        # expanded pass, correct code must never earn a confirm.
        assert result.outcome != "confirmed"

    def test_strchr_reject_with_macro_never_confirms(
        self, tmp_path: Path,
    ):
        snippet = (
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "#define LOG_OK(v) log_ok(v)\n"
            "void f(FILE *s, char *v) {\n"
            "    if (strchr(v, '\\r') || strchr(v, '\\n'))\n"
            "        return;\n"
            '    fprintf(s, "USER %s\\r\\n", v);\n'
            "    LOG_OK(v);\n"
            "}\n"
        )
        result = _sweep(tmp_path, _CRLF_RULE, snippet, fname="f")
        assert result.outcome == "inconclusive", (
            f"{result.outcome} {result.errors}"
        )

    def test_macro_hidden_sink_earns_a_lead_not_a_confirm(
        self, tmp_path: Path,
    ):
        # The legitimate rescue case: the vulnerable emit lives
        # inside a macro the plain pass cannot see. Grade: an
        # inconclusive LEAD (evidence attached when the expanded
        # pass ran), never a promotion-grade confirm — the rule's
        # exclusions are structurally unsound in the expanded view,
        # so a confirm there cannot be trusted for this rule class.
        snippet = (
            "#include <stdio.h>\n"
            '#define EMIT_USER(s, v) fprintf(s, "USER %s\\r\\n", v)\n'
            "void f(FILE *s, char *v) {\n"
            "    EMIT_USER(s, v);\n"
            "}\n"
        )
        result = _sweep(tmp_path, _CRLF_RULE, snippet, fname="f")
        assert result.outcome == "inconclusive", (
            f"{result.outcome} {result.errors}"
        )
        if (result.details or {}).get("expanded_view"):
            # Preprocessor available: the lead carries its evidence
            # and names the expanded-view honesty cap.
            assert result.matches
            assert "lead" in result.details.get("reason", "")
