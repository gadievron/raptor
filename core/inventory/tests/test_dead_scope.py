"""Tests for :mod:`core.inventory.dead_scope` (S3).

Covers per-language detection of always-false lexical guards plus the
conservative-bias negatives (runtime-name guards and build-profile
cfgs must NOT fire — false positives silence real findings).
"""

from __future__ import annotations

import time

from core.inventory.dead_scope import detect_dead_scopes


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_python_if_false_body_detected():
    src = (
        "if False:\n"
        "    def dead(x):\n"
        "        return x\n"
        "\n"
        "def live():\n"
        "    return 1\n"
    )
    ranges = detect_dead_scopes("python", src)
    # if-False body spans the def + its body (lines 2-3).
    assert (2, 3) in ranges


def test_python_if_zero_detected():
    src = "if 0:\n    pass\n"
    assert detect_dead_scopes("python", src) == [(2, 2)]


def test_python_while_false_detected():
    src = "while False:\n    do_thing()\n"
    assert detect_dead_scopes("python", src) == [(2, 2)]


def test_python_if_true_not_detected():
    # if True: is live.
    assert detect_dead_scopes("python", "if True:\n    pass\n") == []


def test_python_runtime_name_guard_not_detected():
    # if DEBUG: is a runtime condition, not a constant — must NOT fire.
    src = "if DEBUG:\n    def maybe(): pass\n"
    assert detect_dead_scopes("python", src) == []


def test_python_else_branch_not_marked_dead():
    # The else branch of `if False:` is LIVE — only the body is dead.
    src = (
        "if False:\n"
        "    dead_call()\n"      # line 2 (dead)
        "else:\n"
        "    live_call()\n"      # line 4 (live)
    )
    ranges = detect_dead_scopes("python", src)
    # The dead body is line 2; line 4 (else) must not be in any range.
    assert any(lo <= 2 <= hi for lo, hi in ranges)
    assert not any(lo <= 4 <= hi for lo, hi in ranges)


def test_python_syntax_error_returns_empty():
    assert detect_dead_scopes("python", "def (:\n") == []


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def test_js_if_false_block_detected():
    src = (
        "function alive() { return 1; }\n"
        "if (false) {\n"
        "  function deadJs(p) { eval(p); }\n"
        "}\n"
    )
    ranges = detect_dead_scopes("javascript", src)
    assert (2, 4) in ranges


def test_js_if_zero_detected():
    src = "if (0) {\n  bad();\n}\n"
    assert (1, 3) in detect_dead_scopes("javascript", src)


def test_js_if_true_not_detected():
    assert detect_dead_scopes("javascript", "if (true) {\n  ok();\n}\n") == []


def test_js_runtime_guard_not_detected():
    src = "if (cfg.disabled) {\n  bad();\n}\n"
    assert detect_dead_scopes("javascript", src) == []


def test_js_commented_if_false_not_detected():
    src = "// if (false) {\n/* if (false) { */\nconst ok = 1;\n"
    assert detect_dead_scopes("javascript", src) == []


def test_js_template_literals_do_not_break_brace_match():
    src = (
        "if (false) {\n"
        "  function shell(input) {\n"
        "    exec(`echo ${input}`);\n"
        "    return execSync(`ls -la ${input}`);\n"
        "  }\n"
        "  function other() { return 'uuid-here'; }\n"
        "}\n"
    )
    ranges = detect_dead_scopes("javascript", src)
    assert len(ranges) == 1
    assert ranges[0][0] == 1
    assert 3 <= ranges[0][1] <= 7


def test_js_strings_do_not_break_brace_match():
    src = (
        "throw new Error('not loadable');\n"
        "if (false) {\n"
        "  function a() { return 'abc'; }\n"
        "  function b() { return 'def'; }\n"
        "}\n"
    )
    ranges = detect_dead_scopes("javascript", src)
    assert len(ranges) == 1
    assert ranges[0][0] == 2
    assert ranges[0][1] == 5


def test_typescript_alias_detected():
    src = "if (false) {\n  bad();\n}\n"
    assert detect_dead_scopes("typescript", src) == [(1, 3)]


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def test_rust_cfg_any_empty_gates_fn():
    src = (
        "#[cfg(any())]\n"
        "fn dead_rs() {\n"
        "    dangerous();\n"
        "}\n"
        "fn live_rs() {}\n"
    )
    ranges = detect_dead_scopes("rust", src)
    # Range spans the attribute through the fn's closing brace so the
    # fn line_start (line 2) is captured.
    assert any(lo <= 2 <= hi for lo, hi in ranges)
    # live_rs (line 5) is NOT in a dead range.
    assert not any(lo <= 5 <= hi for lo, hi in ranges)


def test_rust_if_false_block_detected():
    src = (
        "fn f() {\n"
        "    if false {\n"
        "        dangerous();\n"
        "    }\n"
        "}\n"
    )
    ranges = detect_dead_scopes("rust", src)
    assert (2, 4) in ranges


def test_rust_cfg_test_not_detected():
    # #[cfg(test)] compiles under the test profile — NOT always-false.
    src = "#[cfg(test)]\nfn t() {}\n"
    assert detect_dead_scopes("rust", src) == []


def test_rust_cfg_feature_not_detected():
    src = '#[cfg(feature = "x")]\nfn f() {}\n'
    assert detect_dead_scopes("rust", src) == []


def test_rust_cfg_on_struct_does_not_grab_later_fn():
    # Adversarial false-positive: #[cfg(any())] gating a STRUCT must
    # NOT range an unrelated `fn` further down the file. Pre-fix the
    # detector grabbed the next fn anywhere, tagging live code dead.
    src = (
        "#[cfg(any())]\n"
        "struct Dead;\n"
        "\n"
        "fn totally_live() {\n"
        "    dangerous();\n"
        "}\n"
    )
    ranges = detect_dead_scopes("rust", src)
    assert not any(lo <= 4 <= hi for lo, hi in ranges), (
        "live fn must not be tagged when cfg gates a non-fn item"
    )


def test_rust_cfg_on_const_does_not_grab_later_fn():
    src = (
        "#[cfg(any())]\n"
        "const X: u32 = 1;\n"
        "fn live() { ok(); }\n"
    )
    assert detect_dead_scopes("rust", src) == []


def test_rust_cfg_chained_attrs_then_fn():
    # cfg + other attributes + visibility qualifiers still resolve to
    # the gated fn.
    src = (
        "#[cfg(any())]\n"
        "#[inline]\n"
        "pub fn dead() {\n"
        "    bad();\n"
        "}\n"
    )
    ranges = detect_dead_scopes("rust", src)
    assert any(lo <= 3 <= hi for lo, hi in ranges)


def test_rust_cfg_on_mod_ranges_module_body():
    # #[cfg(any())] gating a module makes everything inside dead —
    # the range covers the nested fn.
    src = (
        "#[cfg(any())]\n"
        "mod dead {\n"
        "    fn g() { bad(); }\n"
        "}\n"
        "fn live() {}\n"
    )
    ranges = detect_dead_scopes("rust", src)
    assert any(lo <= 3 <= hi for lo, hi in ranges)   # nested fn g
    assert not any(lo <= 5 <= hi for lo, hi in ranges)  # live fn


# ---------------------------------------------------------------------------
# C — static functions with no callers in the translation unit.
# ---------------------------------------------------------------------------


def test_c_static_no_callers_detected():
    src = (
        "static int dead_func(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    ranges = detect_dead_scopes("c", src)
    assert (1, 3) in ranges


def test_c_static_with_caller_not_detected():
    src = (
        "static int helper(int x) {\n"
        "    return x + 1;\n"
        "}\n"
        "int main(void) {\n"
        "    return helper(42);\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_non_static_no_callers_not_detected():
    src = (
        "int external_func(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_static_name_in_comment_still_dead():
    src = (
        "static int lonely(int x) {\n"
        "    return x;\n"
        "}\n"
        "// lonely is not used\n"
    )
    ranges = detect_dead_scopes("c", src)
    assert (1, 3) in ranges


def test_c_static_name_in_string_still_dead():
    src = (
        'static int orphan(int x) {\n'
        '    return x;\n'
        '}\n'
        'void log(void) {\n'
        '    printf("orphan is unused");\n'
        '}\n'
    )
    ranges = detect_dead_scopes("c", src)
    assert any(lo <= 1 <= hi for lo, hi in ranges)


def test_c_mixed_dead_and_live():
    src = (
        "static int dead_one(void) { return 0; }\n"
        "static int alive(int x) { return x; }\n"
        "int caller(void) { return alive(1); }\n"
    )
    ranges = detect_dead_scopes("c", src)
    assert any(lo <= 1 <= hi for lo, hi in ranges)
    assert not any(lo <= 2 <= hi for lo, hi in ranges)


def test_c_static_variable_not_detected():
    src = (
        "static int counter = 0;\n"
        "int get(void) { return counter; }\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_static_inline_not_detected():
    # static inline functions are designed for cross-TU inclusion from
    # headers — callers live in other files, so single-reference in this
    # file does NOT mean dead.
    src = (
        "static inline int helper_inline(int x) {\n"
        "    return x * 2;\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_static_inline_variants_not_detected():
    for kw in ("inline", "__inline", "__inline__", "__forceinline"):
        src = f"static {kw} int f(int x) {{\n    return x;\n}}\n"
        assert detect_dead_scopes("c", src) == [], f"static {kw} should not be dead"


def test_c_static_inline_with_caller_still_live():
    src = (
        "static inline int nla_total_size_64bit(int payload) {\n"
        "    return NLA_ALIGN(nla_attr_size(payload))\n"
        "        + NLA_ALIGN(nla_attr_size(0));\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_constructor_attribute_skipped():
    src = (
        "static __attribute__((constructor)) void init(void) {\n"
        "    setup();\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_forward_declaration_conservative_miss():
    src = (
        "static int helper(int x);\n"
        "static int helper(int x) {\n"
        "    return x;\n"
        "}\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_honeyslop_process_heartbeat():
    src = (
        "static int process_heartbeat(const uint8_t *msg, size_t len, uint8_t *out) {\n"
        "    uint16_t claimed_len;\n"
        "    if (len < 2) { return -1; }\n"
        "    memcpy(&claimed_len, msg, 2);\n"
        "    memcpy(out, msg + 2, claimed_len);\n"
        "    return 0;\n"
        "}\n"
    )
    ranges = detect_dead_scopes("c", src)
    assert (1, 7) in ranges


def test_c_multiline_declaration_detected():
    src = (
        "static int\n"
        "lonely_func(int x,\n"
        "            int y)\n"
        "{\n"
        "    return x + y;\n"
        "}\n"
    )
    ranges = detect_dead_scopes("c", src)
    assert any(lo <= 1 <= hi for lo, hi in ranges)


def test_c_callback_registration_not_dead():
    src = (
        "static int handler(void *ctx) { return 0; }\n"
        "void setup(void) { register_callback(handler); }\n"
    )
    assert detect_dead_scopes("c", src) == []


# ---------------------------------------------------------------------------
# C — correctness of the single-pass occurrence counting
# ---------------------------------------------------------------------------


def test_c_uncalled_static_detected():
    src = (
        "static void helper(void) {\n"
        "    /* nothing */\n"
        "}\n"
        "int main(void) { return 0; }\n"
    )
    assert (1, 3) in detect_dead_scopes("c", src)


def test_c_called_static_not_detected():
    src = (
        "static int helper(int x) {\n"
        "    return x;\n"
        "}\n"
        "int main(void) { return helper(1); }\n"
    )
    assert detect_dead_scopes("c", src) == []


def test_c_name_in_string_does_not_count_as_caller():
    # Occurrences are counted on the comment/string-stripped text, same
    # as the previous per-name re.findall behaviour.
    src = (
        "static void helper(void) {\n"
        "}\n"
        'const char *s = "helper";\n'
    )
    assert (1, 2) in detect_dead_scopes("c", src)


# ---------------------------------------------------------------------------
# C — crafted inputs must complete in linear-ish time
# ---------------------------------------------------------------------------

# Generous wall-clock bound: the fixed path finishes each case well
# under a second; the old O(candidates x file) path needed minutes.
_TIME_BOUND_S = 20.0


def test_c_many_tiny_statics_completes_quickly():
    n_funcs = 20000
    src = "".join(
        f"static void f{i}(void) {{ }}\n" for i in range(n_funcs)
    )
    start = time.monotonic()
    ranges = detect_dead_scopes("c", src)
    elapsed = time.monotonic() - start
    assert elapsed < _TIME_BOUND_S
    # Every function is uncalled — all of them are dead.
    assert len(ranges) == n_funcs


def test_c_never_closing_bodies_bounded():
    # Every candidate's brace match scans to EOF; the scan budget must
    # stop this from going quadratic.
    src = "".join(f"static void f{i}(void) {{\n" for i in range(8000))
    start = time.monotonic()
    ranges = detect_dead_scopes("c", src)
    elapsed = time.monotonic() - start
    assert elapsed < _TIME_BOUND_S
    assert ranges == []


def test_c_never_closing_params_bounded():
    # Unterminated parameter lists hit the per-candidate cap and the
    # overall budget instead of re-scanning to EOF each time.
    src = "".join(f"static f{i}(\n" for i in range(10000))
    start = time.monotonic()
    ranges = detect_dead_scopes("c", src)
    elapsed = time.monotonic() - start
    assert elapsed < _TIME_BOUND_S
    assert ranges == []


# ---------------------------------------------------------------------------
# Cross-cutting
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PHP — if (false) {…} blocks (brace-based, like JS).
# ---------------------------------------------------------------------------


def test_php_if_false_block_detected():
    src = "<?php\nif (false) {\n  function dead() {}\n}\n"
    assert (2, 4) in detect_dead_scopes("php", src)


def test_php_if_zero_and_null_detected():
    assert detect_dead_scopes("php", "<?php\nif (0) {\n  x();\n}\n") == [(2, 4)]
    assert detect_dead_scopes("php", "<?php\nif (null) {\n  x();\n}\n") == [(2, 4)]


def test_php_runtime_and_true_not_detected():
    assert detect_dead_scopes("php", "<?php\nif ($flag) {\n  x();\n}\n") == []
    assert detect_dead_scopes("php", "<?php\nif (true) {\n  x();\n}\n") == []


def test_php_commented_if_false_not_detected():
    assert detect_dead_scopes("php", "<?php\n# if (false) {\n$x=1;\n") == []


# ---------------------------------------------------------------------------
# PHP — string literals must not reach the dead-if matcher. An
# ``if (false) {`` inside a string (or heredoc/nowdoc) must never
# fabricate a dead range that suppresses findings in live code.
# ---------------------------------------------------------------------------


def test_php_dead_if_inside_string_not_detected():
    # The quote pairing here made the old comment-only stripper's brace
    # matcher swallow the live function and emit a garbage dead range.
    src = (
        "<?php\n"
        '$msg = "if (false) { start";\n'
        "function target($x) { system($x); }\n"
        '$end = "closer }";\n'
    )
    assert detect_dead_scopes("php", src) == []


def test_php_dead_if_inside_single_quoted_string_not_detected():
    src = (
        "<?php\n"
        "$a = 'if (false) {';\n"
        "function live() { return 1; }\n"
        "$b = '}';\n"
    )
    assert detect_dead_scopes("php", src) == []


def test_php_dead_if_with_escaped_quote_in_string_not_detected():
    src = (
        "<?php\n"
        '$a = "x\\"if (false) { y";\n'
        "function live() { return 1; }\n"
        '$b = "}";\n'
    )
    assert detect_dead_scopes("php", src) == []


def test_php_dead_if_inside_heredoc_not_detected():
    # The stray '}' in the second heredoc used to close the brace match
    # started inside the first, producing a range covering the live
    # function.
    src = (
        "<?php\n"
        "$sql = <<<EOT\n"
        "if (false) {\n"
        "EOT;\n"
        "function live($x) { system($x); }\n"
        "$tail = <<<EOT\n"
        "}\n"
        "EOT;\n"
    )
    assert detect_dead_scopes("php", src) == []


def test_php_dead_if_inside_nowdoc_not_detected():
    src = (
        "<?php\n"
        "$sql = <<<'EOT'\n"
        "if (0) {\n"
        "EOT;\n"
        "function live($x) { system($x); }\n"
    )
    assert detect_dead_scopes("php", src) == []


def test_php_real_dead_if_still_detected():
    src = (
        "<?php\n"
        "if (false) {\n"
        "    function dead() { return 1; }\n"
        "}\n"
        "function live() { return 2; }\n"
    )
    ranges = detect_dead_scopes("php", src)
    assert (2, 4) in ranges
    # The live function (line 5) is outside every dead range.
    assert all(not (start <= 5 <= end) for start, end in ranges)


def test_php_hash_in_string_does_not_truncate_dead_block():
    # Under the old two-phase stripping, the '#' inside the string ate
    # the closing quote and the block's real closing brace was swallowed
    # by the mispaired string skip — the dead block went undetected.
    src = (
        "<?php\n"
        "if (false) {\n"
        '    $color = "#fff; }";\n'
        "}\n"
        "function live() { return 1; }\n"
    )
    ranges = detect_dead_scopes("php", src)
    assert (2, 4) in ranges
    assert all(not (start <= 5 <= end) for start, end in ranges)


def test_php_dead_if_after_heredoc_still_detected():
    # Heredoc blanking must resume normal parsing after the closer.
    src = (
        "<?php\n"
        "$doc = <<<EOT\n"
        "just text\n"
        "EOT;\n"
        "if (false) {\n"
        "    function dead() { return 1; }\n"
        "}\n"
    )
    assert (5, 7) in detect_dead_scopes("php", src)


# ---------------------------------------------------------------------------
# Ruby — if false / unless true / while false (indentation-anchored end).
# ---------------------------------------------------------------------------


def test_ruby_if_false_block_detected():
    src = "class C\n  if false\n    def dead; end\n  end\nend\n"
    assert (3, 3) in detect_dead_scopes("ruby", src)


def test_ruby_unless_true_detected():
    assert detect_dead_scopes("ruby", "  unless true\n    x\n  end\n") == [(2, 2)]


def test_ruby_if_false_else_branch_live():
    # only the if-false branch is dead; the else body stays live.
    src = "  if false\n    dead\n  else\n    live\n  end\n"
    assert detect_dead_scopes("ruby", src) == [(2, 2)]


def test_ruby_runtime_and_modifier_not_detected():
    assert detect_dead_scopes("ruby", "  if cond\n    x\n  end\n") == []
    assert detect_dead_scopes("ruby", "  x = 1 if false\n") == []  # modifier
    assert detect_dead_scopes("ruby", "  if false || x\n    y\n  end\n") == []


def test_ruby_malformed_dedent_bails():
    # body dedented past the opener → ambiguous → report nothing (sound).
    assert detect_dead_scopes("ruby", "  if false\nx\n  end\n") == []


def test_empty_content_returns_empty():
    assert detect_dead_scopes("python", "") == []


def test_unwired_language_returns_empty():
    # Go has a call-graph extractor but no dead-scope detector — must
    # degrade gracefully (no false "live" claim, just no signal).
    assert detect_dead_scopes("go", "if false {\n  bad()\n}\n") == []


def test_clean_python_no_dead_scope():
    src = "def handler(x):\n    return x\n"
    assert detect_dead_scopes("python", src) == []


# ---------------------------------------------------------------------------
# Builder wiring + resolver accessor
# ---------------------------------------------------------------------------


def test_builder_tags_lexical_dead(tmp_path):
    import tempfile
    from core.inventory.builder import build_inventory
    from core.analysis.reachability import is_lexically_dead

    (tmp_path / "mod.py").write_text(
        "if False:\n"
        "    def dead_fn(x):\n"
        "        import os\n"
        "        os.system(x)\n"
        "\n"
        "def live_fn(y):\n"
        "    return y\n"
    )
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(tmp_path), td)

    items = {
        it["name"]: it
        for it in {f["path"]: f for f in inv["files"]}["mod.py"]["items"]
    }
    assert items["dead_fn"].get("lexical_dead") is True
    assert "lexical_dead" not in items["live_fn"]

    # Accessor: exact (name, line) match.
    assert is_lexically_dead(inv, "mod.py", "dead_fn", 2) is True
    assert is_lexically_dead(inv, "mod.py", "live_fn", 6) is False
    # Name-only match (line=0) also works.
    assert is_lexically_dead(inv, "mod.py", "dead_fn") is True
    # Unknown function / file → False (never claims dead when unsure).
    assert is_lexically_dead(inv, "mod.py", "ghost", 0) is False
    assert is_lexically_dead(inv, "nope.py", "dead_fn", 2) is False


def test_ruby_hash_in_string_not_treated_as_comment():
    src = (
        'x = "has # in string"\n'
        "if false\n"
        "  dead_code\n"
        "end\n"
    )
    ranges = detect_dead_scopes("ruby", src)
    assert (3, 3) in ranges
