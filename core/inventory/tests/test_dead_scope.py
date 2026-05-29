"""Tests for :mod:`core.inventory.dead_scope` (S3).

Covers per-language detection of always-false lexical guards plus the
conservative-bias negatives (runtime-name guards and build-profile
cfgs must NOT fire — false positives silence real findings).
"""

from __future__ import annotations

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
    from core.inventory.reachability import is_lexically_dead

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
