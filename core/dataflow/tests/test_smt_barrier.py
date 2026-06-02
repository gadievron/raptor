"""Tests for the Tier 0 SMT backend.

Exercises each layer in isolation (extractor, dominance, prove) and the
full ``try_tier0`` orchestrator on the whoogle archetype.  Graceful
degradation is verified by patching the substrate's z3 gate to False so
the module returns Z3_UNAVAILABLE without touching z3 — matching the
existing ``smt_path_validator`` degradation pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.dataflow import smt_barrier as sb


# ---------------------------------------------------------------------------
# Validator extractor.
# ---------------------------------------------------------------------------

def test_extract_validator_anchored_charset_re_match():
    diff = (
        "@@ -1,2 +1,3 @@\n"
        "     name = req()\n"
        '+    if not re.match(r"^[A-Za-z0-9_.+-]+$", name): return error()\n'
        "     return sink(name)\n"
    )
    spec = sb.extract_validator(diff)
    assert spec is not None
    assert spec.kind == "charset"
    assert spec.var_name == "name"
    assert spec.charset == "A-Za-z0-9_.+-"


def test_extract_validator_fullmatch_no_anchors():
    """re.fullmatch's whole-string semantics are implicit; allow the form
    without explicit ^..$ anchors."""
    diff = '+if not re.fullmatch(r"[A-Za-z]+", x): raise X\n'
    spec = sb.extract_validator(diff)
    assert spec is not None and spec.charset == "A-Za-z" and spec.var_name == "x"


def test_extract_validator_rejects_non_anchored_re_match():
    """Without ^...$ (and re.match, not fullmatch), the validator only
    constrains a PREFIX — extractor must NOT treat it as whole-string."""
    diff = '+if not re.match(r"[A-Za-z]+", x): raise X\n'
    assert sb.extract_validator(diff) is None


def test_extract_validator_ignores_non_added_lines():
    """Lines starting with ' ' or '-' (context / removed) must be ignored;
    only '+' lines are part of the fix."""
    diff = '     if not re.match(r"^[A-Za-z]+$", x): pass\n'
    assert sb.extract_validator(diff) is None


def test_extract_validator_skips_file_header_marker():
    diff = '+++ b/app.py\n'
    assert sb.extract_validator(diff) is None


def test_extract_validator_none_when_no_pattern():
    assert sb.extract_validator("+x = 1\n+y = 2\n") is None
    assert sb.extract_validator("") is None


# ---------------------------------------------------------------------------
# Dominance: validator location on the SARIF codeFlow.
# ---------------------------------------------------------------------------

def test_dominance_source_order_with_exit_on_fail(tmp_path: Path):
    """The archetype: ``if not <call>:`` whose body returns -> dominates."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    if not re.match(r'^x$', x):\n"          # line 3 = validator
        "        return error()\n"
        "    return open(x)\n"                       # line 5 = sink
    )
    assert sb.validator_dominates_sink(src, validator_line=3, sink_line=5) is True


def test_dominance_false_when_validator_after_sink():
    """Source order matters: a validator that appears AFTER the sink can't
    have neutralised the value at the sink."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    open(x)\n"                              # line 3 = sink
        "    if not re.match(r'^x$', x):\n"          # line 4 = validator (later)
        "        return error()\n"
    )
    assert sb.validator_dominates_sink(src, validator_line=4, sink_line=3) is False


def test_dominance_false_when_block_doesnt_exit():
    """The ``if not <call>:`` exists but the body just logs / passes
    instead of return/raise -> the value reaches the sink unsanitized
    -> not sound -> declined."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    if not re.match(r'^x$', x):\n"          # line 3
        "        print('bad input')\n"               # no exit!
        "    return open(x)\n"                       # line 5 = sink
    )
    assert sb.validator_dominates_sink(src, validator_line=3, sink_line=5) is False


def test_dominance_true_with_raise():
    """``raise`` is also a function-exiting branch."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    if not re.match(r'^x$', x):\n"          # line 3
        "        raise ValueError('bad')\n"
        "    return open(x)\n"                       # line 5 = sink
    )
    assert sb.validator_dominates_sink(src, validator_line=3, sink_line=5) is True


def test_dominance_true_with_else_exit_form():
    """The symmetric ``if <call>: continue; else: return error()`` form
    also dominates: the else (failure) branch exits."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    if re.match(r'^x$', x):\n"              # line 3
        "        pass\n"
        "    else:\n"
        "        return error()\n"
        "    return open(x)\n"                       # line 7 = sink
    )
    assert sb.validator_dominates_sink(src, validator_line=3, sink_line=7) is True


def test_dominance_false_across_functions():
    """Validator in helper A doesn't dominate sink in helper B even
    when A's line number is smaller."""
    src = (
        "def helper_a(x):\n"
        "    if not re.match(r'^x$', x):\n"          # line 2 = validator in A
        "        return None\n"
        "    return x\n"
        "\n"
        "def helper_b(y):\n"
        "    return open(y)\n"                       # line 7 = sink in B
    )
    assert sb.validator_dominates_sink(src, validator_line=2, sink_line=7) is False


def test_dominance_false_on_syntax_error():
    """Unparseable source -> conservative False (Tier 0 declines)."""
    src = "def f(:\n    pass\n"
    assert sb.validator_dominates_sink(src, 1, 2) is False


def test_find_validator_line_locates_exact_source_line():
    src = (
        "a()\n"
        "b()\n"
        "if not re.match(r'^x$', n): pass\n"        # line 3
        "c()\n"
    )
    spec = sb.ValidatorSpec(
        "charset", "n", "x", "if not re.match(r'^x$', n): pass", 0)
    assert sb.find_validator_line(src, spec) == 3


def test_find_validator_line_none_when_absent():
    spec = sb.ValidatorSpec("charset", "n", "x", "if not re.match(r'^x$', n): pass", 0)
    assert sb.find_validator_line("a()\nb()\n", spec) is None


# ---------------------------------------------------------------------------
# SMT proof: regex-intersection emptiness.
# ---------------------------------------------------------------------------

def test_prove_unsat_for_whoogle_charset_vs_pathtrav():
    spec = sb.ValidatorSpec("charset", "name", "A-Za-z0-9_.+-", "+...", 0)
    v = sb.prove_neutralizes(spec, "pathtrav")
    assert v.sound is True
    assert v.counterexample is None
    assert "UNSAT" in v.reasoning


def test_prove_sat_for_weak_validator():
    """Charset that permits '/' MUST be declined, with '/' as the
    counterexample input."""
    spec = sb.ValidatorSpec("charset", "name", "A-Za-z0-9_./+-", "+...", 0)
    v = sb.prove_neutralizes(spec, "pathtrav")
    assert v.sound is False
    assert v.counterexample == "/"
    assert "SAT" in v.reasoning


def test_prove_sink_class_aware_whoogle_charset_vs_sqli():
    """The whoogle charset is sound for pathtrav (separators excluded) but
    NOT for sqli — the charset still allows '-'.  Demonstrates the danger
    model is sink-class-keyed, not validator-keyed."""
    spec = sb.ValidatorSpec("charset", "name", "A-Za-z0-9_.+-", "+...", 0)
    v_sqli = sb.prove_neutralizes(spec, "sqli")
    assert v_sqli.sound is False
    assert v_sqli.counterexample == "-"


def test_prove_unknown_sink_class_declines():
    spec = sb.ValidatorSpec("charset", "n", "A-Za-z", "+...", 0)
    v = sb.prove_neutralizes(spec, "no_such_class")
    assert v.sound is False
    assert "no danger model" in v.reasoning


# ---------------------------------------------------------------------------
# Substitution form: x = re.sub('[forbidden]+', '', x)
# ---------------------------------------------------------------------------

def test_extract_charset_sub_rebind():
    diff = "+    x = re.sub('[/\\\\]+', '', x)\n"
    spec = sb.extract_validator(diff)
    assert spec is not None
    assert spec.kind == "charset_sub"
    assert spec.var_name == "x"
    # `\\` in the pattern unescapes to `\`; `/` stays as-is.
    assert spec.forbidden == "/\\"


def test_extract_charset_sub_handles_escaped_quotes_in_pattern():
    """Regression for Bug B: the Gerapy CVE-2020-7698 fix uses
    ``'[\\!\\@\\#\\$\\;\\&\\*\\~\\"\\'\\{\\}\\]\\[\\-\\+\\%\\^]+'`` —
    the body has both ``\\"`` and ``\\'`` inside a single-quoted
    string.  Pre-fix the string-literal capture stopped at the first
    escaped quote and silently truncated the pattern → extractor
    returned None.  Must now extract correctly."""
    diff = (
        "+        project_name = re.sub("
        "'[\\!\\@\\#\\$\\;\\&\\*\\~\\\"\\'\\{\\}\\]\\[\\-\\+\\%\\^]+', "
        "'', project_name)\n"
    )
    spec = sb.extract_validator(diff, language="python")
    assert spec is not None, "Bug B regression: pattern with escaped quotes must extract"
    assert spec.kind == "charset_sub"
    assert spec.var_name == "project_name"
    # After unescape, the forbidden set should include all stripped chars
    assert "!" in spec.forbidden
    assert ";" in spec.forbidden       # in cmdi danger
    assert "$" in spec.forbidden       # in cmdi danger


def test_extract_charset_sub_unescapes_unnecessary_escapes():
    """Author over-escapes inside the char class (Gerapy-style); the
    unescape pass returns the true literal char set."""
    diff = "+    x = re.sub('[\\!\\@\\#\\$\\;]+', '', x)\n"
    spec = sb.extract_validator(diff)
    assert spec is not None
    assert spec.kind == "charset_sub"
    assert spec.forbidden == "!@#$;"


def test_extract_charset_sub_requires_same_var_rebind():
    """``safe = re.sub(..., '', x)`` (assigning to a DIFFERENT name) is
    NOT a same-variable rebind — we can't claim the original ``x`` is
    sanitized just because ``safe`` is. Extractor must skip."""
    diff = "+    safe = re.sub('[/]+', '', x)\n"
    assert sb.extract_validator(diff) is None


def test_extract_charset_sub_requires_empty_replacement():
    """Non-empty replacement could introduce different danger chars
    (`re.sub('[/]', '|', x)` replaces traversal with pipe — bad).
    Extractor only accepts the empty-string replacement."""
    diff = "+    x = re.sub('[/]+', '_', x)\n"
    assert sb.extract_validator(diff) is None


def test_prove_charset_sub_sound_when_danger_subset_of_forbidden():
    """Path-traversal danger is just ['/', '\\\\']. If the substitution
    strips both, every danger char is removed -> SOUND."""
    spec = sb.ValidatorSpec("charset_sub", "x", source_line="+...", forbidden="/\\")
    v = sb.prove_neutralizes(spec, "pathtrav")
    assert v.sound is True
    assert v.counterexample is None
    assert "set inclusion" in v.reasoning


def test_prove_charset_sub_declines_when_danger_char_survives():
    """Gerapy-class: substitution strips many shell metachars but misses
    `|` and backtick — declined with the surviving char as counterexample."""
    # Strips ; & $ but NOT | ` (which are danger chars for cmdi)
    spec = sb.ValidatorSpec("charset_sub", "x", source_line="+...", forbidden=";&$")
    v = sb.prove_neutralizes(spec, "cmdi")
    assert v.sound is False
    # `|` is the smallest-codepoint surviving danger char in our model.
    assert v.counterexample in {"|", "`", "\n"}


def test_substitution_dominance_clean_path():
    """``x = re.sub(...)`` at line 3, sink at line 4, no reassignment
    between them -> dominates."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    x = re.sub('[/]+', '', x)\n"      # line 3
        "    return open(x)\n"                  # line 4
    )
    assert sb.substitution_dominates_sink(src, 3, 4, "x") is True


def test_substitution_dominance_false_when_var_reassigned():
    """A later ``x = req()`` between the sub and the sink UNDOES
    sanitization -> dominance fails."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    x = re.sub('[/]+', '', x)\n"      # line 3 — sub
        "    x = req()\n"                       # line 4 — REASSIGN
        "    return open(x)\n"                  # line 5 — sink
    )
    assert sb.substitution_dominates_sink(src, 3, 5, "x") is False


def test_substitution_dominance_subscript_assignment_doesnt_invalidate():
    """``x[0] = ...`` is a MUTATION of contents, not a rebinding of
    ``x`` — must not invalidate dominance (still sound for the value
    that flows into the sink)."""
    src = (
        "def f():\n"
        "    x = req()\n"
        "    x = re.sub('[/]+', '', x)\n"      # line 3 — sub
        "    x[0] = 'A'\n"                      # line 4 — subscript mutation
        "    return open(x)\n"                  # line 5
    )
    assert sb.substitution_dominates_sink(src, 3, 5, "x") is True


def test_substitution_dominance_false_across_functions():
    src = (
        "def helper(x):\n"
        "    x = re.sub('[/]+', '', x)\n"      # line 2 — sub in helper
        "    return x\n"
        "\n"
        "def caller(y):\n"
        "    return open(y)\n"                  # line 6 — sink in caller
    )
    assert sb.substitution_dominates_sink(src, 2, 6, "x") is False


def test_try_tier0_sound_on_charset_sub_archetype(tmp_path: Path):
    """End-to-end: pure path-traversal substitution that strips both
    separators -> SOUND via Tier 0."""
    (tmp_path / "app.py").write_text(
        "def f():\n"                            # line 1
        "    x = req()\n"                       # line 2
        "    x = re.sub('[/\\\\]+', '', x)\n"   # line 3 — substitution
        "    return open(x)\n"                  # line 4 — sink
    )
    diff = (
        "@@ -1,3 +1,4 @@\n"
        " def f():\n"
        "     x = req()\n"
        "+    x = re.sub('[/\\\\]+', '', x)\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.SOUND
    assert r.artifact == "smt:charset_sub:[/\\]@app.py:3"
    assert "set inclusion" in r.reasoning


def test_try_tier0_declined_when_substitution_misses_danger(tmp_path: Path):
    """Gerapy-shape: strips ; & $ but misses | for cmdi -> DECLINED."""
    (tmp_path / "app.py").write_text(
        "def f():\n"
        "    cmd = req()\n"
        "    cmd = re.sub('[;&$]+', '', cmd)\n"
        "    return run(cmd)\n"
    )
    diff = (
        "@@ -1,3 +1,4 @@\n"
        " def f():\n"
        "     cmd = req()\n"
        "+    cmd = re.sub('[;&$]+', '', cmd)\n"
        "     return run(cmd)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="cmdi",
    )
    assert r.status is sb.Tier0Status.DECLINED
    assert r.counterexample in {"|", "`", "\n"}


# ---------------------------------------------------------------------------
# Multi-language guard-and-exit extractors (JS/TS/Java/Ruby).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line,expected_charset,expected_var", [
    ("+if (!/^[A-Za-z0-9_.+-]+$/.test(name)) return error();",
     "A-Za-z0-9_.+-", "name"),
    ("+    if (!/^[a-z0-9]+$/.test(slug)) throw new Error('bad');",
     "a-z0-9", "slug"),
    ("+if (!name.match(/^[A-Za-z0-9]+$/)) return error();",
     "A-Za-z0-9", "name"),
])
def test_extract_jsts_guard_and_exit(line, expected_charset, expected_var):
    diff = line + "\n"
    spec = sb.extract_validator(diff, language="javascript")
    assert spec is not None and spec.kind == "charset"
    assert spec.charset == expected_charset
    assert spec.var_name == expected_var
    # Same extractor handles typescript.
    assert sb.extract_validator(diff, language="typescript").charset == expected_charset


def test_extract_jsts_rejects_missing_exit():
    """Validator without guard-and-exit shape: skipped (we can't prove
    dominance from the diff alone)."""
    diff = "+const ok = /^[a-z]+$/.test(x);\n"
    assert sb.extract_validator(diff, language="javascript") is None


def test_extract_java_guard_and_exit():
    diff = '+if (!name.matches("^[A-Za-z0-9_.+-]+$")) return error();\n'
    spec = sb.extract_validator(diff, language="java")
    assert spec is not None and spec.kind == "charset"
    assert spec.charset == "A-Za-z0-9_.+-"
    assert spec.var_name == "name"


def test_extract_java_with_throw():
    diff = '+if (!slug.matches("^[a-z0-9]+$")) throw new IllegalArgumentException();\n'
    spec = sb.extract_validator(diff, language="java")
    assert spec is not None and spec.charset == "a-z0-9"


@pytest.mark.parametrize("line,expected_charset,expected_var", [
    ("+return error unless name =~ /^[A-Za-z0-9_.+-]+$/", "A-Za-z0-9_.+-", "name"),
    ("+raise ArgumentError unless slug =~ /^[a-z0-9]+$/", "a-z0-9", "slug"),
    ("+raise 'bad' if name !~ /^[A-Za-z0-9]+$/", "A-Za-z0-9", "name"),
])
def test_extract_ruby_guard_and_exit(line, expected_charset, expected_var):
    diff = line + "\n"
    spec = sb.extract_validator(diff, language="ruby")
    assert spec is not None and spec.kind == "charset"
    assert spec.charset == expected_charset
    assert spec.var_name == expected_var


# ---------------------------------------------------------------------------
# Adversarial-review regressions — bugs caught before the long corpus run.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("metachar", [r"\d", r"\D", r"\w", r"\W", r"\s", r"\S"])
def test_extract_rejects_regex_shorthand_classes(metachar):
    """Bug 1 (UNSOUND): silently misreading `\\W` as literal chars
    `{\\, W}` lets the SMT check claim SOUND for a validator that
    accepts danger chars (`\\W` includes `/`, `\\`).  Must reject."""
    diff = f"+if not re.match(r'^[{metachar}]+$', x):\n+    return error()\n"
    assert sb.extract_validator(diff, language="python") is None


def test_extract_rejects_regex_shorthand_classes_in_charset_sub():
    diff = r"+    x = re.sub('[\W]+', '', x)" + "\n"
    assert sb.extract_validator(diff, language="python") is None


def test_extract_rejects_negated_class():
    """Bug 2 (UNSOUND): `[^a-z]+` accepts any non-lowercase char
    including `/`; misreading `^` as literal would claim SOUND for
    pathtrav.  Reject negated classes."""
    diff = "+if not re.match(r'^[^a-z]+$', x):\n+    return error()\n"
    assert sb.extract_validator(diff, language="python") is None


def test_extract_rejects_negated_class_in_js():
    diff = "+if (!/^[^a-z]+$/.test(x)) return error();\n"
    assert sb.extract_validator(diff, language="javascript") is None


def test_extract_rejects_negated_class_in_java():
    diff = '+if (!x.matches("^[^a-z]+$")) return;\n'
    assert sb.extract_validator(diff, language="java") is None


def test_variable_reassigned_detects_for_loop():
    """Bug 3 (UNSOUND): `for x in items:` rebinds x to iter values.
    Missing this would let dominance falsely succeed when the post-sub
    x is overwritten by the loop."""
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    for x in items:\n"
        "        sink(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 4) is True


def test_variable_reassigned_detects_with_as():
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    with open('p') as x:\n"
        "        sink(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 4) is True


def test_variable_reassigned_detects_tuple_unpacking():
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    x, y = pair\n"
        "    return open(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 4) is True


def test_variable_reassigned_detects_walrus():
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    foo((x := req()))\n"
        "    return open(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 4) is True


def test_variable_reassigned_subscript_assignment_does_not_trigger():
    """`x[0] = y` mutates contents but does NOT rebind `x` itself —
    must NOT flag as reassignment."""
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    x[0] = 'A'\n"
        "    return open(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 4) is False


@pytest.mark.parametrize("lang,boundary_line", [
    ("javascript", "function helper() {"),
    ("javascript", "const helper = (x) => {"),
    ("java",       "public void helper() {"),
    ("ruby",       "  def helper"),
])
def test_crosses_function_boundary_detects_per_language(lang, boundary_line):
    """Bug 4 (UNSOUND): validator in helper A + sink in helper B (same
    file) — without function-boundary detection, source-order alone
    falsely dominates.  Reject."""
    src = (
        "function user_facing() {\n"
        "  if (!/^[a-z]+$/.test(name)) return error();\n"   # line 2
        f"  {boundary_line}\n"                              # line 3 = boundary
        "    do_something();\n"
        "  }\n"
        "  return danger_sink(other);\n"                    # line 6 = sink
        "}\n"
    )
    assert sb._crosses_function_boundary(src, 2, 6, lang) is True


def test_crosses_function_boundary_js_ignores_if_statement():
    """Bug 7: `if (x) {` superficially looks like a JS method header
    (`name(args) {`); must NOT be treated as a function boundary."""
    src = (
        "function f() {\n"
        "  if (!/^[a-z]+$/.test(name)) return error();\n"
        "  if (other_cond) {\n"                # NOT a function boundary
        "    do_thing();\n"
        "  }\n"
        "  return danger_sink(name);\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src, 2, 6, "javascript") is False


def test_crosses_function_boundary_java_detects_package_private():
    """Bug 8: package-private method (no public/private modifier) must
    still be detected as a function boundary so cross-method dominance
    can't false-positive."""
    src = (
        "void user_facing(String x) {\n"
        '    if (!x.matches("^[a-z]+$")) return;\n'
        "}\n"
        "String helper(String y) {\n"          # package-private method
        "    return danger_sink(y);\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src, 2, 5, "java") is True


def test_crosses_function_boundary_java_ignores_if_with_type_prefix():
    """A `Type name = expr;` declaration shouldn't match a method
    header — needs an argument list `(...)` after the name."""
    src = (
        "void m() {\n"
        '    if (!x.matches("^[a-z]+$")) return;\n'
        "    String tmp = x + '!';\n"          # variable decl, NOT a method
        "    int count = 0;\n"
        "    return sink(tmp);\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src, 2, 5, "java") is False


def test_crosses_function_boundary_ruby_detects_self_dot():
    """Ruby class methods are declared `def self.name` — must be
    detected as a function boundary."""
    src = (
        "def user_facing(name)\n"
        "  raise unless name =~ /^[a-z]+$/\n"
        "end\n"
        "\n"
        "def self.helper(y)\n"                  # class method
        "  sink(y)\n"
        "end\n"
    )
    assert sb._crosses_function_boundary(src, 2, 6, "ruby") is True


def test_crosses_function_boundary_returns_false_when_no_boundary():
    src = (
        "function user_facing() {\n"
        "  if (!/^[a-z]+$/.test(name)) return error();\n"
        "  const tmp = name + '!';\n"
        "  return danger_sink(tmp);\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src, 2, 4, "javascript") is False


def test_try_tier0_declined_when_js_crosses_function_boundary(tmp_path: Path):
    """End-to-end: JS validator in one helper, sink in another. Tier 0
    must DECLINE because the validator's `return` exits the wrong
    function."""
    (tmp_path / "app.js").write_text(
        "function helper_a(name) {\n"                                       # line 1
        "  if (!/^[A-Za-z0-9]+$/.test(name)) return null;\n"                # line 2
        "  return name;\n"                                                  # line 3
        "}\n"                                                               # line 4
        "function helper_b(other) {\n"                                      # line 5
        "  return fs.readFile(other);\n"                                    # line 6 = sink
        "}\n"
    )
    diff = (
        "@@ -1,5 +1,6 @@\n"
        " function helper_a(name) {\n"
        "+  if (!/^[A-Za-z0-9]+$/.test(name)) return null;\n"
        "   return name;\n"
        " }\n"
        " function helper_b(other) {\n"
        "   return fs.readFile(other);\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=6, sink_class="pathtrav",
        language="javascript",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "function boundary" in r.reasoning


def test_try_tier0_not_applicable_when_validator_var_not_at_sink(tmp_path: Path):
    """Bug 15 (UNSOUND): fix adds a validator for `x` and a sink for `y`
    in the same function. Tier 0 must NOT apply the validator's
    constraint to the sink's value — the validated variable must
    actually appear at the sink line."""
    (tmp_path / "app.py").write_text(
        "def f(x, y):\n"                                                # line 1
        '    if not re.match(r"^[A-Za-z0-9]+$", x):\n'                  # line 2
        "        return error()\n"                                       # line 3
        "    do_something_with(x)\n"                                     # line 4
        "    return open(y)\n"                                           # line 5 = sink for y, not x
    )
    diff = (
        "@@ -1,3 +1,5 @@\n"
        " def f(x, y):\n"
        '+    if not re.match(r"^[A-Za-z0-9]+$", x):\n'
        "+        return error()\n"
        "     do_something_with(x)\n"
        "     return open(y)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in r.reasoning


def test_try_tier0_sound_when_validated_var_threads_through_assignment(tmp_path: Path):
    """Whoogle-shape: validated ``name`` flows through
    ``cfg = os.path.join(BASE, name)`` to the sink ``open(cfg)``.
    Chain tracking must accept this (the validator's constraint applies
    to ``cfg`` via ``name``).  Pre-fix the literal var-at-sink check
    rejected this — the most common real-world Tier 0 case."""
    (tmp_path / "app.py").write_text(
        "def f(name):\n"                                                # line 1
        '    if not re.match(r"^[A-Za-z0-9_.+-]+$", name):\n'           # line 2
        "        return error()\n"                                       # line 3
        "    cfg = os.path.join(BASE, name)\n"                           # line 4 — derive cfg from name
        "    return open(cfg)\n"                                         # line 5 = sink, references cfg
    )
    diff = (
        "@@ -1,3 +1,5 @@\n"
        " def f(name):\n"
        '+    if not re.match(r"^[A-Za-z0-9_.+-]+$", name):\n'
        "+        return error()\n"
        "     cfg = os.path.join(BASE, name)\n"
        "     return open(cfg)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.SOUND
    assert "UNSAT" in r.reasoning


def test_chain_grows_through_multi_step_assignment():
    """Chain tracking must follow multi-step derivations:
    ``name -> cfg -> safe_path -> open(safe_path)``."""
    import ast as _ast_mod
    tree = _ast_mod.parse(
        "def f(name):\n"
        '    if not re.match(r"^[a-z]+$", name): return\n'
        "    cfg = os.path.join(BASE, name)\n"           # cfg derived from name
        "    safe_path = cfg + '.cfg'\n"                  # safe_path derived from cfg
        "    return open(safe_path)\n"                    # sink uses safe_path
    )
    assert sb._python_chain_reaches_sink(
        tree, "name", 2, 5, "    return open(safe_path)",
    ) is True


def test_chain_does_not_grow_through_unrelated_assignment():
    """Bug 15 still caught: validator constrains ``x``, sink uses
    unrelated ``y``. ``x`` is referenced between but never feeds ``y``."""
    import ast as _ast_mod
    tree = _ast_mod.parse(
        "def f(x, y):\n"
        '    if not re.match(r"^[a-z]+$", x): return\n'
        "    do_something_with(x)\n"                       # x USED but not assigned
        "    return open(y)\n"                              # sink uses y, unrelated to x
    )
    assert sb._python_chain_reaches_sink(
        tree, "x", 2, 4, "    return open(y)",
    ) is False


def test_try_tier0_variable_match_uses_word_boundary(tmp_path: Path):
    """Word-boundary match: validator's `name` must not falsely match
    `surname` at the sink line."""
    (tmp_path / "app.py").write_text(
        "def f(name, surname):\n"                                       # line 1
        '    if not re.match(r"^[A-Za-z0-9]+$", name):\n'               # line 2
        "        return error()\n"                                       # line 3
        "    return open(surname)\n"                                     # line 4 = sink for surname
    )
    diff = (
        "@@ -1,2 +1,4 @@\n"
        " def f(name, surname):\n"
        '+    if not re.match(r"^[A-Za-z0-9]+$", name):\n'
        "+        return error()\n"
        "     return open(surname)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in r.reasoning


def test_crosses_function_boundary_ts_class_method_with_public_modifier():
    """Bug 16: TypeScript class methods use public/private/protected
    modifiers; my JS pattern (which TS dispatches to) must detect
    these as method declarations."""
    src = (
        "class C {\n"
        "  user_facing(name: string) {\n"
        "    if (!/^[a-z]+$/.test(name)) return;\n"
        "  }\n"
        "  public helper(other: string) {\n"          # TS modifier
        "    return danger_sink(other);\n"
        "  }\n"
        "}\n"
    )
    # Validator at line 3, sink at line 6, public method header at line 5
    assert sb._crosses_function_boundary(src, 3, 6, "javascript") is True


def test_crosses_function_boundary_js_detects_generator_function():
    """Bug 18: generator functions (`function* name` / `*method`) must
    be detected as function boundaries."""
    src1 = (
        "function user_facing() {\n"
        "  if (!/^[a-z]+$/.test(name)) return;\n"
        "}\n"
        "function* helper() {\n"                        # generator
        "  yield danger_sink(name);\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src1, 2, 5, "javascript") is True
    src2 = (
        "class C {\n"
        "  user_facing() {\n"
        "    if (!/^[a-z]+$/.test(name)) return;\n"
        "  }\n"
        "  *helper() {\n"                                # generator method
        "    yield danger_sink(name);\n"
        "  }\n"
        "}\n"
    )
    assert sb._crosses_function_boundary(src2, 3, 6, "javascript") is True


def test_validator_block_in_try_with_bare_except_declines(tmp_path: Path):
    """Bug 19: validator's `raise` inside try/except: bare catch lets
    the raise be swallowed → value reaches sink unvalidated → must
    NOT claim dominance."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"                                                  # line 1
        "    try:\n"                                                   # line 2
        '        if not re.match(r"^[A-Za-z0-9]+$", x):\n'             # line 3
        "            raise ValueError\n"                               # line 4
        "    except:\n"                                                # line 5 — bare catches everything
        "        pass\n"                                               # line 6 — raise SWALLOWED
        "    return open(x)\n"                                         # line 7 — sink, x unvalidated
    )
    diff = (
        "@@ -1,3 +1,7 @@\n"
        " def f(x):\n"
        "+    try:\n"
        '+        if not re.match(r"^[A-Za-z0-9]+$", x):\n'
        "+            raise ValueError\n"
        "+    except:\n"
        "+        pass\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not dominate" in r.reasoning


def test_validator_block_in_try_with_exception_catch_declines(tmp_path: Path):
    """Same bug but with `except Exception:` — also catches everything
    the validator raises."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"
        "    try:\n"
        '        if not re.match(r"^[A-Za-z0-9]+$", x):\n'
        "            raise ValueError\n"
        "    except Exception:\n"                                      # catches ValueError
        "        pass\n"
        "    return open(x)\n"
    )
    diff = (
        "@@ -1,3 +1,7 @@\n"
        " def f(x):\n"
        "+    try:\n"
        '+        if not re.match(r"^[A-Za-z0-9]+$", x):\n'
        "+            raise ValueError\n"
        "+    except Exception:\n"
        "+        pass\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE


def test_validator_block_with_specific_except_class_still_dominates(tmp_path: Path):
    """``except OSError:`` doesn't catch the ValueError raised by the
    validator — dominance still holds."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"
        "    try:\n"
        '        if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "            raise ValueError\n"
        "    except OSError:\n"                                        # different exception class
        "        pass\n"
        "    return open(x)\n"
    )
    diff = (
        "@@ -1,3 +1,7 @@\n"
        " def f(x):\n"
        "+    try:\n"
        '+        if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "+            raise ValueError\n"
        "+    except OSError:\n"
        "+        pass\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.SOUND


def test_validator_with_return_inside_try_still_dominates(tmp_path: Path):
    """Return is NOT catchable — even ``except:`` doesn't intercept it.
    Dominance still holds when the failure branch uses ``return``."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"
        "    try:\n"
        '        if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "            return error()\n"                                 # return, not raise
        "    except Exception:\n"
        "        pass\n"
        "    return open(x)\n"
    )
    diff = (
        "@@ -1,3 +1,7 @@\n"
        " def f(x):\n"
        "+    try:\n"
        '+        if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "+            return error()\n"
        "+    except Exception:\n"
        "+        pass\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.SOUND


def test_variable_reassigned_detects_except_as():
    """Bug 20: ``except SomeError as x:`` binds x to the exception
    during the handler body — x is no longer the sanitized value."""
    tree = __import__("ast").parse(
        "def f():\n"
        "    x = re.sub('[/]+', '', x)\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as x:\n"
        "        pass\n"
        "    return open(x)\n"
    )
    assert sb._variable_reassigned_between(tree, "x", 2, 7) is True


def test_re_sub_extractor_rejects_whitespace_replacement():
    """Bug 5 (cleanliness): `' '` replacement is not truly empty.
    Tighten the extractor to reject."""
    diff = "+    x = re.sub('[/]+', ' ', x)\n"
    assert sb.extract_validator(diff, language="python") is None


def test_java_matches_without_anchors_still_extracts():
    """Bug 6: Java's `String.matches` is fullmatch by default; explicit
    `^...$` anchors are redundant. Patterns without anchors must still
    extract (and validate as sound)."""
    diff = '+if (!name.matches("[A-Za-z0-9_.+-]+")) throw new Error();\n'
    spec = sb.extract_validator(diff, language="java")
    assert spec is not None and spec.kind == "charset"
    assert spec.charset == "A-Za-z0-9_.+-"


def test_extract_unknown_language_returns_none():
    """Languages with no extractor configured -> Tier 0 declines cleanly."""
    diff = "+if (!/^[a-z]+$/.test(x)) return error();\n"
    assert sb.extract_validator(diff, language="rust") is None
    assert sb.extract_validator(diff, language="cobol") is None


def test_try_tier0_sound_on_js_archetype(tmp_path: Path):
    """End-to-end JS: guard-and-exit + path-traversal sink -> SOUND."""
    (tmp_path / "app.js").write_text(
        "function get_config(name) {\n"                                    # line 1
        "  if (!/^[A-Za-z0-9_.+-]+$/.test(name)) return error();\n"        # line 2
        "  return fs.readFile(path.join(BASE, name));\n"                   # line 3
        "}\n"
    )
    diff = (
        "@@ -1,2 +1,3 @@\n"
        " function get_config(name) {\n"
        "+  if (!/^[A-Za-z0-9_.+-]+$/.test(name)) return error();\n"
        "   return fs.readFile(path.join(BASE, name));\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="pathtrav",
        language="javascript",
    )
    assert r.status is sb.Tier0Status.SOUND
    assert "UNSAT" in r.reasoning


def test_try_tier0_sound_on_java_archetype(tmp_path: Path):
    (tmp_path / "App.java").write_text(
        "void load(String name) {\n"                                                       # line 1
        '    if (!name.matches("^[A-Za-z0-9_.+-]+$")) throw new IllegalArgumentException();\n'  # line 2
        "    Files.readAllBytes(Paths.get(BASE, name));\n"                                 # line 3
        "}\n"
    )
    diff = (
        "@@ -1,2 +1,3 @@\n"
        " void load(String name) {\n"
        '+    if (!name.matches("^[A-Za-z0-9_.+-]+$")) throw new IllegalArgumentException();\n'
        "     Files.readAllBytes(Paths.get(BASE, name));\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="App.java", sink_line=3, sink_class="pathtrav",
        language="java",
    )
    assert r.status is sb.Tier0Status.SOUND


def test_try_tier0_sound_on_ruby_archetype(tmp_path: Path):
    (tmp_path / "app.rb").write_text(
        "def get_config(name)\n"                                          # line 1
        "  raise ArgumentError unless name =~ /^[A-Za-z0-9_.+-]+$/\n"     # line 2
        "  File.open(File.join(BASE, name))\n"                            # line 3
        "end\n"
    )
    diff = (
        "@@ -1,2 +1,3 @@\n"
        " def get_config(name)\n"
        "+  raise ArgumentError unless name =~ /^[A-Za-z0-9_.+-]+$/\n"
        "   File.open(File.join(BASE, name))\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.rb", sink_line=3, sink_class="pathtrav",
        language="ruby",
    )
    assert r.status is sb.Tier0Status.SOUND


def test_try_tier0_not_applicable_when_substitution_var_reassigned(tmp_path: Path):
    """Substitution would be sound on its own, but a later reassignment
    undoes it -> Tier 0 must DECLINE the suppression."""
    (tmp_path / "app.py").write_text(
        "def f():\n"
        "    x = req()\n"
        "    x = re.sub('[/\\\\]+', '', x)\n"   # line 3 — sub
        "    x = req()\n"                       # line 4 — REASSIGNED
        "    return open(x)\n"                  # line 5 — sink
    )
    diff = (
        "@@ -1,4 +1,5 @@\n"
        " def f():\n"
        "     x = req()\n"
        "+    x = re.sub('[/\\\\]+', '', x)\n"
        "     x = req()\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
    )
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "reassigned" in r.reasoning


# ---------------------------------------------------------------------------
# Full orchestrator.
# ---------------------------------------------------------------------------

_WHOOGLE_DIFF = (
    "@@ -1,4 +1,6 @@\n"
    " def get_config():\n"
    "     name = os.path.normpath(request.args.get('name'))\n"
    '+    if not re.match(r"^[A-Za-z0-9_.+-]+$", name):\n'
    "+        return error()\n"
    "     return open(os.path.join(CONFIG_PATH, name))\n"
)


def _write_post_fix_repo(tmp_path: Path) -> Path:
    """Materialise the whoogle archetype: validator before sink, in the
    same function, with an exit-on-fail body."""
    src = tmp_path / "app" / "routes.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "def get_config():\n"                                                  # line 1
        "    name = os.path.normpath(request.args.get('name'))\n"              # line 2
        '    if not re.match(r"^[A-Za-z0-9_.+-]+$", name):\n'                  # line 3
        "        return error()\n"                                             # line 4
        "    return open(os.path.join(CONFIG_PATH, name))\n"                   # line 5
    )
    return tmp_path


def test_try_tier0_sound_on_whoogle_archetype(tmp_path: Path):
    """End-to-end: validator extracted, dominance proven via AST source-
    order + exit-on-fail, Z3 proves the language intersection empty."""
    repo = _write_post_fix_repo(tmp_path)
    r = sb.try_tier0(
        fix_diff=_WHOOGLE_DIFF, repo_root=repo,
        sink_uri="app/routes.py", sink_line=5, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.SOUND
    assert r.artifact == "smt:charset:[A-Za-z0-9_.+-]+@app/routes.py:3"
    assert r.extras == {"validator_line": 3, "var_name": "name"}
    assert "UNSAT" in r.reasoning


def test_try_tier0_declined_when_validator_allows_danger(tmp_path: Path):
    """Weak validator (permits '/') -> DECLINED with counterexample."""
    (tmp_path / "app.py").write_text(
        "def f():\n"                                                      # line 1
        "    x = req()\n"                                                 # line 2
        '    if not re.match(r"^[A-Za-z./]+$", x):\n'                     # line 3
        "        return error()\n"                                        # line 4
        "    return open(x)\n"                                            # line 5
    )
    diff = (
        "@@ -1,3 +1,5 @@\n"
        " def f():\n"
        "     x = req()\n"
        '+    if not re.match(r"^[A-Za-z./]+$", x):\n'
        "+        return error()\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.DECLINED
    assert r.counterexample == "/"


def test_try_tier0_not_applicable_when_no_validator(tmp_path: Path):
    r = sb.try_tier0(
        fix_diff="+x = 1\n+y = 2\n", repo_root=tmp_path,
        sink_uri="a.py", sink_line=1, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no recognised" in r.reasoning


def test_try_tier0_not_applicable_when_validator_block_doesnt_exit(tmp_path: Path):
    """Validator's ``if not X:`` body just logs — value reaches sink
    unsanitized -> Tier 0 must decline."""
    (tmp_path / "app.py").write_text(
        "def f():\n"
        "    x = req()\n"
        '    if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "        print('bad')\n"                                          # NO return
        "    return open(x)\n"
    )
    diff = (
        "@@ -1,3 +1,5 @@\n"
        " def f():\n"
        "     x = req()\n"
        '+    if not re.match(r"^[A-Za-z0-9_.+-]+$", x):\n'
        "+        print('bad')\n"
        "     return open(x)\n"
    )
    r = sb.try_tier0(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not dominate" in r.reasoning


def test_try_tier0_not_applicable_when_validator_not_in_post_fix_source(
        tmp_path: Path):
    """Diff claims to add the validator, but the post-fix file doesn't
    contain it (mismatched diff context).  Must NOT crash and must fall
    through cleanly."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "routes.py").write_text("just a stub\n")
    r = sb.try_tier0(
        fix_diff=_WHOOGLE_DIFF, repo_root=tmp_path,
        sink_uri="app/routes.py", sink_line=10, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "not findable" in r.reasoning


def test_try_tier0_not_applicable_when_source_file_missing(tmp_path: Path):
    """No post-fix source file at all -> clean fall-through."""
    r = sb.try_tier0(
        fix_diff=_WHOOGLE_DIFF, repo_root=tmp_path,
        sink_uri="missing/path.py", sink_line=5, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.NOT_APPLICABLE
    assert "not readable" in r.reasoning


def test_try_tier0_z3_unavailable_degrades(monkeypatch, tmp_path: Path):
    """Substrate reports z3 not installed -> Z3_UNAVAILABLE without
    touching z3 (matches smt_path_validator's degradation pattern)."""
    monkeypatch.setattr(sb, "_z3_available", lambda: False)
    r = sb.try_tier0(
        fix_diff=_WHOOGLE_DIFF, repo_root=tmp_path,
        sink_uri="app/routes.py", sink_line=5, sink_class="pathtrav")
    assert r.status is sb.Tier0Status.Z3_UNAVAILABLE
    assert "z3 not installed" in r.reasoning


@pytest.mark.parametrize("sink_class,charset,expect_sound", [
    ("pathtrav", "A-Za-z0-9_.+-", True),   # whoogle archetype
    ("cmdi",     "A-Za-z0-9_.-",  True),   # excludes shell metachars
    ("pathtrav", "A-Za-z0-9_./",  False),  # permits '/'
    ("cmdi",     "A-Za-z0-9; ",   False),  # permits ';'
])
def test_prove_table_per_sink_class(sink_class, charset, expect_sound):
    spec = sb.ValidatorSpec("charset", "x", charset, "+...", 0)
    v = sb.prove_neutralizes(spec, sink_class)
    assert v.sound is expect_sound
