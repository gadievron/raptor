"""Chain extraction: the as-written property and the refusal rules.

Hermetic (regex/lexer only — no interpreter). Positive cases pin the
re-emitted step templates byte-for-byte where load-bearing; every
refusal rule has a direct trigger.
"""

from __future__ import annotations

import pytest

from core.audit.sanwit._extract import (
    ALLOWED_STEP_CALLABLES,
    ChainExtraction,
    ExtractionRefusal,
    extract_chain,
)


def _ok(src: str, names=("htmlspecialchars", "escapeshellarg",
                         "escapeshellcmd")) -> ChainExtraction:
    result = extract_chain(src, tuple(names))
    assert isinstance(result, ChainExtraction), result
    return result


def _refused(src: str, names=("htmlspecialchars", "escapeshellarg",
                              "escapeshellcmd")) -> ExtractionRefusal:
    result = extract_chain(src, tuple(names))
    assert isinstance(result, ExtractionRefusal), result
    return result


class TestPositiveChains:
    def test_single_step_with_flags(self):
        r = _ok(
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_COMPAT);\n"
            "    echo \"<a title='$v'>\";\n"
            "}"
        )
        assert [s.template() for s in r.steps] == [
            "htmlspecialchars({DATA},ENT_COMPAT)",
        ]
        assert r.subject_var == "x"
        assert r.final_var == "v"

    def test_nested_and_sequential_steps_in_order(self):
        r = _ok(
            "function m($x) {\n"
            "    $v = str_replace(\"'\", \"\", "
            "htmlspecialchars($x, ENT_QUOTES));\n"
            "    $v = trim($v);\n"
            "    echo $v;\n"
            "}"
        )
        assert [s.callable_name for s in r.steps] == [
            "htmlspecialchars", "str_replace", "trim",
        ]
        # Literal lexemes survive re-emission verbatim.
        assert r.steps[1].template() == "str_replace(\"'\",\"\",{DATA})"

    def test_inline_assembly_anchor(self):
        r = _ok(
            "function g($x) {\n"
            '    $cmd = "prog " . escapeshellcmd($x) . " -v";\n'
            "    system($cmd);\n"
            "}"
        )
        assert [s.callable_name for s in r.steps] == ["escapeshellcmd"]
        assert r.final_var == "cmd"

    def test_alias_is_followed(self):
        r = _ok(
            "function r($x) {\n"
            "    $v = htmlspecialchars($x);\n"
            "    $w = $v;\n"
            "    $w = trim($w);\n"
            "    echo $w;\n"
            "}"
        )
        assert [s.callable_name for s in r.steps] == [
            "htmlspecialchars", "trim",
        ]
        assert r.final_var == "w"

    def test_comments_are_ignored(self):
        r = _ok(
            "function t($x) {\n"
            "    // $v = escapeshellcmd($x); disabled\n"
            "    $v = escapeshellarg($x); /* good */\n"
            "    system($v);\n"
            "}"
        )
        assert [s.callable_name for s in r.steps] == ["escapeshellarg"]

    def test_bare_body_without_function_header(self):
        r = _ok(
            "$v = escapeshellarg($x);\nsystem($v);\n",
        )
        assert [s.callable_name for s in r.steps] == ["escapeshellarg"]

    def test_array_literal_argument(self):
        r = _ok(
            "function u($x) {\n"
            "    $v = str_replace(array('a', 'b'), '', "
            "htmlspecialchars($x));\n"
            "    echo $v;\n"
            "}"
        )
        assert [s.callable_name for s in r.steps] == [
            "htmlspecialchars", "str_replace",
        ]


class TestRefusals:
    def test_no_application(self):
        r = _refused("function f($x) { echo $x; }")
        assert "no application" in r.reason

    def test_conditional_application(self):
        r = _refused(
            "function h($x) {\n"
            "    if ($x) { $v = escapeshellarg($x); }\n"
            "    system($v);\n"
            "}"
        )
        assert "conditional" in r.reason

    def test_conditional_application_with_preceding_stmt_in_block(self):
        # The anchor is a bare assignment but still sits inside the
        # if-block — brace depth, not statement shape, must catch it.
        r = _refused(
            "function h($x) {\n"
            "    if ($x) {\n"
            "        $t = 1;\n"
            "        $v = escapeshellarg($x);\n"
            "    }\n"
            "    system($v);\n"
            "}"
        )
        assert "conditional" in r.reason

    def test_ternary_application(self):
        r = _refused(
            "function p($x) {\n"
            "    $v = $x ? escapeshellarg($x) : $x;\n"
            "    system($v);\n"
            "}"
        )
        assert "outside the step grammar" in r.reason

    def test_chain_continues_past_intervening_use(self):
        r = _refused(
            "function k($x) {\n"
            "    $v = escapeshellcmd($x);\n"
            "    log_it($v);\n"
            "    $v = escapeshellarg($v);\n"
            "    system($v);\n"
            "}"
        )
        assert "after an intervening boundary" in r.reason

    def test_conditional_resanitization_after_chain(self):
        r = _refused(
            "function k($x) {\n"
            "    $v = escapeshellcmd($x);\n"
            "    if ($strict) { $v = escapeshellarg($v); }\n"
            "    system($v);\n"
            "}"
        )
        assert "after an intervening boundary" in r.reason

    def test_compound_assignment_after_chain(self):
        r = _refused(
            "function o($x) {\n"
            "    $v = escapeshellarg($x);\n"
            "    $v .= '.log';\n"
            "    system($v);\n"
            "}"
        )
        assert "after an intervening boundary" in r.reason

    def test_sink_assembly_is_not_a_refusal(self):
        # Concatenating the SANITIZED value into another variable is
        # the normal sink hand-off, not chain continuation.
        r = _ok(
            "function n($x) {\n"
            "    $v = escapeshellarg($x);\n"
            '    $cmd = "prog $v";\n'
            "    system($cmd);\n"
            "}"
        )
        assert r.final_var == "v"

    def test_non_allowlisted_transform(self):
        r = _refused(
            "function w($x) {\n"
            "    $v = my_clean(escapeshellarg($x));\n"
            "    system($v);\n"
            "}"
        )
        assert "not an allowlisted" in r.reason

    def test_variable_second_argument(self):
        r = _refused(
            "function v($x) {\n"
            "    $v = str_replace($bad, '', htmlspecialchars($x));\n"
            "    echo $v;\n"
            "}"
        )
        assert "variable references" in r.reason

    def test_interpolated_double_quoted_argument(self):
        r = _refused(
            "function y($x) {\n"
            '    $v = str_replace("$sep", "", htmlspecialchars($x));\n'
            "    echo $v;\n"
            "}"
        )
        assert "'$'" in r.reason

    def test_dollar_in_double_quotes_refused_outright(self):
        """The blanket rule: ANY '$' in a double-quoted literal
        refuses — escape parity is deliberately not modeled."""
        # Even backslash run before ${...}: PHP sees an escaped
        # backslash followed by LIVE ${} interpolation; a parity-
        # naive lookbehind admitted it (the probe-escape shape).
        r = _refused(
            "function run($input) {\n"
            "    $clean = str_replace(\"\\\\${system('id')}\", \"\", "
            "escapeshellcmd($input));\n"
            "    system(\"prog \" . $clean);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "'$'" in r.reason
        # ${expr} arbitrary-expression form (the forged-verdict
        # chain rode this: read own source, exfiltrate the token,
        # print an authenticated forged document).
        r = _refused(
            "function render($input) {\n"
            '    $clean = str_replace("\\\\${exit(print(1))}", "", '
            "escapeshellcmd($input));\n"
            '    system("prog " . $clean);\n'
            "}",
            names=("escapeshellcmd",),
        )
        assert "'$'" in r.reason
        # Plain scope interpolation: "$x" would read the PROBE's own
        # data variable, not target state.
        r = _refused(
            "function f($x) {\n"
            '    $v = str_replace("\\\\$x", "", htmlspecialchars($x));\n'
            "    echo $v;\n"
            "}",
        )
        assert "'$'" in r.reason
        # Escaped-dollar spelling ("\\$sep" — inert in PHP) refuses
        # too: the rule is blanket by design.
        r = _refused(
            "function g($x) {\n"
            '    $v = str_replace("\\$sep", "", htmlspecialchars($x));\n'
            "    echo $v;\n"
            "}",
        )
        assert "'$'" in r.reason

    def test_dollar_in_array_and_assembly_literals_refused(self):
        r = _refused(
            "function u($x) {\n"
            "    $v = str_replace(array(\"\\\\${'a'}\"), '', "
            "htmlspecialchars($x));\n"
            "    echo $v;\n"
            "}",
        )
        assert "'$'" in r.reason
        r = _refused(
            "function w($x) {\n"
            '    $cmd = "pre${1}fix" . escapeshellcmd($x);\n'
            "    system($cmd);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "'$'" in r.reason

    def test_carrier_divergence_via_alias_refuses(self):
        # The chain moved to $b (and strengthened/weakened there)
        # while the sink still consumes $a — attributing the $b chain
        # to the $a sink would mint a wrong verdict.
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    $b = $a;\n"
            "    $b = stripslashes($b);\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "diverge" in r.reason

    def test_carrier_divergence_via_new_var_transform_refuses(self):
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    $b = escapeshellarg($a);\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "diverge" in r.reason

    def test_dead_old_carrier_still_follows(self):
        r = _ok(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    $b = $a;\n"
            "    $b = escapeshellarg($b);\n"
            "    system($b);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert [s.callable_name for s in r.steps] == [
            "escapeshellcmd", "escapeshellarg",
        ]

    def test_embedded_reassignment_after_boundary_refuses(self):
        # `$z = $a = f($a);` reassigns $a mid-expression — a
        # statement-start anchor missed it and hid the strengthening
        # transform.
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    log_it($a);\n"
            "    $z = $a = my_clean($a);\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "after an intervening boundary" in r.reason

    def test_braceless_control_body_reassignment_refuses(self):
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    log_it($a);\n"
            "    if ($m) $a = my_clean($a);\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "after an intervening boundary" in r.reason

    def test_destructuring_reassignment_after_boundary_refuses(self):
        # list($a, $b) = ... and [$a, $b] = ... re-bind the chain
        # variable without a direct `$a =` shape.
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    log_it($a);\n"
            "    list($a, $b) = parse_pair();\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "after an intervening boundary" in r.reason
        r = _refused(
            "function d($x) {\n"
            "    $a = escapeshellcmd($x);\n"
            "    log_it($a);\n"
            "    [$a, $b] = parse_pair();\n"
            "    system($a);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert "after an intervening boundary" in r.reason

    def test_index_write_keyed_by_chain_var_is_not_a_reassignment(self):
        # $cache[$a] = ... WRITES an array slot keyed by $a; it does
        # not re-bind $a (unlike destructuring, where `[` starts the
        # statement's assignment target).
        r = _ok(
            "function d($x) {\n"
            "    $a = escapeshellarg($x);\n"
            "    log_it($a);\n"
            "    $cache[$a] = 1;\n"
            "    system($a);\n"
            "}",
            names=("escapeshellarg",),
        )
        assert [s.callable_name for s in r.steps] == ["escapeshellarg"]

    def test_reassignment_text_inside_string_literal_is_inert(self):
        # '$a =' inside a string literal is data, not a reassignment.
        r = _ok(
            "function d($x) {\n"
            "    $a = escapeshellarg($x);\n"
            "    log_msg('note: $a = command argument');\n"
            "    system($a);\n"
            "}",
            names=("escapeshellarg",),
        )
        assert [s.callable_name for s in r.steps] == ["escapeshellarg"]

    def test_nul_bearing_literal_renders_faithfully(self):
        # A NUL byte inside a string lexeme must ride the literal —
        # the slot split is by token index, never an in-band
        # sentinel a hostile literal could collide with.
        r = _ok(
            "function f($i) {\n"
            "    $c = str_replace('a\x00b', 'y', escapeshellcmd($i));\n"
            "    system($c);\n"
            "}",
            names=("escapeshellcmd",),
        )
        assert r.steps[1].template() == "str_replace('a\x00b','y',{DATA})"

    def test_superglobal_indexed_data_slot(self):
        r = _ok(
            "function f() {\n"
            "    $v = htmlspecialchars($_GET['x'], ENT_QUOTES);\n"
            "    echo \"<a title='$v'>\";\n"
            "}",
        )
        assert r.steps[0].template() == (
            "htmlspecialchars({DATA},ENT_QUOTES)"
        )
        assert r.subject_var == "_GET"

    def test_indexed_slot_requires_literal_index(self):
        r = _refused(
            "function f($k) {\n"
            "    $v = htmlspecialchars($_GET[$k]);\n"
            "    echo $v;\n"
            "}",
        )
        assert "variable references" in r.reason or "literal" in r.reason

    def test_unknown_flag_constant(self):
        r = _refused(
            "function z($x) {\n"
            "    $v = htmlspecialchars($x, MY_FLAGS);\n"
            "    echo $v;\n"
            "}"
        )
        assert "flag vocabulary" in r.reason

    def test_heredoc_refuses(self):
        r = _refused(
            "function s($x) {\n"
            "    $v = escapeshellarg($x);\n"
            "    $t = <<<EOT\nhello\nEOT;\n"
            "    system($v);\n"
            "}"
        )
        assert "heredoc" in r.reason

    def test_raw_copy_beside_assembly(self):
        r = _refused(
            "function q($x) {\n"
            '    $cmd = "prog " . escapeshellcmd($x) . " " . $x;\n'
            "    system($cmd);\n"
            "}"
        )
        assert "unsanitized" in r.reason

    def test_preg_replace_e_modifier(self):
        r = _refused(
            "function e($x) {\n"
            "    $v = preg_replace('/a/e', 'b', "
            "htmlspecialchars($x));\n"
            "    echo $v;\n"
            "}"
        )
        assert "'e' modifier" in r.reason

    def test_empty_source(self):
        r = _refused("")
        assert "no function source" in r.reason

    def test_pathological_expression_size_refuses(self):
        # Deep allowlisted nesting must refuse at the token ceiling,
        # never recurse toward the interpreter limit.
        nested = "trim(" * 400 + "$x" + ")" * 400
        r = _refused(
            "function d($x) {\n"
            f"    $v = htmlspecialchars({nested});\n"
            "    echo $v;\n"
            "}"
        )
        assert "exceeds" in r.reason


class TestVocabularyPolicy:
    def test_step_allowlist_stays_seed_sized_per_category(self):
        from core.audit.sanwit._extract import _STEP_ALLOWLIST

        for category, names in _STEP_ALLOWLIST.items():
            assert len(names) <= 9, (category, len(names))
        assert ALLOWED_STEP_CALLABLES == frozenset(
            n for names in _STEP_ALLOWLIST.values() for n in names
        )

    @pytest.mark.parametrize("name", sorted(ALLOWED_STEP_CALLABLES))
    def test_allowlist_names_are_php_identifiers(self, name):
        assert name.replace("_", "").isalnum()
        assert name == name.lower()
