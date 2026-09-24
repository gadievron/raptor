"""Include-argument shape classification pairs and the wiring
re-point — one parser, two consumers."""

from __future__ import annotations

import pytest

from core.inventory.script_handler import (
    classify_include_argument,
    php_interstitial_is_handler,
)

# ---------------------------------------------------------------------------
# Shape classification — the ONE include-literal decision
# ---------------------------------------------------------------------------


class TestClassifyIncludeArgument:
    @pytest.mark.parametrize("arg,shape,const,tail", [
        ("'lib/util.php'", "literal", None, "lib/util.php"),
        ('"lib/util.php"', "literal", None, "lib/util.php"),
        ("('lib/util.php')", "literal", None, "lib/util.php"),
        ("(('a.php'))", "literal", None, "a.php"),
        ("'a' . 'b.php'", "literal", None, "ab.php"),
        ("APP_PATH . 'inc/boot.php'", "const_prefix", "APP_PATH",
         "inc/boot.php"),
        ("(APP_PATH . 'inc/boot.php')", "const_prefix", "APP_PATH",
         "inc/boot.php"),
        ("APP_PATH . 'inc/' . 'boot.php'", "const_prefix", "APP_PATH",
         "inc/boot.php"),
        ("__DIR__ . '/x.php'", "const_prefix", "__DIR__", "/x.php"),
        ("APP_PATH . $dir . 'conf.php'", "dynamic", "APP_PATH",
         "conf.php"),
        ("$_GET['page'] . '.php'", "dynamic", None, ".php"),
        ("dirname(__FILE__) . '/x.php'", "dynamic", None, "/x.php"),
        ("$var", "dynamic", None, None),
        ("", "dynamic", None, None),
        ("'unterminated", "dynamic", None, None),
    ])
    def test_shape_pairs(self, arg, shape, const, tail):
        got = classify_include_argument(arg)
        assert got.shape == shape
        assert got.const_name == const
        assert got.literal_tail == tail

    def test_interpolated_dispatcher_stem_and_tail(self):
        got = classify_include_argument(
            'APP_PATH . $dir . "modules/$page.mod"')
        assert got.shape == "dynamic"
        assert got.const_name == "APP_PATH"
        assert got.literal_stem == "modules/"
        assert got.literal_tail == ".mod"

    def test_interpolated_prefix_only(self):
        got = classify_include_argument('"themes/$name/theme.php"')
        assert got.shape == "dynamic"
        assert got.literal_stem == "themes/"
        assert got.literal_tail == "/theme.php"

    def test_double_quoted_without_holes_is_literal(self):
        got = classify_include_argument('"inc/boot.php"')
        assert got.shape == "literal"

    def test_single_quote_escapes(self):
        got = classify_include_argument(r"'it\'s.php'")
        assert got.shape == "literal"
        assert got.literal_tail == "it's.php"

    def test_dot_inside_string_is_not_concat(self):
        got = classify_include_argument("'a.b.php'")
        assert got.shape == "literal"
        assert got.literal_tail == "a.b.php"

    def test_never_a_resolution_verdict(self):
        # const_prefix does NOT populate a target — resolution is a
        # per-entry (phase 1b) or derivation-side concern.
        got = classify_include_argument("APP_PATH . 'x.php'")
        assert not hasattr(got, "target")


class TestWiringRepoint:
    """The wiring test consumes the shared classifier — one parser,
    two consumers."""

    def test_literal_include_is_wiring(self):
        assert php_interstitial_is_handler(
            "<?php\ninclude_once('setup.php');\n") is False
        assert php_interstitial_is_handler(
            "<?php\nrequire 'setup.php';\n") is False

    def test_const_prefix_include_is_handler(self):
        assert php_interstitial_is_handler(
            "<?php\nrequire_once(APP_PATH . 'inc/boot.php');\n") is True

    def test_dynamic_include_is_handler(self):
        assert php_interstitial_is_handler(
            "<?php\ninclude($_GET['page'] . '.php');\n") is True
