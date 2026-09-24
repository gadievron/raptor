"""PHP fragmented-parse function recovery in the tree-sitter extractor.

Legacy constructs the grammar cannot parse (the removed-in-PHP-8
curly-brace offset syntax ``$arr{"k"}``) make tree-sitter drop the
enclosing ``function_definition`` and scatter its header tokens under
an ERROR node. Without recovery the function owned NO inventory item:
its span was swallowed by the surrounding interstitial (or by an
error-inflated neighbouring function span), so the code was never
scheduled for review and invisible to coverage.

Census invariants pinned here (synthetic fixtures):
  * every declared function owns exactly one function item;
  * no interstitial span contains a function declaration line.
"""

from __future__ import annotations

import re

import pytest

from core.inventory.extractors import (
    KIND_FUNCTION,
    compute_interstitial_items,
    extract_functions,
    extract_items,
)


def _php_grammar_available() -> bool:
    try:
        from core.inventory.extractors import _ts_parser_for
        return _ts_parser_for("php") is not None
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _php_grammar_available(), reason="tree-sitter-php not installed",
)


# Middle function's body carries the legacy curly-brace offset syntax:
# the parse errors, and pre-recovery the whole function vanished.
CURLY_OFFSET_FIXTURE = '''<?php
function alpha($a) {
    return $a + 1;
}

/**
 * Rewrites attributes.
 */
function beta($attrs, $box) {
    $out = Array('k' => 1);
    if (is_array($attrs)) {
        $out{"style"} = "\\"$box\\"";
    }
    return $out;
}

function gamma($x) {
    return $x;
}
'''

# Cascading-error shape: the first function's body errors deep inside
# nested blocks; tree-sitter leaves the FOLLOWING declarations' headers
# as bare ``function`` keyword tokens inside tiny ERROR nodes (the
# name/params get parsed as unrelated expressions), and can inflate a
# neighbouring recovered span over the next declaration.
CASCADE_FIXTURE = '''<?php
function advance($body, $offset){
    if ($offset > 0){
        while (sizeof($body{1})){
            $offset += strlen($body{1});
        }
    }
    return $offset;
}
function locate($body, $needle){
    $pos = strpos($body, $needle);
    return $pos;
}
'''

_DECL_RE = re.compile(r"\s*function\s+&?(\w+)\s*\(")


def _declared(fixture: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, line in enumerate(fixture.split("\n")):
        m = _DECL_RE.match(line)
        if m:
            out[m.group(1)] = i + 1
    return out


def _assert_census(fixture: str) -> None:
    """The invariant pair: one item per declared function, and no
    interstitial covering a declaration line."""
    declared = _declared(fixture)
    items = extract_items("fixture.php", "php", fixture)
    funcs = [it for it in items if it.kind == KIND_FUNCTION]
    by_name: dict[str, list] = {}
    for f in funcs:
        by_name.setdefault(f.name, []).append(f)
    for name, line in declared.items():
        owned = by_name.get(name, [])
        assert len(owned) == 1, (
            f"declared function {name} (line {line}) owns "
            f"{len(owned)} items, expected exactly 1"
        )
        assert owned[0].line_start == line
    lines = fixture.split("\n")
    for inter in compute_interstitial_items(items, fixture):
        for ln in range(inter.line_start, (inter.line_end or 0) + 1):
            assert not _DECL_RE.match(lines[ln - 1]), (
                f"{inter.name} swallows the declaration at line {ln}"
            )


def test_curly_offset_function_recovered_with_exact_span():
    funcs = {f.name: (f.line_start, f.line_end)
             for f in extract_functions("f.php", "php", CURLY_OFFSET_FIXTURE)}
    assert set(funcs) == {"alpha", "beta", "gamma"}
    assert funcs["beta"] == (9, 15)
    # Neighbours keep their tree-sitter spans.
    assert funcs["alpha"] == (2, 4)
    assert funcs["gamma"] == (17, 19)


def test_curly_offset_census_invariants():
    _assert_census(CURLY_OFFSET_FIXTURE)


def test_cascade_lone_token_recovery_and_clamp():
    funcs = {f.name: (f.line_start, f.line_end)
             for f in extract_functions("f.php", "php", CASCADE_FIXTURE)}
    assert set(funcs) == {"advance", "locate"}
    # ``advance``'s recovered span must not swallow ``locate``'s
    # declaration line (the clamp), and ``locate`` gets a bounded span.
    assert funcs["advance"][1] < funcs["locate"][0]
    assert funcs["locate"][0] == 10
    assert funcs["locate"][1] >= 12


def test_cascade_census_invariants():
    _assert_census(CASCADE_FIXTURE)


def test_clean_parse_unchanged():
    fixture = (
        "<?php\n"
        "function one($a) {\n"
        "    return $a;\n"
        "}\n"
        "$top = one(2);\n"
        "function two($b) {\n"
        "    return $b * 2;\n"
        "}\n"
    )
    funcs = {f.name: (f.line_start, f.line_end)
             for f in extract_functions("f.php", "php", fixture)}
    assert funcs == {"one": (2, 4), "two": (6, 8)}
    _assert_census(fixture)


def test_recovery_never_duplicates_parsed_function():
    # A parsed function with the same name as a recovered candidate
    # must not be re-minted (the seen-names guard).
    funcs = extract_functions("f.php", "php", CURLY_OFFSET_FIXTURE)
    names = [f.name for f in funcs]
    assert len(names) == len(set(names))


def test_anonymous_closure_fragment_not_minted():
    # A closure inside an errored region has no name to recover —
    # recovery must mint nothing rather than a phantom item.
    fixture = (
        "<?php\n"
        "$cb = function ($x) {\n"
        "    return $x{1};\n"
        "};\n"
        "function named($y) {\n"
        "    return $y;\n"
        "}\n"
    )
    funcs = [f for f in extract_functions("f.php", "php", fixture)
             if f.kind == KIND_FUNCTION]
    assert {f.name for f in funcs} == {"named"}


def test_broken_interpolation_string_text_not_minted():
    # A broken ``${`` interpolation makes tree-sitter re-tokenize the
    # string's own text as loose tokens under the string node — a
    # header spelled in string DATA reached the lone-token recovery
    # and minted a phantom item. The string-ancestry screen drops the
    # debris; the real declaration is still extracted.
    fixture = (
        "<?php\n"
        '$s = "abc ${ function phantom($x) { } }";\n'
        "function real($a) {\n"
        "    return $a;\n"
        "}\n"
    )
    funcs = {f.name: (f.line_start, f.line_end)
             for f in extract_functions("f.php", "php", fixture)
             if f.kind == KIND_FUNCTION}
    assert set(funcs) == {"real"}
    assert funcs["real"][0] == 3


def test_fragmented_function_still_recovered_beside_broken_interpolation():
    # Control direction: the ancestry screen must not reach code
    # OUTSIDE string nodes — a genuinely fragmented declaration in the
    # same file still recovers.
    fixture = (
        "<?php\n"
        '$s = "abc ${ function phantom($x) { } }";\n'
        "function fragmented($body) {\n"
        "    return sizeof($body{1});\n"
        "}\n"
        "function after($y) {\n"
        "    return $y;\n"
        "}\n"
    )
    funcs = {f.name for f in extract_functions("f.php", "php", fixture)
             if f.kind == KIND_FUNCTION}
    assert "phantom" not in funcs
    assert {"fragmented", "after"} <= funcs
