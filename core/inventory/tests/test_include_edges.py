"""Layer-0 PHP include edges: walker extraction and
serialization round-trips."""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    FileCallGraph,
    IncludeDefine,
    IncludeEdge,
    extract_call_graph_php,
)

# ---------------------------------------------------------------------------
# Walker extraction
# ---------------------------------------------------------------------------

_FIXTURE = """<?php
define('APP_PATH', './');
define('LIMIT', 5 + 1);
require_once(APP_PATH . 'inc/boot.php');
require 'plain.php';
if (!defined('APP_PATH')) {
    define('APP_PATH', '../');
}
if ($debug) {
    include(APP_PATH . 'inc/debug.php');
}
foreach ($mods as $m) { include "$m.php"; }
$x = $flag ? include 'alt.php' : 0;
$cond or include 'late.php';
function loader($name) {
    include_once(APP_PATH . "plugins/$name/setup.php");
}
"""


class TestPhpIncludeEdges:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_php")

    def _edges(self, src=_FIXTURE):
        return extract_call_graph_php(src)

    def test_edge_fields(self):
        g = self._edges()
        assert g.includes_extracted
        by_line = {e.line: e for e in g.includes}
        boot = by_line[4]
        assert boot.keyword == "require_once"
        assert boot.shape == "const_prefix"
        assert boot.const_name == "APP_PATH"
        assert boot.literal_tail == "inc/boot.php"
        assert boot.conditional is False
        assert boot.position == "file_scope"
        assert boot.enclosing_function is None
        assert len(boot.span_hash) == 12
        assert boot.raw == "APP_PATH . 'inc/boot.php'"
        plain = by_line[5]
        assert plain.shape == "literal"
        assert plain.literal_tail == "plain.php"

    def test_conditional_flags(self):
        g = self._edges()
        by_line = {e.line: e for e in g.includes}
        assert by_line[10].conditional is True   # inside if
        assert by_line[12].conditional is True   # inside foreach
        assert by_line[13].conditional is True   # ternary branch
        assert by_line[14].conditional is True   # RHS of `or`
        assert by_line[4].conditional is False

    def test_function_body_position(self):
        g = self._edges()
        fn = [e for e in g.includes if e.position == "function_body"]
        assert len(fn) == 1
        assert fn[0].enclosing_function == "loader"
        assert fn[0].literal_stem == "plugins/"
        assert fn[0].literal_tail == "/setup.php"

    def test_define_records(self):
        g = self._edges()
        defs = {(d.line, d.name): d for d in g.defines}
        first = defs[(2, "APP_PATH")]
        assert first.value == "./"
        assert first.conditional is False
        assert first.fallback is False
        nonlit = defs[(3, "LIMIT")]
        assert nonlit.value is None
        assert nonlit.raw_value  # capped raw kept for honesty
        fb = defs[(7, "APP_PATH")]
        assert fb.conditional is True
        assert fb.fallback is True
        assert fb.value == "../"

    def test_fallback_is_exact_shape_only(self):
        # ``fallback`` may only mark the exact one-guard shape: an
        # OUTER conditional around the fallback makes it an ordinary
        # conditional define (the record cannot express "fallback
        # plus outer condition", and claiming it would bind a
        # constant a direct request may never define).
        src = ("<?php\n"
               "if ($_GET['setup']) {\n"
               "  if (!defined('AUTH')) define('AUTH', 'yes');\n"
               "}\n"
               "if (!defined('K')) define('K', '1');\n")
        g = self._edges(src)
        defs = {d.name: d for d in g.defines}
        assert defs["AUTH"].fallback is False
        assert defs["AUTH"].conditional is True
        assert defs["K"].fallback is True  # the exact shape still marks

    def test_closure_and_arrow_bodies_are_function_body(self):
        # Anonymous/arrow function bodies run at CALL time: their
        # includes and defines must never surface as file-scope.
        src = ("<?php\n"
               "$cb = function () { include 'gate.php'; "
               "define('X', '1'); };\n"
               "$ar = fn() => include 'late.php';\n"
               "include 'now.php';\n")
        g = self._edges(src)
        by_tail = {e.literal_tail: e for e in g.includes}
        assert by_tail["gate.php"].position == "function_body"
        assert by_tail["late.php"].position == "function_body"
        assert by_tail["now.php"].position == "file_scope"
        [d] = g.defines
        assert d.position == "function_body"

    def test_lossy_flag_still_set(self):
        from core.inventory.call_graph import INDIRECTION_DYNAMIC_IMPORT
        g = self._edges()
        assert INDIRECTION_DYNAMIC_IMPORT in g.indirection

    def test_direct_access_guard_if_die(self):
        src = ("<?php\n"
               "if (!defined('IN_APP')) { die('no direct access'); }\n"
               "$x = 1;\n")
        g = self._edges(src)
        assert g.direct_access_guard == {"line": 2, "constant": "IN_APP"}

    def test_direct_access_guard_braceless_exit(self):
        src = "<?php\nif (!defined('IN_APP')) exit;\n"
        g = self._edges(src)
        assert g.direct_access_guard == {"line": 2, "constant": "IN_APP"}

    def test_direct_access_guard_or_die(self):
        src = "<?php\ndefined('IN_APP') or die('nope');\n"
        g = self._edges(src)
        assert g.direct_access_guard == {"line": 2, "constant": "IN_APP"}

    def test_fallback_define_is_not_a_guard(self):
        src = ("<?php\n"
               "if (!defined('APP_PATH')) { define('APP_PATH', './'); }\n")
        g = self._edges(src)
        assert g.direct_access_guard is None

    def test_guard_inside_function_ignored(self):
        src = ("<?php\nfunction f() {\n"
               "  if (!defined('IN_APP')) { die(); }\n}\n")
        g = self._edges(src)
        assert g.direct_access_guard is None

    def test_nested_conditional_guard_is_not_evidence(self):
        # A planted dead-branch guard must not make an unguarded
        # included file read as guarded.
        src = ("<?php\nif ($never) {\n"
               "  if (!defined('IN_APP')) { die(); }\n"
               "  defined('IN_APP') or exit;\n}\n")
        g = self._edges(src)
        assert g.direct_access_guard is None

    @pytest.mark.parametrize("src", [
        # dead plants: the guard line never executes
        "<?php\nexit;\nif (!defined('IN_APP')) die('x');\n",
        "<?php\nreturn;\nif (!defined('IN_APP')) die('x');\n",
        "<?php\ngoto skip;\nif (!defined('IN_APP')) die('x');\n"
        "skip: echo 1;\n",
        "<?php\n__halt_compiler();\nif (!defined('IN_APP')) die();\n",
        "<?php\nexit;\ndefined('IN_APP') or die;\n",
        # bottom-of-file guard: a direct request runs the payload
        # FIRST — the guard protects nothing
        "<?php\nprocess($_GET['q']);\nif (!defined('IN_APP')) die();\n",
        "<?php\n$x = $_GET['q'];\ndefined('IN_APP') or exit;\n",
        "<?php\necho $banner;\nif (!defined('IN_APP')) die('x');\n",
        # markup output before the guard is payload output
        "<?php $pad = 1; ?><b>out</b><?php\n"
        "if (!defined('IN_APP')) die('x');\n",
    ])
    def test_guard_after_payload_or_abort_is_not_evidence(self, src):
        assert self._edges(src).direct_access_guard is None

    @pytest.mark.parametrize("src", [
        # genuine guard spellings in an inert prologue still record
        "<?php\nif (!defined('IN_APP')) die('no');\necho 1;\n",
        "<?php\ndefined('IN_APP') or exit;\n$x = 1;\n",
        "<?php\nif (!defined('IN_APP')): die('no'); endif;\n",
        "<?php\nif (!(defined('IN_APP'))) @die('x');\n",
        "<?php\ndeclare(strict_types=1);\n"
        "if (!defined('IN_APP')) die('x');\n",
        "<?php\nnamespace A;\nif (!defined('IN_APP')) die('x');\n",
        "<?php\ndefine('V', '1');\nrequire 'inc/a.php';\n"
        "if (!defined('IN_APP')) exit(1);\nreal_code();\n",
    ])
    def test_prologue_guard_spellings_record(self, src):
        assert self._edges(src).direct_access_guard is not None

    def test_inverted_double_negation_is_not_a_guard(self):
        # !!defined dies when the constant IS defined — recording it
        # would invert the evidence.
        src = "<?php\nif (!!defined('IN_APP')) die('no');\n"
        assert self._edges(src).direct_access_guard is None

    @pytest.mark.parametrize("src", [
        # inert-LOOKING wrappers with payload bodies/values: the
        # payload executes on a direct request before the guard.
        "<?php\ndeclare(ticks=1) { process($_GET['c']); }\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\ndeclare(ticks=1) process($_GET['c']);\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\ndefine('K', pick_value($_GET['c']));\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\nif (!defined('NEVER_SET')) { process($_GET['c']); }\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\ninclude pick_path();\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\n@process($_GET['c']);\n"
        "if (!defined('IN_APP')) die();\n",
    ])
    def test_payload_inside_inert_wrapper_closes_prologue(self, src):
        assert self._edges(src).direct_access_guard is None

    @pytest.mark.parametrize("src", [
        # body-aware inertness keeps the honest shapes recorded
        "<?php\ndeclare(strict_types=1);\n"
        "if (!defined('IN_APP')) die();\n",
        "<?php\ndefine('K', 'v');\ndefine('N', 1);\n"
        "define('B', true);\nif (!defined('IN_APP')) die();\n",
        "<?php\nif (!defined('K')) { define('K', '1'); }\n"
        "if (!defined('IN_APP')) die();\n",
        # include with an inert argument stays prologue-inert — the
        # adjudicated shape: the included file keeps its own role,
        # guard, and census attention; this file's guard claims only
        # its OWN below-guard payload.
        "<?php\nrequire 'inc/bootstrap.php';\n"
        "if (!defined('IN_APP')) die();\n",
    ])
    def test_inert_wrappers_with_inert_bodies_stay_recorded(self, src):
        assert self._edges(src).direct_access_guard is not None

    def test_braced_namespace_guard_records(self):
        # The anonymous `{` token is not a statement — classifying it
        # would close the prologue at the opening brace and blind
        # every braced-namespace guard.
        src = ("<?php\nnamespace A {\n"
               "  if (!defined('IN_APP')) die();\n"
               "  process($x);\n}\n")
        assert self._edges(src).direct_access_guard is not None

    def test_braced_namespace_payload_still_closes(self):
        # Two-direction: payload before the guard inside the braces
        # still closes eligibility.
        src = ("<?php\nnamespace A {\n  echo 'x';\n"
               "  if (!defined('IN_APP')) die();\n}\n")
        assert self._edges(src).direct_access_guard is None

    def test_dynamic_include_before_guard_closes(self):
        # A dynamic include's target carries no
        # role/census attention of its own — the pre-guard dispatcher
        # risk stays on this file, so it closes guard eligibility.
        for src in (
            "<?php\ninclude $page;\nif (!defined('IN_APP')) die();\n",
            "<?php\ninclude APP_PATH . $dir . 'x.php';\n"
            "if (!defined('IN_APP')) die();\n",
        ):
            assert self._edges(src).direct_access_guard is None

    def test_resolvable_include_before_guard_stays_recorded(self):
        # Two-direction: literal and const-prefix includes keep the
        # adjudicated inertness (their targets keep their own
        # attention in the graph).
        for src in (
            "<?php\nrequire 'inc/boot.php';\n"
            "if (!defined('IN_APP')) die();\n",
            "<?php\nrequire_once(APP_PATH . 'inc/boot.php');\n"
            "if (!defined('IN_APP')) die();\n",
        ):
            assert self._edges(src).direct_access_guard is not None

    def test_deep_concat_extraction_stays_linear(self):
        # A per-node parent probe made extraction quadratic in
        # expression depth (tens of seconds at 16k concat parts);
        # prologue classification must ride the statement iteration.
        import time
        src = ("<?php\ninclude "
               + ".".join("'p%d'" % i for i in range(8000))
               + ";\n$x = 1;\n")
        t0 = time.monotonic()
        g = extract_call_graph_php(src)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0  # pre-fix: >10s at this size
        [edge] = g.includes  # non-vacuity: still extracted
        assert edge.shape == "literal"

    def test_edge_cap_sets_truncated(self, monkeypatch):
        from core.inventory.call_graph import _PhpCallGraph
        monkeypatch.setattr(_PhpCallGraph, "_MAX_INCLUDE_EDGES", 2)
        src = "<?php\n" + "\n".join(
            f"include 'f{i}.php';" for i in range(4))
        g = extract_call_graph_php(src)
        assert len(g.includes) == 2
        assert g.includes_truncated is True

    def test_roundtrip(self):
        g = self._edges()
        d = g.to_dict()
        assert "includes" in d and "defines" in d
        g2 = FileCallGraph.from_dict(d)
        assert g2.includes_extracted
        assert [e.to_dict() for e in g2.includes] == d["includes"]
        assert [x.to_dict() for x in g2.defines] == d["defines"]

    def test_from_dict_coerces_forged_shapes(self):
        e = IncludeEdge.from_dict(
            {"line": "99", "keyword": 7, "shape": ["x"],
             "conditional": "yes", "candidates": ["a", 3]})
        assert e.line == 0
        assert e.keyword == "include"
        assert e.shape == "dynamic"
        assert e.candidates == ["a"]
        x = IncludeDefine.from_dict({"name": 3, "fallback": "y"})
        assert x.name == ""
        assert x.fallback is True

    def test_boundary_records(self):
        src = ("<?php\n"
               "define('APP_PATH', './');\n"
               "if (!defined('IN_APP')) die('x');\n"
               "if ($x) { return; }\n"
               "if (defined('DONE')) exit;\n"
               "goto skip;\n"
               "skip:\n"
               "return;\n"
               "__halt_compiler();\n")
        g = self._edges(src)
        kinds = [(b["line"], b["kind"]) for b in g.boundaries]
        assert kinds == [
            (3, "conditional_abort"), (4, "conditional_return"),
            (5, "conditional_abort"), (6, "goto"),
            (8, "terminator"), (9, "halt"),
        ]
        assert g.boundaries[0]["guard_constant"] == "IN_APP"
        assert g.boundaries[0]["guard_negated"] is True
        assert g.boundaries[2]["guard_constant"] == "DONE"
        assert g.boundaries[2]["guard_negated"] is False
        assert "guard_constant" not in g.boundaries[1]

    def test_boundary_nested_conditional_has_no_guard_info(self):
        # Guard info only when there is exactly ONE enclosing
        # conditional and it is guard-shaped — a nested return can't
        # be no-opped by binding one constant.
        src = ("<?php\nif (!defined('A')) { if ($x) { return; } }\n")
        g = self._edges(src)
        [b] = g.boundaries
        assert b["kind"] == "conditional_return"
        assert "guard_constant" not in b

    def test_boundary_inside_function_ignored(self):
        src = "<?php\nfunction f() { return 1; }\n$x = 1;\n"
        assert self._edges(src).boundaries == []

    def test_boundary_overflow_sentinel(self):
        src = "<?php\n" + "\n".join(
            "if ($c%d) { return; }" % i for i in range(12))
        g = self._edges(src)
        assert len(g.boundaries) == 9
        assert g.boundaries[-1]["kind"] == "overflow"

    def test_parse_errors_flag(self):
        assert self._edges("<?php\n$x = 1;\n").parse_errors is False
        assert self._edges(
            "<?php if ( { ; process($x);").parse_errors is True

    def test_non_php_graph_has_no_include_keys(self):
        d = FileCallGraph().to_dict()
        assert "includes" not in d
        assert "defines" not in d
        assert FileCallGraph.from_dict(d).includes_extracted is False
