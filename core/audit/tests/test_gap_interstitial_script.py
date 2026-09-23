"""Script-per-file handler interstitials are gap-eligible.

For languages where file-scope statements ARE the program (classic
PHP request handlers), the extractor's ``interstitial`` items carry
the code a request actually executes — on script-heavy trees they are
roughly half the checklist. Excluding the kind from gap selection and
demoting it as dead residue wrote off that half of the attack
surface. The fix is measured, not a blanket flip: only interstitials
whose FILE language is script-per-file AND whose content is more than
include/require boilerplate are selected, and they compete on the
normal priority tiers; compiled-language file-scope residue keeps the
existing exclusion and dead-code demotion (that rationale was real —
declarations-and-braces glue has nothing to review).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.gaps import (
    PRIORITY_DEAD_CODE,
    _compute_priority,
    _php_interstitial_is_handler,
    _script_interstitials_enabled,
    compute_gaps,
)

_PHP_HANDLER = """\
<?php
/**
 * Module fixture: file-scope request handler.
 */
global $app_config;

function helper($x) {
  return htmlspecialchars($x);
}

$cmd = $_POST['cmd'];
$lines = explode("\\n", $cmd);
for ($i = 0; $i < sizeof($lines); $i++) {
  process_line($lines[$i]);
}
"""

_PHP_BOILERPLATE = """\
<?php
/**
 * Wiring-only fixture: nothing here runs beyond includes.
 */
include_once('lib/common.php');
require_once('lib/auth.php');
use App\\Handlers;
declare(strict_types=1);
global $app_config;

function helper($x) {
  return trim($x);
}
"""

_C_FILE = """\
#include <stdlib.h>

static int counter;

int bump(void) {
  return ++counter;
}
"""


def _write_tree(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "handler.mod").write_text(_PHP_HANDLER)
    (target / "wiring.php").write_text(_PHP_BOILERPLATE)
    (target / "count.c").write_text(_C_FILE)
    return target


def _checklist(target: Path) -> dict:
    return {
        "target_path": str(target),
        "files": [
            {
                "path": "handler.mod",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 7, "line_end": 9},
                    # License/docblock header residue.
                    {"name": "interstitial:1-6", "kind": "interstitial",
                     "line_start": 1, "line_end": 6},
                    # The file-scope request handler.
                    {"name": "interstitial:11-15", "kind": "interstitial",
                     "line_start": 11, "line_end": 15},
                ],
            },
            {
                "path": "wiring.php",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 11, "line_end": 13},
                    {"name": "interstitial:1-10", "kind": "interstitial",
                     "line_start": 1, "line_end": 10},
                ],
            },
            {
                "path": "count.c",
                "language": "c",
                "items": [
                    {"name": "bump", "kind": "function",
                     "line_start": 5, "line_end": 7},
                    # File-scope residue: include + static declaration.
                    {"name": "interstitial:1-3", "kind": "interstitial",
                     "line_start": 1, "line_end": 3},
                ],
            },
        ],
    }


def _gap_names(gaps: list[dict]) -> set:
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestSelection:
    def test_php_handler_interstitial_selected_and_prioritized(
        self, tmp_path: Path,
    ):
        gaps = compute_gaps(_checklist(_write_tree(tmp_path)), [])
        names = _gap_names(gaps)
        assert "handler.mod:interstitial:11-15" in names
        handler = next(
            g for g in gaps
            if g["file"] == "handler.mod"
            and g["name"] == "interstitial:11-15"
        )
        assert handler["priority"] < PRIORITY_DEAD_CODE

    def test_php_boilerplate_interstitial_stays_out(self, tmp_path: Path):
        gaps = compute_gaps(_checklist(_write_tree(tmp_path)), [])
        names = _gap_names(gaps)
        assert "wiring.php:interstitial:1-10" not in names
        assert "handler.mod:interstitial:1-6" not in names

    def test_c_interstitial_stays_out(self, tmp_path: Path):
        gaps = compute_gaps(_checklist(_write_tree(tmp_path)), [])
        assert "count.c:interstitial:1-3" not in _gap_names(gaps)

    def test_mixed_fixture_counts(self, tmp_path: Path):
        gaps = compute_gaps(_checklist(_write_tree(tmp_path)), [])
        # 3 functions + exactly ONE interstitial (the PHP handler).
        assert len(gaps) == 4
        assert sum(
            1 for g in gaps if g["name"].startswith("interstitial:")
        ) == 1

    def test_opt_out_via_include_kinds(self, tmp_path: Path):
        gaps = compute_gaps(
            _checklist(_write_tree(tmp_path)), [],
            include_kinds={"-interstitial"},
        )
        assert not any(
            g["name"].startswith("interstitial:") for g in gaps
        )

    def test_none_keeps_functions_only(self, tmp_path: Path):
        gaps = compute_gaps(
            _checklist(_write_tree(tmp_path)), [],
            include_kinds={"none"},
        )
        assert not any(
            g["name"].startswith("interstitial:") for g in gaps
        )

    def test_positive_interstitial_admits_kind_wholesale(
        self, tmp_path: Path,
    ):
        # Operator override: naming the kind positively admits every
        # interstitial (existing semantics), but only script handlers
        # escape the dead-code demotion — C residue stays demoted.
        gaps = compute_gaps(
            _checklist(_write_tree(tmp_path)), [],
            include_kinds={"interstitial"},
        )
        by_key = {f"{g['file']}:{g['name']}": g for g in gaps}
        assert "count.c:interstitial:1-3" in by_key
        assert (
            by_key["count.c:interstitial:1-3"]["priority"]
            == PRIORITY_DEAD_CODE
        )
        assert (
            by_key["handler.mod:interstitial:11-15"]["priority"]
            < PRIORITY_DEAD_CODE
        )


class TestScriptInterstitialsEnabled:
    def test_default_on(self):
        assert _script_interstitials_enabled(None)
        assert _script_interstitials_enabled(set())

    def test_none_off(self):
        assert not _script_interstitials_enabled({"none"})

    def test_negative_opt_out(self):
        assert not _script_interstitials_enabled({"-interstitial"})

    def test_other_negative_keeps_default(self):
        assert _script_interstitials_enabled({"-macro"})

    def test_positive_list_overrides(self):
        # A positive list picks the exact extra kinds — the gated
        # default steps aside (name "interstitial" for the whole kind).
        assert not _script_interstitials_enabled({"top_level"})


class TestPhpHandlerContentGate:
    def test_empty_and_missing(self):
        assert not _php_interstitial_is_handler(None)
        assert not _php_interstitial_is_handler("")

    def test_comments_and_wiring_only(self):
        assert not _php_interstitial_is_handler(
            "<?php\n"
            "/**\n * header\n */\n"
            "// note\n"
            "# note\n"
            "include('a.php');\n"
            "include_once('a.php');\n"
            "require 'b.php';\n"
            "require_once('c.php');\n"
            "use App\\Thing;\n"
            "namespace App;\n"
            "declare(strict_types=1);\n"
            "global $cfg;\n"
            "?>\n",
        )

    def test_assignment_is_handler_code(self):
        assert _php_interstitial_is_handler("$x = $_GET['q'];\n")

    def test_call_is_handler_code(self):
        assert _php_interstitial_is_handler("process($request);\n")

    def test_code_on_open_tag_line(self):
        assert _php_interstitial_is_handler("<?php dispatch(); ?>\n")

    def test_short_echo_tag(self):
        assert _php_interstitial_is_handler("<?= $x ?>\n")

    def test_block_comment_spanning_lines_then_code(self):
        assert _php_interstitial_is_handler(
            "/* start\n   middle\n   end */\n$y = f();\n",
        )
        assert not _php_interstitial_is_handler(
            "/* start\n   middle\n   end */\ninclude('a.php');\n",
        )

    def test_markup_counts_as_handler_surface(self):
        # Raw output markup is included on purpose (inclusion-biased:
        # the output surface is where injection lands).
        assert _php_interstitial_is_handler("<form action='save'>\n")

    def test_non_literal_include_is_handler_code(self):
        # include/require is wiring ONLY with a literal-string
        # argument; a request-derived or computed argument is the
        # classic local-file-inclusion dispatcher — handler code.
        assert _php_interstitial_is_handler(
            "include($_GET['page'] . '.php');\n",
        )
        assert _php_interstitial_is_handler(
            "require_once(APP_PATH . 'functions/init.php');\n",
        )
        assert _php_interstitial_is_handler(
            "require $module_file;\n",
        )

    def test_literal_include_stays_wiring(self):
        assert not _php_interstitial_is_handler(
            "include('lib/common.php');\n"
            "include_once \"lib/auth.php\";\n"
            "require 'b.php'; require_once('c.php');\n",
        )

    def test_second_statement_after_wiring_keyword(self):
        # Statement-wise classification: a wiring keyword opening the
        # line must not swallow the statement after the semicolon.
        assert _php_interstitial_is_handler(
            "global $x; $x = $_GET['q'];\n",
        )

    def test_trailing_comment_after_wiring_statement(self):
        assert not _php_interstitial_is_handler(
            "global $x; // request state lives here\n",
        )


class TestPriorityDirections:
    _BASE = {
        "file_coverage": set(),
        "reachable_sinks": None,
        "sloc": 40,
    }

    def test_script_handler_competes_on_normal_tiers(self):
        assert _compute_priority(
            **self._BASE, item_kind="interstitial", script_handler=True,
        ) < PRIORITY_DEAD_CODE

    def test_residue_interstitial_stays_demoted(self):
        assert _compute_priority(
            **self._BASE, item_kind="interstitial",
        ) == PRIORITY_DEAD_CODE

    def test_binary_absent_still_demotes_handlers(self):
        # The oracle's absent verdict outranks the handler lift.
        assert _compute_priority(
            **self._BASE, item_kind="interstitial",
            script_handler=True, binary_absent=True,
        ) == PRIORITY_DEAD_CODE


@pytest.mark.parametrize("language", ["c", "cpp", "go", "rust", "java"])
def test_compiled_languages_never_lift(language: str, tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "f.x").write_text("$x = f();\n")  # handler-shaped content
    checklist = {
        "target_path": str(target),
        "files": [{
            "path": "f.x",
            "language": language,
            "items": [{
                "name": "interstitial:1-1", "kind": "interstitial",
                "line_start": 1, "line_end": 1,
            }],
        }],
    }
    assert compute_gaps(checklist, []) == []
