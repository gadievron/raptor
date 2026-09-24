"""Graph reachability verdicts are vacuous for interstitial spans.

An ``interstitial`` checklist item is a synthetic file-scope span —
its name (``interstitial:<start>-<end>``) never appears as a call
graph node, so the entry-reachability and 1-hop stages can only
manufacture dead verdicts for it. With sites now resolving into
stamped script-handler spans (``lookup_function`` enclosure), a
manufactured ``not_called`` would clamp /validate attack-path
proximity and steer the /codeql prefilter on a REAL request handler.
The precedence guard stops at ``uncertain`` for interstitial items;
sound line-based dead witnesses (module abort) still win, and
function items keep their normal verdicts.
"""

from __future__ import annotations

import pytest

from core.analysis.reach_audit import classify_reachability

pytest.importorskip(
    "tree_sitter_php",
    reason="PHP call graph needs the tree-sitter grammar",
)

_PHP_MODULE = """\
<?php
require_once('lib/common.php');

function helper($x) {
  return htmlspecialchars($x);
}

$cmd = $_POST['cmd'];
helper($cmd);
"""

_PHP_INDEX = """\
<?php
require('mod/save.php');
function main_fn() { helper('x'); }
main_fn();
"""


@pytest.fixture
def inventory(tmp_path):
    from core.inventory.builder import build_inventory
    target = tmp_path / "target"
    (target / "mod").mkdir(parents=True)
    (target / "mod" / "save.php").write_text(_PHP_MODULE)
    (target / "index.php").write_text(_PHP_INDEX)
    return build_inventory(str(target), str(tmp_path / "out"))


class TestInterstitialVacuity:
    def test_handler_span_is_uncertain_not_not_called(self, inventory):
        # The file-scope handler span: no call-graph node carries its
        # name, so pre-guard the 1-hop stage manufactured not_called —
        # a proximity clamp on a real request handler.
        items = next(f["items"] for f in inventory["files"]
                     if f["path"] == "mod/save.php")
        span = next(it for it in items
                    if it.get("kind") == "interstitial"
                    and it.get("script_handler") is True)
        verdict = classify_reachability(
            inventory, "mod/save.php", span["name"],
            span["line_start"], "mod.save",
        )
        assert verdict == "uncertain"

    def test_wiring_span_is_uncertain_too(self, inventory):
        # Kind-keyed, not stamp-keyed: the graph verdict is vacuous
        # for EVERY interstitial span (the stamp governs review
        # eligibility, not call-graph identity).
        items = next(f["items"] for f in inventory["files"]
                     if f["path"] == "mod/save.php")
        span = next(it for it in items
                    if it.get("kind") == "interstitial"
                    and it.get("script_handler") is False)
        verdict = classify_reachability(
            inventory, "mod/save.php", span["name"],
            span["line_start"], "mod.save",
        )
        assert verdict == "uncertain"

    def test_unresolvable_span_name_is_uncertain(self, inventory):
        # Span boundaries drift between checklist vintages; a caller
        # holding an old span name misses the item index — the
        # name-shape fallback still refuses to manufacture a verdict.
        verdict = classify_reachability(
            inventory, "mod/save.php", "interstitial:999-1000",
            999, "mod.save",
        )
        assert verdict == "uncertain"

    def test_function_items_keep_their_verdicts(self, inventory):
        # The guard is interstitial-only: the called function still
        # classifies as called.
        verdict = classify_reachability(
            inventory, "mod/save.php", "helper", 4, "mod.save",
        )
        assert verdict == "called"

    def test_sound_module_abort_still_wins(self):
        # A handler span BELOW an unconditional module abort is dead
        # regardless of kind — the sound witness precedes the guard.
        inv = {"files": [{
            "path": "mod/gone.php", "language": "php",
            "module_aborts_on_load": {"line": 2, "summary": "die()"},
            "items": [{"name": "interstitial:4-6", "kind": "interstitial",
                       "line_start": 4, "line_end": 6,
                       "script_handler": True}],
        }]}
        verdict = classify_reachability(
            inv, "mod/gone.php", "interstitial:4-6", 4, "mod.gone",
        )
        assert verdict == "module_aborts"

    def test_sound_lexical_dead_still_wins(self):
        # Same pin for the other sound line-based witness: a span
        # inside an always-false guard stays lexically dead — the
        # witness precedes the vacuity stop.
        inv = {"files": [{
            "path": "mod/dead.php", "language": "php",
            "items": [{"name": "interstitial:4-6", "kind": "interstitial",
                       "line_start": 4, "line_end": 6,
                       "script_handler": True,
                       "lexical_dead": True}],
        }]}
        verdict = classify_reachability(
            inv, "mod/dead.php", "interstitial:4-6", 4, "mod.dead",
        )
        assert verdict == "lexical_dead"
