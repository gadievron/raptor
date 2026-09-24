"""compute_gaps consumes the persisted script_handler stamp.

The builder stamps the handler classification on checklist items;
gap selection must READ that stamp — not recompute — with the
source-recompute path reserved for pre-stamp checklists (resumable
runs). Pinned here:

* differential: a stamped checklist selects exactly the same gap set
  as the same checklist without stamps (the landed recompute
  behavior) over the same tree;
* authority: the stamp decides selection without touching source —
  a stamped checklist selects correctly even when the tree is gone;
* fallback: a forged non-bool stamp degrades to the recompute path,
  never reads as True.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.gaps import compute_gaps

_PHP_HANDLER = """\
<?php
/**
 * Module fixture: file-scope request handler.
 */
require_once('lib/common.php');

function helper($x) {
  return htmlspecialchars($x);
}

$cmd = $_POST['cmd'];
process_line($cmd);
"""

_PHP_WIRING = """\
<?php
include_once('lib/common.php');
require_once('lib/auth.php');
declare(strict_types=1);

function helper($x) {
  return trim($x);
}
"""


def _write_tree(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "handler.php").write_text(_PHP_HANDLER)
    (target / "wiring.php").write_text(_PHP_WIRING)
    return target


def _checklist(target: Path, *, stamps: bool) -> dict:
    def _stamp(item: dict, value: bool) -> dict:
        if stamps:
            item["script_handler"] = value
        return item

    return {
        "target_path": str(target),
        "files": [
            {
                "path": "handler.php",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 7, "line_end": 9},
                    _stamp({"name": "interstitial:1-6",
                            "kind": "interstitial",
                            "line_start": 1, "line_end": 6}, False),
                    _stamp({"name": "interstitial:10-12",
                            "kind": "interstitial",
                            "line_start": 10, "line_end": 12}, True),
                ],
            },
            {
                "path": "wiring.php",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 6, "line_end": 8},
                    _stamp({"name": "interstitial:1-5",
                            "kind": "interstitial",
                            "line_start": 1, "line_end": 5}, False),
                ],
            },
        ],
    }


def _gap_keys(gaps: list[dict]) -> set[tuple[str, str, int]]:
    return {(g["file"], g["name"], g["priority"]) for g in gaps}


def _run(checklist: dict) -> list[dict]:
    return compute_gaps(checklist, [])


class TestStampConsumption:
    def test_stamped_equals_recomputed(self, tmp_path):
        """Differential: stamp-read and source-recompute agree —
        same gap set, same priorities, over the same tree."""
        target = _write_tree(tmp_path)
        stamped = _run(_checklist(target, stamps=True))
        recomputed = _run(_checklist(target, stamps=False))
        assert _gap_keys(stamped) == _gap_keys(recomputed)
        # And the handler span is in the set (the landed behavior).
        assert any(g["name"] == "interstitial:10-12" for g in stamped)
        assert not any(g["name"] == "interstitial:1-6" for g in stamped)

    def test_stamp_decides_without_source(self, tmp_path):
        """The stamp is authoritative: selection works with the tree
        gone (nothing to recompute from), both directions."""
        gone = tmp_path / "no-such-tree"
        gaps = _run(_checklist(gone, stamps=True))
        assert any(g["name"] == "interstitial:10-12" for g in gaps)
        assert not any(g["name"] == "interstitial:1-6" for g in gaps)

    def test_missing_stamp_without_source_degrades_closed(self, tmp_path):
        """Pre-stamp checklist AND no source → the recompute has
        nothing to classify from; the span stays unselected (the
        landed degradation, no crash)."""
        gone = tmp_path / "no-such-tree"
        gaps = _run(_checklist(gone, stamps=False))
        assert not any(g["name"].startswith("interstitial:")
                       for g in gaps)

    def test_forged_stamp_falls_back_to_recompute(self, tmp_path):
        """A non-bool stamp (the checklist is attacker-writable JSON)
        is not a verdict: the recompute fallback classifies from
        source, so the wiring span stays out."""
        target = _write_tree(tmp_path)
        ck = _checklist(target, stamps=False)
        # Forge string stamps on both spans of handler.php.
        for item in ck["files"][0]["items"]:
            if item["kind"] == "interstitial":
                item["script_handler"] = "true"
        gaps = _run(ck)
        assert any(g["name"] == "interstitial:10-12" for g in gaps)
        assert not any(g["name"] == "interstitial:1-6" for g in gaps)

    def test_stamp_false_suppresses_selection(self, tmp_path):
        """A False stamp on handler-shaped content keeps the span out
        — the builder's verdict wins over what a recompute would say
        (one source of truth, not two)."""
        target = _write_tree(tmp_path)
        ck = _checklist(target, stamps=True)
        for item in ck["files"][0]["items"]:
            if item["name"] == "interstitial:10-12":
                item["script_handler"] = False
        gaps = _run(ck)
        assert not any(g["name"] == "interstitial:10-12" for g in gaps)

    def test_builder_stamped_checklist_round_trips(self, tmp_path):
        """End to end: build_inventory → JSON round-trip →
        compute_gaps selects the handler span from the stamp."""
        from core.inventory.builder import build_inventory
        target = _write_tree(tmp_path)
        inv = build_inventory(str(target), str(tmp_path / "out"))
        ck = json.loads(json.dumps(inv, default=str))
        ck["target_path"] = str(target)
        gaps = _run(ck)
        names = {g["name"] for g in gaps
                 if g["name"].startswith("interstitial:")}
        assert names == {"interstitial:10-12"}
