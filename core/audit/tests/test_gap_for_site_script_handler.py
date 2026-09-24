"""gap_for_site binds mechanical hits inside stamped handler spans.

The sweeplang change made script-per-file handler interstitials
schedulable as COLD gaps, but a mechanical tool HIT landing inside
one still could not bind to a reviewable gap — confirmed signal was
dropped at the exact spans the run itself decided were reviewable.
Binding is stamp-gated: ``script_handler: true`` admits the span,
``false`` and compiled-language residue stay refused, an enclosing
function still wins over the span, and a pre-stamp checklist
recomputes from source rather than silently diverging from stamped
runs.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.gaps import gap_for_site

_PHP_HANDLER = """\
<?php
require_once('lib/common.php');

function helper($x) {
  return htmlspecialchars($x);
}

$cmd = $_POST['cmd'];
process_line($cmd);
"""


def _checklist(*, stamps: bool, target: Path | None = None) -> dict:
    handler = {"name": "interstitial:8-9", "kind": "interstitial",
               "line_start": 8, "line_end": 9}
    wiring = {"name": "interstitial:1-3", "kind": "interstitial",
              "line_start": 1, "line_end": 3}
    if stamps:
        handler["script_handler"] = True
        wiring["script_handler"] = False
    ck = {
        "files": [
            {
                "path": "mod/save.php",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 4, "line_end": 6},
                    wiring,
                    handler,
                ],
            },
            {
                "path": "native.c",
                "language": "c",
                "items": [
                    {"name": "bump", "kind": "function",
                     "line_start": 5, "line_end": 7},
                    {"name": "interstitial:1-3", "kind": "interstitial",
                     "line_start": 1, "line_end": 3},
                ],
            },
        ],
    }
    if target is not None:
        ck["target_path"] = str(target)
    return ck


class TestStampedBinding:
    def test_hit_in_stamped_handler_span_binds(self):
        gap = gap_for_site(_checklist(stamps=True), "mod/save.php", 8)
        assert gap is not None
        assert gap["name"] == "interstitial:8-9"
        assert gap["line_start"] == 8
        assert gap["line_end"] == 9
        # Same shape compute_gaps emits — consumers index by these.
        for key in ("file", "name", "priority", "strategies",
                    "is_stale", "sloc"):
            assert key in gap

    def test_hit_in_stamped_wiring_span_stays_unbound(self):
        assert gap_for_site(
            _checklist(stamps=True), "mod/save.php", 2) is None

    def test_compiled_language_residue_stays_unbound(self):
        assert gap_for_site(
            _checklist(stamps=True), "native.c", 2) is None

    def test_enclosing_function_wins_over_handler_span(self):
        gap = gap_for_site(_checklist(stamps=True), "mod/save.php", 5)
        assert gap is not None
        assert gap["name"] == "helper"

    def test_forged_stamp_string_does_not_admit(self):
        ck = _checklist(stamps=False)
        for it in ck["files"][0]["items"]:
            if it["kind"] == "interstitial":
                it["script_handler"] = "true"
        # No target_path either → nothing to recompute from → refuse.
        assert gap_for_site(ck, "mod/save.php", 8) is None


class TestPreStampFallback:
    def test_recomputes_from_source_when_stamp_absent(self, tmp_path):
        target = tmp_path / "target"
        (target / "mod").mkdir(parents=True)
        (target / "mod" / "save.php").write_text(_PHP_HANDLER)
        ck = _checklist(stamps=False, target=target)
        gap = gap_for_site(ck, "mod/save.php", 8)
        assert gap is not None and gap["name"] == "interstitial:8-9"
        # Wiring span still refuses under the recompute.
        assert gap_for_site(ck, "mod/save.php", 2) is None

    def test_stamp_absent_and_source_gone_degrades_closed(self, tmp_path):
        ck = _checklist(stamps=False, target=tmp_path / "no-such-tree")
        assert gap_for_site(ck, "mod/save.php", 8) is None

    def test_stamp_absent_and_no_target_path_degrades_closed(self):
        assert gap_for_site(
            _checklist(stamps=False), "mod/save.php", 8) is None
