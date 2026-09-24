"""lookup_function encloses sites in stamped script-handler spans.

A sink inside a script-per-file request handler (a stamped
interstitial span) previously had no enclosing unit — enrichment
(finding metadata, journal naming, variant-candidate resolution)
silently lost the handler. Enclosure is stamp-gated in the
conservative direction: True encloses, False / absent / forged does
not (pre-stamp checklists keep the old behavior, which never
manufactures anything for downstream reachability).
"""

from __future__ import annotations

from core.inventory.lookup import lookup_function


def _checklist() -> dict:
    return {
        "files": [
            {
                "path": "mod/save.php",
                "language": "php",
                "items": [
                    {"name": "helper", "kind": "function",
                     "line_start": 4, "line_end": 6},
                    {"name": "interstitial:1-3", "kind": "interstitial",
                     "line_start": 1, "line_end": 3,
                     "script_handler": False},
                    {"name": "interstitial:8-9", "kind": "interstitial",
                     "line_start": 8, "line_end": 9,
                     "script_handler": True},
                ],
            },
        ],
    }


class TestStampedEnclosure:
    def test_sink_in_stamped_handler_span_encloses(self):
        func = lookup_function(_checklist(), "mod/save.php", 8)
        assert func is not None
        assert func["name"] == "interstitial:8-9"

    def test_sink_in_wiring_span_has_no_enclosure(self):
        assert lookup_function(_checklist(), "mod/save.php", 2) is None

    def test_pre_stamp_interstitial_has_no_enclosure(self):
        ck = _checklist()
        for it in ck["files"][0]["items"]:
            it.pop("script_handler", None)
        assert lookup_function(ck, "mod/save.php", 8) is None

    def test_forged_stamp_does_not_enclose(self):
        ck = _checklist()
        ck["files"][0]["items"][2]["script_handler"] = "true"
        assert lookup_function(ck, "mod/save.php", 8) is None

    def test_function_enclosure_unaffected(self):
        func = lookup_function(_checklist(), "mod/save.php", 5)
        assert func is not None and func["name"] == "helper"

    def test_spanless_interstitial_never_fuzzy_matches(self):
        ck = _checklist()
        # Drop the handler span's end: fuzzy fallback is for
        # FUNCTIONS without line_end only — an interstitial missing
        # its span has no inferable extent.
        del ck["files"][0]["items"][2]["line_end"]
        assert lookup_function(ck, "mod/save.php", 8) is None
        # ...and it must not steal later lines either.
        assert lookup_function(ck, "mod/save.php", 100) is None
