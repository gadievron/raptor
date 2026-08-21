"""Receiver-qualified pin matching (``--pin file:Class.method``).

Replays the v5 corpus shape: every dotted pin (Python
``BaseSecurityManager.*``, Go pointer-receiver ``atomicFile.Cancel``,
the seven ``Null*.Scan`` methods sharing one file) silently failed the
hoist because pins were matched against the bare inventory name only —
78 pin instances lost the force/prefilter-bypass guarantee while the
warning claimed the functions "will not be reviewed" (they were, via
the normal schedule) and mis-diagnosed the cause.
"""

from __future__ import annotations

import logging

from core.audit.gaps import _classify_unmatched_pin, gap_keys, hoist_pins


def _gap(file, name, class_name=None, priority=3):
    md = {"class_name": class_name} if class_name else {}
    return {
        "file": file, "name": name, "priority": priority,
        "line_start": 1, "line_end": 10, "metadata": md,
    }


class TestGapKeys:
    def test_bare_function(self):
        assert gap_keys(_gap("a.c", "f")) == {"a.c:f"}

    def test_python_class_method(self):
        keys = gap_keys(_gap("m.py", "is_auth_limited",
                             class_name="BaseSecurityManager"))
        assert keys == {
            "m.py:is_auth_limited",
            "m.py:BaseSecurityManager.is_auth_limited",
        }

    def test_go_pointer_receiver_star_already_stripped(self):
        # GoExtractor stores class_name with the ``*`` stripped.
        keys = gap_keys(_gap("file.go", "Cancel", class_name="atomicFile"))
        assert "file.go:atomicFile.Cancel" in keys


class TestQualifiedPinHoist:
    def test_class_method_pin_hoists(self):
        gaps = [
            _gap("m.py", "other", priority=0),
            _gap("m.py", "is_auth_limited",
                 class_name="BaseSecurityManager"),
        ]
        out = hoist_pins(gaps, ["m.py:BaseSecurityManager.is_auth_limited"])
        assert out[0]["name"] == "is_auth_limited"
        assert out[0].get("pinned") is True

    def test_go_receiver_pin_hoists(self):
        gaps = [
            _gap("pkg/atomicfile/file.go", "New", priority=0),
            _gap("pkg/atomicfile/file.go", "Cancel",
                 class_name="atomicFile"),
        ]
        out = hoist_pins(
            gaps, ["pkg/atomicfile/file.go:atomicFile.Cancel"],
        )
        assert out[0]["name"] == "Cancel"
        assert out[0].get("pinned") is True

    def test_seven_scan_receivers_each_pin_their_own_gap(self):
        receivers = ["NullBool", "NullFloat64", "NullInt32", "NullInt64",
                     "NullString", "NullTime", "Rows"]
        gaps = [
            _gap("sql.go", "Scan", class_name=r, priority=i)
            for i, r in enumerate(receivers)
        ]
        pins = [f"sql.go:{r}.Scan" for r in receivers]
        out = hoist_pins([dict(g) for g in gaps], pins)
        assert all(g.get("pinned") for g in out)

        # A single qualified pin hoists ONLY its own receiver's gap.
        out = hoist_pins(
            [dict(g) for g in gaps], ["sql.go:NullTime.Scan"],
        )
        pinned = [g for g in out if g.get("pinned")]
        assert len(pinned) == 1
        assert pinned[0]["metadata"]["class_name"] == "NullTime"

    def test_bare_pin_still_matches_bare_gap(self):
        gaps = [_gap("a.c", "f", priority=5), _gap("a.c", "g", priority=0)]
        out = hoist_pins(gaps, ["a.c:f"])
        assert out[0]["name"] == "f"

    def test_unambiguous_bare_fallback_without_metadata(self):
        # Extractor recorded no class_name; a qualified pin still
        # matches when exactly one gap in the file bears the bare name.
        gaps = [
            _gap("v.cc", "other", priority=0),
            _gap("v.cc", "doAuthenticate"),
        ]
        out = hoist_pins(gaps, ["v.cc:SpnegoAuthenticator.doAuthenticate"])
        assert out[0]["name"] == "doAuthenticate"
        assert out[0].get("pinned") is True

    def test_ambiguous_bare_fallback_is_refused(self, caplog):
        # Two metadata-less same-named methods: hoisting an arbitrary
        # one would pin the wrong receiver — warn instead.
        gaps = [
            _gap("sql.go", "Scan", priority=0),
            _gap("sql.go", "Scan", priority=1),
        ]
        with caplog.at_level(logging.WARNING):
            out = hoist_pins(gaps, ["sql.go:NullBool.Scan"])
        assert not any(g.get("pinned") for g in out)
        assert any("matched no gap" in r.message for r in caplog.records)


class TestUnmatchedPinCauses:
    _CHECKLIST = {"files": [{
        "path": "sql.go",
        "items": [
            {"name": "Scan", "kind": "function", "line_start": 1,
             "line_end": 5, "metadata": {"class_name": "NullBool"}},
            {"name": "Close", "kind": "function", "line_start": 8,
             "line_end": 12},
        ],
    }]}

    def test_in_inventory_but_no_gap(self):
        cause = _classify_unmatched_pin(
            "sql.go:NullBool.Scan", self._CHECKLIST,
        )
        assert "already reviewed" in cause

    def test_receiver_mismatch(self):
        cause = _classify_unmatched_pin(
            "sql.go:WrongReceiver.Scan", self._CHECKLIST,
        )
        assert "mismatch" in cause

    def test_not_in_inventory(self):
        cause = _classify_unmatched_pin(
            "sql.go:absent_fn", self._CHECKLIST,
        )
        assert "not in the checklist inventory" in cause

    def test_no_checklist_degrades(self):
        assert "unclassified" in _classify_unmatched_pin("a.c:f", None)

    def test_warning_carries_cause_per_pin(self, caplog):
        gaps = [_gap("sql.go", "Close")]
        with caplog.at_level(logging.WARNING):
            hoist_pins(
                gaps, ["sql.go:absent_fn"], checklist=self._CHECKLIST,
            )
        msgs = [r.getMessage() for r in caplog.records
                if "matched no gap" in r.message]
        assert msgs and "not in the checklist inventory" in msgs[0]
        # The old, wrong claim is gone: the pin not matching a gap
        # does not mean the function will not be reviewed.
        assert "will not be reviewed" not in msgs[0]
