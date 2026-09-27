"""Fid-shaped ``--pin`` values (``<anchor>:0x<rel>``) resolve by
content identity through the checklist's ``module_identity`` space —
never sheared as ``file:function`` — with truthful per-cause warnings
when they cannot resolve."""

from __future__ import annotations

import logging

import pytest

from core.audit.gaps import hoist_pins

_ANCHOR = "a" * 16
_BASE = 0x160000


def _checklist(*, base: int | None = _BASE, items=None):
    block = {
        "kind": "elf_build_id", "value": _ANCHOR, "anchor": _ANCHOR,
    }
    if base is not None:
        block["image_base"] = base
    return {"files": [{
        "path": "binary:acmed",
        "language": "binary",
        "sha256": "f0" * 32,
        "module_identity": block,
        "items": items or [],
    }]}


def _gaps():
    return [
        {"file": "binary:acmed", "name": "validate_sig",
         "priority": 1, "metadata": {"address": 0x162000}},
        {"file": "binary:acmed", "name": "parse_channel",
         "priority": 1, "metadata": {"address": 0x161DA0}},
    ]


class TestFidPinHoist:
    def test_exact_fid_pin_hoists_the_addressed_gap(self):
        gaps = _gaps()
        result = hoist_pins(
            gaps, [f"{_ANCHOR}:0x1da0"], checklist=_checklist(),
        )
        assert result[0]["name"] == "parse_channel"

    def test_fuzzy_window_unique_candidate_hoists(self):
        gaps = _gaps()
        result = hoist_pins(
            gaps, [f"{_ANCHOR}:0x1da8"], checklist=_checklist(),
        )
        assert result[0]["name"] == "parse_channel"

    def test_ambiguous_window_refuses_with_truthful_cause(
        self, caplog,
    ):
        gaps = _gaps()
        gaps[0]["metadata"]["address"] = 0x161DA4  # 2nd in-window
        # Classification walks the checklist INVENTORY (the gap list
        # only drives resolution) — mirror both in-window functions.
        checklist = _checklist(items=[
            {"name": "parse_channel",
             "metadata": {"address": 0x161DA0}},
            {"name": "validate_sig",
             "metadata": {"address": 0x161DA4}},
        ])
        with caplog.at_level(logging.WARNING):
            result = hoist_pins(
                gaps, [f"{_ANCHOR}:0x1da2"], checklist=checklist,
            )
        assert result == gaps  # nothing hoisted
        assert "ambiguous" in caplog.text
        assert "fuzzy window" in caplog.text

    def test_unknown_anchor_names_the_build_mismatch(self, caplog):
        with caplog.at_level(logging.WARNING):
            hoist_pins(
                _gaps(), ["b" * 16 + ":0x1da0"],
                checklist=_checklist(),
            )
        assert "matches no checklist module_identity" in caplog.text

    def test_no_recorded_base_names_the_producer_gap(self, caplog):
        with caplog.at_level(logging.WARNING):
            hoist_pins(
                _gaps(), [f"{_ANCHOR}:0x1da0"],
                checklist=_checklist(base=None),
            )
        assert "no recorded image base" in caplog.text

    def test_in_inventory_but_not_in_gaps_says_so(self, caplog):
        """The address exists in the checklist inventory but the gap
        list no longer carries it (reviewed/suppressed/filtered)."""
        checklist = _checklist(items=[{
            "name": "parse_channel",
            "metadata": {"address": 0x161DA0},
        }])
        gaps = [g for g in _gaps() if g["name"] != "parse_channel"]
        with caplog.at_level(logging.WARNING):
            result = hoist_pins(
                gaps, [f"{_ANCHOR}:0x1da0"], checklist=checklist,
            )
        assert result == gaps
        assert "in the inventory but not in the gap list" \
            in caplog.text

    def test_no_function_at_address_names_drift(self, caplog):
        with caplog.at_level(logging.WARNING):
            hoist_pins(
                _gaps(), [f"{_ANCHOR}:0xdead00"],
                checklist=_checklist(),
            )
        assert "no function at the resolved address" in caplog.text

    def test_fid_pin_without_checklist_warns_not_raises(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = hoist_pins(_gaps(), [f"{_ANCHOR}:0x1da0"])
        assert result == _gaps()
        assert "matched no gap" in caplog.text

    @pytest.mark.parametrize("pin", [
        "src/auth.c:check_pw",       # ordinary source pin
        "binary:acmed:parse_channel",  # binary file:function pin
    ])
    def test_non_fid_pins_untouched_by_the_fid_leg(self, pin):
        """The fid loop only sees fid-shaped pins — file:function
        spellings keep their historical resolution exactly."""
        gaps = _gaps() + [
            {"file": "src/auth.c", "name": "check_pw", "priority": 2},
        ]
        result = hoist_pins(gaps, [pin], checklist=_checklist())
        expect = "check_pw" if pin.endswith("check_pw") \
            else "parse_channel"
        assert result[0]["name"] == expect
