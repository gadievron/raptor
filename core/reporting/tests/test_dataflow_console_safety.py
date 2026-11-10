"""Captured telemetry must remain inert at the shared console boundary."""
from copy import deepcopy
import re

from core.reporting.dataflow_summary import render_dataflow_validation_lines


def test_captured_cwe_control_bytes_cannot_reach_console():
    captured = {"n_validated": 1, "n_path_conditions_populated": 1,
                "path_conditions_by_cwe": {"CWE-190\x1b[2J\rFORGED": 1}}
    original = deepcopy(captured)
    lines = render_dataflow_validation_lines(captured)
    assert all("\x1b" not in line and "\r" not in line for line in lines)
    assert any("CWE-190\\x1b[2J\\x0dFORGED=1" in line for line in lines)
    assert captured == original


def test_skip_reason_and_rejection_labels_are_inert_and_bounded():
    skipped = render_dataflow_validation_lines({"skipped_reason": "missing\nFORGED\x1b[2J"})
    assert len(skipped) == 1 and "\n" not in skipped[0] and "\x1b" not in skipped[0]
    assert "missing\\x0aFORGED\\x1b[2J" in skipped[0]
    captured = {"n_validated": 1, "n_smt_rejections_by_kind": {"bad\x1b[2J": 3},
                "n_path_conditions_populated": 1, "path_conditions_by_cwe": {"CWE-" + "x" * 5000: 1}}
    lines = render_dataflow_validation_lines(captured)
    assert all("\x1b" not in line for line in lines)
    bounded = next(line for line in lines if "path_conditions populated" in line)
    prefix, marker = bounded.rsplit("...[+", 1)
    assert len(prefix) == 4000
    assert re.fullmatch(r"[1-9][0-9]* chars\]", marker)
    assert any("bad\\x1b[2J=3" in line for line in lines)
