"""Tests for ``packages.sca.calibration._apply_refit`` — in-place
patcher for risk.py's tunable multiplier constants."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.calibration._apply_refit import (
    RefitApplyError,
    _format_value,
    apply_refit_to_risk_py,
)


# ---------------------------------------------------------------------------
# Apply behaviour
# ---------------------------------------------------------------------------


def test_apply_rewrites_named_constants(tmp_path: Path):
    src = tmp_path / "risk.py"
    src.write_text(
        "_KEV_MULTIPLIER = 1.20\n"
        "_KEV_FLOOR = 80.0\n"
        "_OTHER = 5.0  # untouched\n"
    )
    modified = apply_refit_to_risk_py(
        {"_KEV_MULTIPLIER": 1.32, "_KEV_FLOOR": 88.0},
        src,
    )
    assert modified == 2
    text = src.read_text()
    assert "_KEV_MULTIPLIER = 1.32" in text
    assert "_KEV_FLOOR = 88.0" in text
    assert "_OTHER = 5.0" in text


def test_apply_preserves_inline_comments(tmp_path: Path):
    src = tmp_path / "risk.py"
    src.write_text(
        "_KEV_MULTIPLIER = 1.20  # tuned 2026-04-01\n"
    )
    apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.32}, src)
    line = src.read_text().splitlines()[0]
    assert line.endswith("# tuned 2026-04-01")
    assert "1.32" in line


def test_apply_preserves_indentation(tmp_path: Path):
    src = tmp_path / "risk.py"
    src.write_text(
        "    _KEV_MULTIPLIER = 1.20  # weirdly indented\n"
    )
    apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.32}, src)
    line = src.read_text().splitlines()[0]
    assert line.startswith("    ")


def test_apply_idempotent(tmp_path: Path):
    """Applying the same dict twice produces identical output."""
    src = tmp_path / "risk.py"
    src.write_text("_KEV_MULTIPLIER = 1.20\n")
    apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.32}, src)
    after_first = src.read_text()
    apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.32}, src)
    assert src.read_text() == after_first


def test_apply_returns_zero_when_no_change(tmp_path: Path):
    """Same value → no modification, returns 0."""
    src = tmp_path / "risk.py"
    src.write_text("_KEV_MULTIPLIER = 1.20\n")
    modified = apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.20}, src)
    assert modified == 0


def test_apply_empty_proposed_no_op(tmp_path: Path):
    src = tmp_path / "risk.py"
    src.write_text("_KEV_MULTIPLIER = 1.20\n")
    modified = apply_refit_to_risk_py({}, src)
    assert modified == 0


def test_apply_missing_constant_raises(tmp_path: Path):
    """A name in proposed_values that doesn't appear in source
    should raise — silently skipping would be a footgun."""
    src = tmp_path / "risk.py"
    src.write_text("_KEV_MULTIPLIER = 1.20\n")
    with pytest.raises(RefitApplyError, match="not found"):
        apply_refit_to_risk_py(
            {"_KEV_MULTIPLIER": 1.32, "_NON_EXISTENT": 1.0},
            src,
        )


def test_apply_missing_file_raises(tmp_path: Path):
    with pytest.raises(RefitApplyError, match="not found"):
        apply_refit_to_risk_py(
            {"_KEV_MULTIPLIER": 1.32},
            tmp_path / "nope.py",
        )


def test_apply_works_on_real_risk_py(tmp_path: Path):
    """Sanity: snapshot the production risk.py + apply a refit
    against the snapshot. Verifies the regex matches the actual
    file shape, not just synthetic minimal fixtures."""
    import shutil
    real_risk = (
        Path(__file__).resolve().parents[2]
        / "risk.py"
    )
    snapshot = tmp_path / "risk.py"
    shutil.copy(real_risk, snapshot)
    # Pick a constant we know is in production.
    from packages.sca.risk import _KEV_MULTIPLIER as orig_kev
    new_kev = orig_kev * 1.05
    modified = apply_refit_to_risk_py(
        {"_KEV_MULTIPLIER": new_kev},
        snapshot,
    )
    assert modified == 1
    text = snapshot.read_text()
    assert f"_KEV_MULTIPLIER = {_format_value(new_kev)}" in text


def test_apply_preserves_no_trailing_newline(tmp_path: Path):
    """A file without a final newline should stay that way."""
    src = tmp_path / "risk.py"
    src.write_bytes(b"_KEV_MULTIPLIER = 1.20")
    apply_refit_to_risk_py({"_KEV_MULTIPLIER": 1.32}, src)
    assert not src.read_bytes().endswith(b"\n")


# ---------------------------------------------------------------------------
# Number formatting
# ---------------------------------------------------------------------------


def test_format_value_integer_floats():
    assert _format_value(80.0) == "80.0"
    assert _format_value(1.0) == "1.0"
    assert _format_value(100.0) == "100.0"


def test_format_value_truncates_float_noise():
    """Refit math may produce 1.0800000000000001 — we cap at 4
    decimals so the diff stays readable."""
    assert _format_value(1.0800000000000001) == "1.08"


def test_format_value_keeps_significant_digits():
    assert _format_value(0.7) == "0.7"
    assert _format_value(0.85) == "0.85"
    assert _format_value(1.234) == "1.234"


def test_format_value_rounds_to_4_decimals():
    assert _format_value(1.234567) == "1.2346"
