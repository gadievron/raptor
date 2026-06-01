"""Tests for core.startup.banner version injection.

The banner asset carries a ``__VERSION__`` placeholder; ``read_logo`` injects
the live version at render time and re-pads the box so the border stays
aligned regardless of the version string's length (a clone's git-describe
string is much longer than a clean release number)."""

from core.startup import banner


def _version_line(text: str) -> str:
    return next(ln for ln in text.splitlines() if "Based on Claude Code" in ln)


def test_injects_version_with_leading_v_and_preserves_box_width():
    line = _version_line(banner.read_logo("3.0.0-1786-g7fcf38ea"))
    assert "v3.0.0-1786-g7fcf38ea" in line   # leading 'v' added
    assert "__VERSION__" not in line          # placeholder consumed
    assert line.startswith("║") and line.endswith("║")
    assert len(line) == 77                    # box width unchanged


def test_clean_release_number_keeps_box_width():
    line = _version_line(banner.read_logo("3.0.0"))
    assert "v3.0.0" in line
    assert len(line) == 77


def test_does_not_double_the_v_prefix():
    line = _version_line(banner.read_logo("v3.0.0"))
    assert "vv" not in line
    assert "v3.0.0" in line


def test_overlong_version_still_closes_the_box():
    # Pathologically long string: box can't keep width 77 but must stay closed.
    line = _version_line(banner.read_logo("9" * 60))
    assert line.endswith("║")


def test_empty_version_leaves_placeholder_untouched():
    line = _version_line(banner.read_logo(""))
    assert "__VERSION__" in line
